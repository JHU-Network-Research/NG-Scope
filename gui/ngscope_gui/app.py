"""pywebview shell: native window, native dialogs, and the JS<->Python bridge.

The frontend is plain HTML/CSS/JS in ui/. Everything it needs from the machine -- file
dialogs, the config file, the subprocess -- goes through the Api class below, which
pywebview exposes to the page as `window.pywebview.api`.
"""

import copy
import csv
import json
import re
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

import webview

from . import config_io, earfcn, schema, state as state_mod
from .plotfeed import PlotFeed
from .runner import REPO_ROOT, Runner, describe_exit, find_binary
from .sweep import Sweep

UI_DIR = Path(__file__).parent / "ui"

# Emitted by ngscope/src/main.c:207 once the run directory exists.
DCI_PATH_MARKER = "Using DCI Path:"

RUN_CONFIG_NAME = "ngscope-gui-run.toml"

# ngscope's own run-directory format (main.c:173), reused so everything the GUI stamps
# reads the same way.
STAMP_FORMAT = "%Y_%m_%d_%H_%M_%S"

SWEEP_SUMMARY_COLUMNS = [
    "pass", "earfcn", "band", "freq_hz", "locked", "pci", "prb",
    "lock_s", "listen_s", "total_s", "exit_code", "run_dir",
]

# srsRAN colours its log lines (ERROR red, WARNING yellow, INFO green). The escapes are
# noise in a HTML console, but the colour itself is the most reliable severity signal the
# backend gives us -- so read it off, then strip.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SGR_COLOUR_RE = re.compile(r"\x1b\[(?:[0-9;]*;)?(3[0-9])(?:;[0-9]+)*m")
SGR_CLASS = {"31": "err", "33": "warn", "32": "ok", "36": "cfg"}


def _decorate(line):
    match = SGR_COLOUR_RE.search(line)
    return {"text": ANSI_RE.sub("", line), "cls": SGR_CLASS.get(match.group(1)) if match else None}


def _dialog_type(new_name, old_name, fallback):
    """pywebview 6 moved these onto a FileDialog enum and deprecated the module-level
    constants; older releases only have the constants."""
    enum = getattr(webview, "FileDialog", None)
    if enum is not None and hasattr(enum, new_name):
        return getattr(enum, new_name)
    return getattr(webview, old_name, fallback)


FOLDER_DIALOG = _dialog_type("FOLDER", "FOLDER_DIALOG", 20)
OPEN_DIALOG = _dialog_type("OPEN", "OPEN_DIALOG", 10)
SAVE_DIALOG = _dialog_type("SAVE", "SAVE_DIALOG", 30)


class Api:
    def __init__(self):
        self._window = None
        self.state = state_mod.load()
        self._runner = Runner(self._push_lines, self._push_exit)
        self.run_dir = None
        # One console note per sweep, not per channel; see _push_exit.
        self._join_sweep_noted = False
        # Receives the two series srsGUI would have drawn; see plotfeed.py.
        self._plots = PlotFeed(lambda frame: self._js("onPlotFrame", frame))
        self._sweep = Sweep(
            launch=self._sweep_launch,
            stop=lambda: self._runner.stop(),
            progress=lambda state: self._js("onSweepProgress", state),
            on_result=self._sweep_write_row,
        )
        # The config and output directory a sweep was started with, reused for every step.
        self._sweep_ctx = None

    # ------------------------------------------------------------------ bridge

    def _js(self, fn, *args):
        if self._window is None:
            return
        payload = ", ".join(json.dumps(arg) for arg in args)
        try:
            # Guarded so a call that races page load is a no-op rather than an exception.
            self._window.evaluate_js(f"window.{fn} && window.{fn}({payload})")
        except Exception:  # noqa: BLE001 - the window may be tearing down
            pass

    def _push_lines(self, lines):
        decorated = [_decorate(line) for line in lines]
        for item in decorated:
            if DCI_PATH_MARKER in item["text"]:
                # ".../<timestamp>/dci_output/" -- the run directory is its parent.
                dci_path = item["text"].split(DCI_PATH_MARKER, 1)[1].strip()
                run_dir = Path(dci_path.rstrip("/")).parent
                if run_dir.is_dir():
                    self.run_dir = str(run_dir)
                    self._js("onRunDir", self.run_dir)
                    self._sweep.note_run_dir(self.run_dir)
            self._sweep.note_line(item["text"])
        self._js("appendLines", decorated)

    def _push_exit(self, code):
        message, kind = describe_exit(code)
        if self._sweep.active:
            # Mid-sweep an exit is the end of one channel, not the end of the run: report
            # it in the console but let the sweep decide what happens next.
            self._push_lines([f"[gui] channel finished ({message})"])
            # Deliberately not joining here. The sweep launches the next channel straight
            # away, and the join is CPU-hungry enough to make that channel drop subframes --
            # a silent loss, which is the one cost this tooling must not introduce. Say so
            # once rather than leaving the option looking broken.
            if self.state.get("join_after_run") and not self._join_sweep_noted:
                self._join_sweep_noted = True
                self._push_lines(
                    ["[gui] security phase join skipped for the sweep: running it between "
                     "channels would compete for CPU with the next channel's capture. Run "
                     "tools/security_phase_join.py over each earfcn-*/<timestamp>/ afterwards."]
                )
            self._sweep.on_exit(code)
            return
        self._js("onExit", {"code": code, "message": message, "kind": kind})
        self._start_join()

    # ------------------------------------------------------------- post-run join

    def _start_join(self):
        """Run tools/security_phase_join.py over the run that just finished, if asked.

        Worth automating rather than leaving to the user: ngscope's in-stream
        security_phase can only ever mark a fraction of the pre-security DCIs, because the
        boundary arrives after the DCIs it bounds -- 52 of 1,089 on the band 12 capture. So
        a forgotten join does not fail loudly, it just quietly under-reports, which is the
        failure mode this whole feature set exists to avoid.

        Off by default, and skipped with a reason in the console rather than silently
        whenever it cannot run.
        """
        if not self.state.get("join_after_run"):
            return

        top = (self.state.get("config") or {}).get("top") or {}
        if not top.get("mark_security_phase"):
            self._push_lines(
                ["[gui] security phase join skipped: mark_security_phase was off, so there "
                 "is no security_log to join"]
            )
            return

        run_dir = self.run_dir
        if not run_dir:
            self._push_lines(
                ["[gui] security phase join skipped: no run directory was reported (the run "
                 "may have died before it opened its logs)"]
            )
            return

        script = REPO_ROOT / "tools" / "security_phase_join.py"
        if not script.is_file():
            self._push_lines([f"[gui] security phase join skipped: {script} is missing"])
            return

        threading.Thread(
            target=self._join_worker, args=(str(script), run_dir), daemon=True
        ).start()

    def _join_worker(self, script, run_dir):
        """Stream the join into the same console as the run. Its own thread so the exit
        notification the frontend is waiting on is not held up behind it."""
        argv = [sys.executable, script, run_dir, "-f", "all"]
        self._push_lines(["[gui] " + " ".join(argv)])
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=run_dir,
            )
        except OSError as exc:
            self._push_lines([f"[gui] security phase join could not start: {exc}"])
            self._js("onJoinDone", {"ok": False, "error": str(exc)})
            return

        for line in proc.stdout:
            self._push_lines([line.rstrip("\n")])
        code = proc.wait()

        if code == 0:
            self._push_lines(["[gui] security phase join finished"])
        else:
            self._push_lines([f"[gui] security phase join exited {code}"])
        self._js("onJoinDone", {"ok": code == 0, "code": code, "run_dir": run_dir})

    # ------------------------------------------------------------------ startup

    def bootstrap(self):
        binary, source = find_binary(self.state.get("binary", ""))
        return {
            "schema": schema.bootstrap(),
            "state": self.state,
            "binary": {"path": binary, "source": source},
            "config_path": str(state_mod.STATE_PATH),
        }

    # ------------------------------------------------------------------ persistence

    def save_state(self, new_state):
        self.state = new_state
        try:
            state_mod.save(new_state)
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def reset_state(self):
        self.state = state_mod.default_state()
        state_mod.save(self.state)
        return self.state

    # ------------------------------------------------------------------ dialogs

    def _dialog(self, dialog_type, **kwargs):
        if self._window is None:
            return None
        result = self._window.create_file_dialog(dialog_type, **kwargs)
        if not result:
            return None
        return result[0] if isinstance(result, (list, tuple)) else result

    def pick_out_dir(self, current=""):
        start = current if current and Path(current).is_dir() else str(Path.home())
        return self._dialog(FOLDER_DIALOG, directory=start)

    def pick_replay_file(self, current=""):
        path = Path(current) if current else None
        start = str(path.parent) if path and path.parent.is_dir() else str(Path.home())
        return self._dialog(
            OPEN_DIALOG,
            directory=start,
            allow_multiple=False,
            file_types=("IQ recordings (*.bin)", "All files (*.*)"),
        )

    def pick_binary(self, current=""):
        start = str(Path(current).parent) if current else str(Path.home())
        return self._dialog(OPEN_DIALOG, directory=start, allow_multiple=False)

    def load_toml(self):
        path = self._dialog(
            OPEN_DIALOG,
            directory=str(Path.home()),
            allow_multiple=False,
            file_types=("TOML config (*.toml)", "All files (*.*)"),
        )
        if not path:
            return None
        try:
            return {"ok": True, "path": path, "config": config_io.load(path)}
        except Exception as exc:  # noqa: BLE001 - surface any parse failure to the user
            return {"ok": False, "error": f"{Path(path).name}: {exc}"}

    def save_toml_as(self, config):
        path = self._dialog(
            SAVE_DIALOG, directory=str(Path.home()), save_filename="config.toml"
        )
        if not path:
            return None
        if not path.endswith(".toml"):
            path += ".toml"
        try:
            config_io.write(config, path)
            return {"ok": True, "path": path}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def save_console(self, text):
        path = self._dialog(
            SAVE_DIALOG, directory=str(Path.home()), save_filename="ngscope-console.log"
        )
        if not path:
            return None
        try:
            Path(path).write_text(text, encoding="utf-8")
            return {"ok": True, "path": path}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ running

    def validate(self, config, out_dir):
        errors, warnings = config_io.validate(config, out_dir)
        return {"errors": errors, "warnings": warnings}

    def preview_config(self, config):
        return config_io.dumps(config)

    # ------------------------------------------------------------------ EARFCN

    def earfcn_info(self, value):
        """Resolve an EARFCN to its frequency and band for the live hint under the field."""
        try:
            n = int(value)
        except (TypeError, ValueError):
            return None
        info = earfcn.describe(n)
        if info is None:
            return {"ok": False, "max": earfcn.MAX_DL_EARFCN}
        return {"ok": True, **info}

    def earfcns_for_freq(self, freq_hz):
        """Candidate EARFCNs for a frequency. More than one means overlapping bands."""
        try:
            hz = int(freq_hz)
        except (TypeError, ValueError):
            return []
        return [{"earfcn": e, "band": b} for e, b in earfcn.freq_to_earfcns(hz)]

    def _spawn(self, config, out_dir, binary_override, config_name):
        """Write the config and launch ngscope. Returns (ok, detail)."""
        binary, _source = find_binary(binary_override)
        if not binary:
            return False, (
                "Could not find the ngscope executable. Build it, or set the path "
                "under Advanced."
            )

        config_path = str(Path(out_dir) / config_name)
        try:
            config_io.write(config, config_path)
        except OSError as exc:
            return False, f"Could not write {config_path}: {exc}"

        argv = [binary, "-c", config_path, "-o", str(out_dir)]
        self.run_dir = None
        # Redirects the plot thread from srsGUI's own windows into this one. Only has an
        # effect when the build has ENABLE_GUI and the cell leaves disable_plot off.
        env_extra = {"NGSCOPE_PLOT_SOCK": self._plots.path}
        try:
            pid = self._runner.start(argv, cwd=out_dir, env_extra=env_extra)
        except OSError as exc:
            return False, f"Could not launch ngscope: {exc}"

        self._push_lines(
            [
                "[gui] " + " ".join(argv),
                f"[gui] pid {pid}, config written to {config_path}",
            ]
        )
        return True, {"pid": pid, "argv": argv}

    def start(self, config, out_dir, binary_override=""):
        if self._runner.running:
            return {"ok": False, "error": "ngscope is already running."}

        errors, warnings = config_io.validate(config, out_dir)
        if errors:
            return {"ok": False, "errors": errors, "warnings": warnings}

        ok, detail = self._spawn(config, out_dir, binary_override, RUN_CONFIG_NAME)
        if not ok:
            return {"ok": False, "error": detail}
        return {"ok": True, "warnings": warnings, **detail}

    def stop(self):
        if self._sweep.active:
            self._sweep.cancel()
            return {"ok": True, "sweep": True}
        if not self._runner.running:
            return {"ok": False, "error": "Not running."}
        self._runner.stop()
        return {"ok": True}

    # ------------------------------------------------------------------ sweep

    def parse_earfcn_list(self, text):
        """Live feedback for the sweep list field."""
        values, errors = earfcn.parse_list(text or "")
        preview = []
        for value in values[:6]:
            info = earfcn.describe(value)
            preview.append({"earfcn": value, "band": info["band"], "mhz": info["mhz"]})
        return {"count": len(values), "errors": errors, "preview": preview}

    def _sweep_launch(self, value):
        """Launch one channel of the sweep, overriding the first cell's frequency."""
        ctx = self._sweep_ctx
        info = earfcn.describe(value)
        if ctx is None or info is None:
            return False, f"EARFCN {value} is not valid."

        config = copy.deepcopy(ctx["config"])
        cell = config["cells"][0]
        cell["rf_freq"] = info["freq_hz"]
        cell["gui_freq_mode"] = "earfcn"
        cell["gui_earfcn"] = value

        # Each channel gets its own subdirectory, so ngscope's timestamped run folders end
        # up grouped by EARFCN instead of in one undifferentiated pile.
        channel_dir = Path(ctx["out_dir"]) / f"earfcn-{value}"
        try:
            channel_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return False, f"Could not create {channel_dir}: {exc}"

        self._push_lines([
            f"[gui] --- EARFCN {value} · band {info['band']} · {info['mhz']:.1f} MHz · "
            f"listen {ctx['dwell']:g}s from lock, give up after {ctx['acquire']:g}s ---"
        ])
        # The config lands in the channel's own directory, beside its captures.
        return self._spawn(config, str(channel_dir), ctx["binary"],
                           f"ngscope-gui-sweep-{value}.toml")

    def _sweep_write_row(self, step):
        """Append one channel's result to the sweep summary as soon as it finishes."""
        ctx = self._sweep_ctx
        if ctx is None or not ctx.get("summary"):
            return
        path = Path(ctx["summary"])
        new = not path.exists()
        with open(path, "a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            if new:
                writer.writerow(SWEEP_SUMMARY_COLUMNS)
            writer.writerow([
                step.get("cycle"),
                step.get("earfcn"),
                step.get("band"),
                step.get("freq_hz"),
                1 if step.get("locked") else 0,
                step.get("pci"),
                step.get("prb"),
                step.get("lock_s"),
                step.get("listen_s"),
                step.get("seconds"),
                step.get("exit_code"),
                step.get("run_dir"),
            ])

    def sweep_start(self, config, out_dir, earfcn_text, dwell, acquire, repeat, binary_override=""):
        if self._runner.running or self._sweep.active:
            return {"ok": False, "error": "Already running."}

        self._join_sweep_noted = False

        values, parse_errors = earfcn.parse_list(earfcn_text or "")
        if parse_errors:
            return {"ok": False, "error": "; ".join(parse_errors[:4])}
        if not values:
            return {"ok": False, "error": "Enter at least one EARFCN to sweep."}
        try:
            dwell = float(dwell)
        except (TypeError, ValueError):
            dwell = 0
        if dwell < 1:
            return {"ok": False, "error": "Listen time must be at least 1 second."}
        try:
            acquire = float(acquire)
        except (TypeError, ValueError):
            acquire = 0
        if acquire < 1:
            return {"ok": False, "error": "Give-up time must be at least 1 second."}

        # Validate with the first channel applied, so frequency-dependent rules (the
        # duplicate-frequency check in particular) are exercised against a real value.
        probe = copy.deepcopy(config)
        first = earfcn.describe(values[0])
        probe["cells"][0]["rf_freq"] = first["freq_hz"]
        errors, warnings = config_io.validate(probe, out_dir)
        if errors:
            return {"ok": False, "errors": errors, "warnings": warnings}

        # Stamped at sweep start, so one file covers the whole sweep including every repeat
        # pass, and a later sweep into the same directory cannot overwrite it.
        stamp = datetime.now().strftime(STAMP_FORMAT)
        summary = str(Path(out_dir) / f"sweep-summary-{stamp}.csv")

        self._sweep_ctx = {
            "config": copy.deepcopy(config),
            "out_dir": out_dir,
            "binary": binary_override,
            "dwell": dwell,
            "acquire": acquire,
            "summary": summary,
        }
        result = self._sweep.start(values, dwell, acquire, repeat)
        if not result.get("ok"):
            return result
        self._push_lines([f"[gui] sweep summary: {summary}"])
        return {"ok": True, "earfcns": values, "summary": summary, "warnings": warnings}

    def status(self):
        return {"running": self._runner.running, "stopping": self._runner.stopping}

    # ------------------------------------------------------------------ misc

    def open_path(self, path):
        target = Path(path) if path else None
        if not target or not target.exists():
            return {"ok": False, "error": "Path no longer exists."}
        try:
            subprocess.Popen(
                ["xdg-open", str(target)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    def resolve_binary(self, override=""):
        path, source = find_binary(override)
        return {"path": path, "source": source}


def _on_closing(api):
    def handler():
        try:
            state_mod.save(api.state)
        except OSError:
            pass
        api._runner.kill_now()
        return True

    return handler


def build_window(api, **overrides):
    """Create the app window and wire it to `api`.

    Everything that opens this UI goes through here -- including the test harnesses -- so
    the window they exercise cannot drift from the one users get.
    """
    window_state = api.state.get("window", {})
    options = {
        "width": int(window_state.get("width", 1440)),
        "height": int(window_state.get("height", 920)),
        "min_size": (1040, 680),
        "background_color": "#0f1116",
        # pywebview defaults this to False and injects `body { user-select: none }`, which
        # makes the console output impossible to select or copy. The stylesheet turns
        # selection back off for the chrome (buttons, tabs, labels).
        "text_select": True,
    }
    options.update(overrides)

    window = webview.create_window("NG-Scope", str(UI_DIR / "index.html"), js_api=api, **options)
    api._window = window
    window.events.closing += _on_closing(api)
    return window


def main():
    api = Api()
    build_window(api)
    webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
