"""pywebview shell: Record (sweep) / Replay -> compile -> classify."""

import json
import os
import queue
import re
import signal
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

import webview

from . import earfcn, pipeline, rules as rules_mod
from .plotfeed import PlotFeed
from .runner import Runner, describe_exit, find_binary
from .sweep import Sweep

UI_DIR = Path(__file__).parent / "ui"
APP_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "imsiguard-gui"
STATE_PATH = APP_DIR / "state.json"
DCI_PATH_MARKER = "Using DCI Path:"
GIVEUP_SECONDS = 20
STAMP_FORMAT = "%Y_%m_%d_%H_%M_%S"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SGR_RE = re.compile(r"\x1b\[(?:[0-9;]*;)?(3[0-9])(?:;[0-9]+)*m")
SGR_CLASS = {"31": "err", "33": "warn", "32": "ok", "36": "cfg"}


def _decorate(line):
    m = SGR_RE.search(line)
    return {"text": ANSI_RE.sub("", line), "cls": SGR_CLASS.get(m.group(1)) if m else None}


def _pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def default_state():
    return {
        "mode": "record",
        "out_dir": str(Path.home() / "imsiguard_out"),
        "binary": "",
        "earfcns": "",
        "giveup": 20,
        "rf_args": "",
        "nof_rx_ant": 1,
        "nof_thread": 5,
        "replay_files": [],
        "timeout": 900,
        "pause_for_replay": False,
        "listen": rules_mod.DEFAULT_LISTEN_S,
        "rules": dict(rules_mod.DEFAULT_RULES),
    }


def _dialog_type(new, old, fallback):
    enum = getattr(webview, "FileDialog", None)
    if enum is not None and hasattr(enum, new):
        return getattr(enum, new)
    return getattr(webview, old, fallback)


FOLDER_DIALOG = _dialog_type("FOLDER", "FOLDER_DIALOG", 20)
OPEN_DIALOG = _dialog_type("OPEN", "OPEN_DIALOG", 10)
SAVE_DIALOG = _dialog_type("SAVE", "SAVE_DIALOG", 30)


class Cancelled(Exception):
    pass


class Api:
    def __init__(self):
        self._window = None
        self.state = default_state()
        try:
            self.state.update(json.loads(STATE_PATH.read_text()))
        except (OSError, json.JSONDecodeError):
            pass
        self.state["rules"] = {**rules_mod.DEFAULT_RULES, **(self.state.get("rules") or {})}

        self._runner = Runner(self._push_lines, self._push_exit)
        # A second process slot, so a replay can run while the sweep records the next channel.
        self._replay_ctx = None
        self._replay_runner = Runner(self._replay_lines, self._replay_exit)
        self._plots = PlotFeed(lambda f: self._js("onPlotFrame", f))
        self._sweep = Sweep(
            launch=self._sweep_launch,
            stop=lambda: self._runner.stop(),
            progress=lambda s: self._js("onSweepProgress", s),
            on_result=self._on_channel_done,
            hold=self._replay_busy,
        )
        self._sweep_ctx = None
        self.run_dir = None


        self._jobs = []
        self._jobs_lock = threading.Lock()
        self._queue = queue.Queue()
        self._job_proc = None
        self._cancel = threading.Event()
        self._next_id = 1
        threading.Thread(target=self._worker, name="pipeline", daemon=True).start()

    # ---------------------------------------------------------------- bridge

    def _js(self, fn, *args):
        if self._window is None:
            return
        payload = ", ".join(json.dumps(a) for a in args)
        try:
            self._window.evaluate_js(f"window.{fn} && window.{fn}({payload})")
        except Exception:  # noqa: BLE001
            pass

    def _log(self, text):
        self._js("appendLines", [_decorate(text)])

    def _push_lines(self, lines):
        dec = [_decorate(l) for l in lines]
        for item in dec:
            if DCI_PATH_MARKER in item["text"]:
                p = Path(item["text"].split(DCI_PATH_MARKER, 1)[1].strip().rstrip("/")).parent
                if p.is_dir():
                    self.run_dir = str(p)
                    self._sweep.note_run_dir(self.run_dir)
            self._sweep.note_line(item["text"])
        self._js("appendLines", dec)

    # ---- replay process: output to the console, plots to the plot socket

    def _replay_lines(self, lines):
        ctx = self._replay_ctx
        dec = [_decorate(l) for l in lines]
        if ctx is not None:
            try:
                ctx["file"].write(("\n".join(d["text"] for d in dec) + "\n").encode())
            except (OSError, ValueError):
                pass
        self._js("appendLines", dec)

    def _replay_exit(self, code):
        ctx = self._replay_ctx
        if ctx is not None:
            ctx["code"] = code
            ctx["done"].set()

    def _run_replay_proc(self, argv, cwd, plots, log_path, timeout):
        """Blocking: run one replay with ngscope's output shown live. Returns the exit code."""
        import bz2
        ctx = {"done": threading.Event(), "code": None, "file": bz2.open(log_path, "wb")}
        self._replay_ctx = ctx
        try:
            env = {"NGSCOPE_PLOT_SOCK": self._plots.path} if plots else None
            self._replay_runner.start(argv, cwd=cwd, env_extra=env)
            if plots:
                self._js("onPlotsReset")
            deadline = time.monotonic() + timeout
            stopping = False
            while not ctx["done"].wait(0.5):
                if (self._cancel.is_set() or time.monotonic() > deadline) and not stopping:
                    stopping = True
                    if not self._cancel.is_set():
                        self._log(f"[replay] timed out after {timeout}s -- stopping")
                    self._replay_runner.stop()
            return ctx["code"]
        finally:
            self._replay_ctx = None
            try:
                ctx["file"].close()
            except OSError:
                pass

    def _push_exit(self, code):
        msg, kind = describe_exit(code)
        self._push_lines([f"[gui] channel finished ({msg})"])
        if self._sweep.active:
            self._sweep.on_exit(code)

    # ---------------------------------------------------------------- startup / state

    def bootstrap(self):
        binary, source = find_binary(self.state.get("binary", ""))
        return {"state": self.state, "binary": {"path": binary, "source": source},
                "jobs": self._jobs_view()}

    def save_state(self, new_state):
        self.state.update(new_state or {})
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(APP_DIR), suffix=".json")
            with os.fdopen(fd, "w") as fh:
                json.dump(self.state, fh, indent=2)
            os.replace(tmp, STATE_PATH)
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    # ---------------------------------------------------------------- dialogs

    def _dialog(self, kind, multiple=False, **kw):
        if self._window is None:
            return None
        res = self._window.create_file_dialog(kind, allow_multiple=multiple, **kw) \
            if kind == OPEN_DIALOG else self._window.create_file_dialog(kind, **kw)
        if not res:
            return None
        if multiple:
            return list(res)
        return res[0] if isinstance(res, (list, tuple)) else res

    def pick_dir(self, current=""):
        start = current if current and Path(current).is_dir() else str(Path.home())
        return self._dialog(FOLDER_DIALOG, directory=start)

    def pick_replay_files(self):
        return self._dialog(OPEN_DIALOG, multiple=True, directory=str(Path.home()),
                            file_types=("IQ recordings (*.bin;*.bz2;*.gz;*.xz)", "All files (*.*)"))

    def pick_file(self, kind="any"):
        types = {"pkl": ("Pickled model (*.pkl)", "All files (*.*)"),
                 "csv": ("CSV (*.csv)", "All files (*.*)")}.get(kind, ("All files (*.*)",))
        return self._dialog(OPEN_DIALOG, directory=str(Path.home()), file_types=types)

    def open_path(self, path):
        import subprocess
        if path and Path(path).exists():
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return {"ok": True}
        return {"ok": False}

    # ---------------------------------------------------------------- jobs

    def _jobs_view(self):
        with self._jobs_lock:
            return [dict(j) for j in self._jobs]

    def _update_job(self, job, **kw):
        with self._jobs_lock:
            job.update(kw)
            view = dict(job)
        self._js("onJob", view)

    def _enqueue(self, recording, source):
        with self._jobs_lock:
            job = {"id": self._next_id, "recording": str(recording), "source": source,
                   "status": "queued", "label": None, "auth_frac": None, "windows": [],
                   "error": None, "work_dir": None, "earfcn": None}
            self._next_id += 1
            self._jobs.append(job)
        self._js("onJob", dict(job))
        self._queue.put(job)
        return job

    def _worker(self):
        while True:
            job = self._queue.get()
            if self._cancel.is_set():
                self._update_job(job, status="cancelled")
                continue
            binary, _ = find_binary(self.state.get("binary", ""))
            if not binary:
                self._update_job(job, status="error", error="ngscope binary not found.")
                continue
            try:
                res = pipeline.process_recording(
                    job["recording"], self.state["out_dir"], binary,
                    self.state["rules"], int(self.state["listen"]), self._log,
                    timeout=int(self.state.get("timeout", 900)),
                    stage=lambda s, j=job: self._update_job(j, status=s),
                    cancel=self._cancel.is_set,
                    set_proc=lambda p: setattr(self, "_job_proc", p),
                    run_ngscope=self._run_replay_proc,
                    # Plots only when nothing else is feeding them (a sweep recording).
                    plots=not (self._runner.running or self._sweep.active))
                self._update_job(job, status="done", label=res["label"],
                                 auth_frac=res["auth_frac"], windows=res["windows"],
                                 work_dir=res["work_dir"], earfcn=res["earfcn"])
                self._log(f"[result] {Path(job['recording']).name}: {res['label'].upper()} "
                          f"({_pct(res['auth_frac'])} of UEs authenticated)")
            except pipeline.Cancelled:
                self._update_job(job, status="cancelled")
            except Exception as exc:  # noqa: BLE001
                self._log(traceback.format_exc().rstrip().splitlines()[-1])
                self._update_job(job, status="error", error=str(exc))

    def _check_ready(self):
        try:
            rules_mod.normalize(self.state.get("rules"))
            if float(self.state.get("listen") or 0) < 10:
                return "Listen time must be at least 10 seconds."
        except (TypeError, ValueError) as exc:
            return str(exc)
        binary, _ = find_binary(self.state.get("binary", ""))
        if not binary:
            return "Could not find the ngscope executable (set it under Advanced)."
        return None

    def start_replay(self, files):
        err = self._check_ready()
        if err:
            return {"ok": False, "error": err}
        files = [str(f) for f in (files or []) if str(f).strip()]
        if not files:
            return {"ok": False, "error": "Choose at least one recording."}
        missing = [f for f in files if not Path(f).is_file()]
        if missing:
            return {"ok": False, "error": f"Not found: {missing[0]}"}
        Path(self.state["out_dir"]).mkdir(parents=True, exist_ok=True)
        self._cancel.clear()
        for f in files:
            self._enqueue(f, "replay")
        return {"ok": True, "count": len(files)}

    # ---------------------------------------------------------------- record (sweep)

    def parse_earfcn_list(self, text):
        values, errors = earfcn.parse_list(text or "")
        preview = []
        for v in values[:6]:
            info = earfcn.describe(v)
            preview.append({"earfcn": v, "band": info["band"], "mhz": info["mhz"]})
        return {"count": len(values), "errors": errors, "preview": preview}

    def start_record(self, earfcn_text, listen, giveup, rf_args="", nof_rx_ant=1, nof_thread=4):
        if self._runner.running or self._sweep.active:
            return {"ok": False, "error": "A sweep is already running."}
        err = self._check_ready()
        if err:
            return {"ok": False, "error": err}
        giveup = GIVEUP_SECONDS  # fixed
        listen = float(self.state.get("listen") or 0)
        values, perr = earfcn.parse_list(earfcn_text or "")
        if perr:
            return {"ok": False, "error": "; ".join(perr[:4])}
        if not values:
            return {"ok": False, "error": "Enter at least one EARFCN to sweep."}
        out_dir = Path(self.state["out_dir"])
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return {"ok": False, "error": f"Cannot create {out_dir}: {exc}"}
        if len(rf_args or "") > 99:
            return {"ok": False, "error": "RF args is limited to 99 characters."}

        self._cancel.clear()
        nof_thread = 5  # fixed
        self._sweep_ctx = {"out_dir": str(out_dir), "listen": listen, "giveup": giveup,
                           "rf_args": rf_args or "", "nof_rx_ant": int(nof_rx_ant),
                           "nof_thread": int(nof_thread)}
        result = self._sweep.start(values, listen, giveup, False)  # record is one pass only
        return result if not result.get("ok") else {"ok": True, "earfcns": values}

    def _sweep_launch(self, value):
        ctx = self._sweep_ctx
        info = earfcn.describe(value)
        if ctx is None or info is None:
            return False, f"EARFCN {value} is not valid."
        binary, _ = find_binary(self.state.get("binary", ""))
        if not binary:
            return False, "Could not find the ngscope executable."
        chan = Path(ctx["out_dir"]) / f"earfcn-{value}"
        try:
            chan.mkdir(parents=True, exist_ok=True)
            cfg = chan / f"ngscope-gui-record-{value}.toml"
            pipeline.record_config(cfg, info["freq_hz"], ctx["rf_args"], ctx["nof_thread"],
                                   ctx["nof_rx_ant"])
        except OSError as exc:
            return False, f"Could not write config: {exc}"
        argv = [binary, "-c", str(cfg), "-o", str(chan)]
        self.run_dir = None
        self._push_lines([
            f"[gui] --- RECORD EARFCN {value} · band {info['band']} · {info['mhz']:.1f} MHz · "
            f"record {ctx['listen']:g}s from lock, give up after {ctx['giveup']:g}s ---",
            "[gui] " + " ".join(argv)])
        try:
            pid = self._runner.start(argv, cwd=str(chan),
                                     env_extra={"NGSCOPE_PLOT_SOCK": self._plots.path})
        except OSError as exc:
            return False, f"Could not launch ngscope: {exc}"
        self._push_lines([f"[gui] pid {pid}"])
        return True, {"pid": pid}

    def _replay_busy(self):
        """True while the sweep should wait: option on and a replay/compile/classify is active."""
        if not self.state.get("pause_for_replay") or self._cancel.is_set():
            return False
        return any(j["status"] in ("queued", "replaying", "compiling", "classifying")
                   for j in self._jobs_view())

    def _on_channel_done(self, step):
        """A channel's recording has finished: replay it immediately."""
        run_dir = step.get("run_dir")
        rec = Path(run_dir) / "recorded-samples.bin" if run_dir else None
        if not step.get("locked") or not rec or not rec.is_file():
            self._log(f"[gui] EARFCN {step.get('earfcn')}: no recording to replay "
                      f"({'no cell found' if not step.get('locked') else 'file missing'})")
            return
        self._log(f"[gui] EARFCN {step.get('earfcn')}: queued {rec} for replay")
        self._enqueue(rec, f"earfcn {step.get('earfcn')}")

    # ---------------------------------------------------------------- stop

    def stop(self):
        stopped = False
        if self._sweep.active:
            self._sweep.cancel()
            stopped = True
        elif self._runner.running:
            self._runner.stop()
            stopped = True
        pending = False
        with self._jobs_lock:
            pending = any(j["status"] not in ("done", "error", "cancelled") for j in self._jobs)
        if pending:
            self._cancel.set()
            proc = self._job_proc
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            if self._replay_runner.running:
                self._replay_runner.stop()
            stopped = True
        return {"ok": stopped}

    def clear_jobs(self):
        with self._jobs_lock:
            self._jobs = [j for j in self._jobs
                          if j["status"] not in ("done", "error", "cancelled")]
        return self._jobs_view()

    def status(self):
        return {"recording": self._runner.running or self._sweep.active,
                "busy": any(j["status"] in ("replaying", "compiling", "classifying", "queued")
                            for j in self._jobs_view())}


def _on_closing(api):
    def handler():
        api.save_state({})
        api._cancel.set()
        proc = api._job_proc
        if proc is not None and proc.poll() is None:
            proc.kill()
        api._runner.kill_now()
        api._replay_runner.kill_now()
        return True
    return handler


def main():
    api = Api()
    window = webview.create_window(
        "IMSIGuard", str(UI_DIR / "index.html"), js_api=api, width=1360, height=900,
        min_size=(1000, 680), background_color="#0f1116", text_select=True)
    api._window = window
    window.events.closing += _on_closing(api)
    webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
