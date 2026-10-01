"""Sequence a run of ngscope across a list of EARFCNs.

ngscope has no scanning mode: it takes one rf_freq and runs until SIGINT. So a sweep is
orchestrated here -- write a config for the next EARFCN, launch, listen, SIGINT, wait for the
process to exit, repeat. Each launch gets its own <out_dir>/<timestamp>/ from ngscope, so
the per-channel logs stay separate without any extra bookkeeping.

Each channel has two phases, because time spent hunting for a cell is not time spent
listening to one:

  acquire   from launch until the radio reports it is ready. Bounded by `acquire`: a channel
            with nothing on it would otherwise retry cell search forever, and the whole
            point of a sweep is to move on.
  listen    the dwell proper, timed from lock, so every channel that locks gets the same
            amount of decoding regardless of how long its cell search took.

Progression is driven by the process actually exiting, not by a timer alone. A timer only
asks ngscope to stop; the next channel starts when the previous one is really gone, so two
decoders never contend for the same SDR.
"""

import re
import threading
import time

from . import earfcn as earfcn_mod

# srsRAN prints a line per cell-search candidate and stars the one it locked onto:
#   *Found Cell_id:  56 FDD, CP: Normal  , DetectRatio=100% PSR=2.16, Power=4.1 dBm
FOUND_CELL_RE = re.compile(r"^\s*\*Found Cell_id:\s*(\d+)")
PRB_RE = re.compile(r"^\s*-\s*PRB:\s*(\d+)")

# The receive path is up. On its own this is NOT proof of a lock: ngscope also prints it
# while tearing down, so a channel with no cell would appear to lock at the exact moment the
# give-up timer fired. Lock therefore requires a starred Found Cell_id first (see _on_lock).
READY_RE = re.compile(r"Radio is ready|ALL THREE CELL ARE READY")


class Sweep:
    """One sweep at a time. `launch(earfcn)` must return (ok, error)."""

    def __init__(self, launch, stop, progress, on_result=None):
        self._launch = launch
        self._stop = stop
        self._progress = progress
        # Called with each completed channel, so the summary is written as the sweep runs
        # rather than only at the end -- an interrupted sweep still leaves its rows.
        self._on_result = on_result

        self.active = False
        self._lock = threading.Lock()
        self._acquire_timer = None
        self._dwell_timer = None
        self._cancelled = False

        self.earfcns = []
        self.dwell = 0
        self.acquire = 0
        self.repeat = False
        self.index = 0
        self.cycle = 1
        self.results = []
        self._step = None
        self._lock_at = None

    # ------------------------------------------------------------------ control

    def start(self, earfcns, dwell, acquire, repeat):
        if self.active:
            return {"ok": False, "error": "A sweep is already running."}
        if not earfcns:
            return {"ok": False, "error": "No EARFCNs to sweep."}

        self.active = True
        self._cancelled = False
        self.earfcns = list(earfcns)
        self.dwell = float(dwell)
        self.acquire = float(acquire)
        self.repeat = bool(repeat)
        self.index = 0
        self.cycle = 1
        self.results = []
        return self._begin_step()

    def cancel(self):
        """Stop after the current channel; the running process is asked to exit."""
        if not self.active:
            return False
        self._cancelled = True
        self._cancel_timers()
        self._stop()
        return True

    # ------------------------------------------------------------------ timers

    def _cancel_timers(self):
        with self._lock:
            for name in ("_acquire_timer", "_dwell_timer"):
                timer = getattr(self, name)
                if timer is not None:
                    timer.cancel()
                    setattr(self, name, None)

    def _arm(self, name, seconds, callback):
        timer = threading.Timer(seconds, callback)
        timer.daemon = True
        with self._lock:
            setattr(self, name, timer)
        timer.start()

    # ------------------------------------------------------------------ steps

    def _begin_step(self):
        value = self.earfcns[self.index]
        info = earfcn_mod.describe(value)

        self._lock_at = None
        self._step = {
            "earfcn": value,
            "cycle": self.cycle,
            "band": info["band"] if info else None,
            "freq_hz": info["freq_hz"] if info else 0,
            "started": time.monotonic(),
            "locked": False,
            "lock_s": None,      # seconds from launch to lock
            "listen_s": None,    # seconds decoding after lock
            "pci": None,
            "prb": None,
            "run_dir": None,
            "exit_code": None,
        }

        ok, error = self._launch(value)
        if not ok:
            self.active = False
            self._step = None
            return {"ok": False, "error": error}

        self._arm("_acquire_timer", self.acquire, self._acquire_expired)
        self._emit("acquiring")
        return {"ok": True}

    def _on_lock(self):
        """The radio is up on a cell we actually found: start the dwell."""
        with self._lock:
            if self._step is None or self._step["locked"]:
                return
            # No starred Found Cell_id means cell search never succeeded, so a ready line
            # here came from the shutdown path rather than from a lock.
            if self._step["pci"] is None:
                return
            self._step["locked"] = True
            self._lock_at = time.monotonic()
            self._step["lock_s"] = round(self._lock_at - self._step["started"], 1)
            if self._acquire_timer is not None:
                self._acquire_timer.cancel()
                self._acquire_timer = None

        self._arm("_dwell_timer", self.dwell, self._dwell_elapsed)
        self._emit("listening")

    def _acquire_expired(self):
        """No cell within the give-up window; record it and move on."""
        with self._lock:
            self._acquire_timer = None
            if self._step is None or self._step["locked"]:
                return
        if self.active:
            self._emit("no-cell")
            self._stop()

    def _dwell_elapsed(self):
        """Dwell is up: ask ngscope to exit. Advancing happens in on_exit()."""
        with self._lock:
            self._dwell_timer = None
        if self.active:
            self._emit("stopping")
            self._stop()

    def on_exit(self, code):
        """Called when the ngscope process for the current channel has exited."""
        if not self.active:
            return
        self._cancel_timers()

        now = time.monotonic()
        step = self._step or {}
        step["exit_code"] = code
        step["seconds"] = round(now - step.get("started", now), 1)
        if step.get("locked") and self._lock_at is not None:
            step["listen_s"] = round(now - self._lock_at, 1)
        step.pop("started", None)
        self.results.append(step)
        self._step = None
        self._lock_at = None

        if self._on_result is not None:
            try:
                self._on_result(step)
            except Exception:  # noqa: BLE001 - a summary write must not derail the sweep
                pass

        if self._cancelled:
            self._finish("cancelled")
            return

        self.index += 1
        if self.index >= len(self.earfcns):
            if not self.repeat:
                self._finish("done")
                return
            self.index = 0
            self.cycle += 1

        result = self._begin_step()
        if not result.get("ok"):
            self._finish("error", result.get("error"))

    def _finish(self, reason, error=None):
        self.active = False
        self._cancel_timers()
        self._emit(reason, error)

    # ------------------------------------------------------------------ output

    def note_line(self, text):
        """Watch the console for the cell identity and then the lock."""
        if self._step is None:
            return

        # Order matters and matches ngscope's output: the starred cell-search result comes
        # first, the ready line after it.
        match = FOUND_CELL_RE.match(text)
        if match:
            self._step["pci"] = int(match.group(1))
            return
        match = PRB_RE.match(text)
        if match:
            self._step["prb"] = int(match.group(1))
            return

        if READY_RE.search(text):
            self._on_lock()

    def note_run_dir(self, path):
        if self._step is not None:
            self._step["run_dir"] = path

    def _emit(self, phase, error=None):
        self._progress(self.state(phase, error))

    def state(self, phase, error=None):
        return {
            # acquiring | listening | no-cell | stopping | done | cancelled | error
            "phase": phase,
            "active": self.active,
            "index": self.index,
            "total": len(self.earfcns),
            "cycle": self.cycle,
            "repeat": self.repeat,
            "dwell": self.dwell,
            "acquire": self.acquire,
            "current": dict(self._step) if self._step else None,
            "results": list(self.results),
            "error": error,
        }
