"""Launch ngscope and pump its output back to the UI.

Two things drive the design here:

* ngscope logs with plain printf(). Through a pipe, libc switches stdout to block
  buffering and the console would sit empty for minutes and then dump 4 KB at a time. The
  child is therefore given a pty, which keeps it line-buffered exactly as in a terminal.

* Stopping has to be graceful. SIGINT sets `go_exit` (ngscope/src/main.c:45) and every
  worker loop polls it, so the process unwinds and flushes its logs. Only if that does not
  land do we escalate.
"""

import errno
import os
import pty
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

# gui/ngscope_gui/runner.py -> gui/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

FLUSH_INTERVAL = 0.05  # seconds between UI pushes; caps evaluate_js churn in debug mode
MAX_LINE = 8192  # flush a partial line this long rather than buffering forever

SIGINT_GRACE = 10.0
SIGTERM_GRACE = 5.0


def find_binary(override=""):
    """Resolve the ngscope executable. Returns (path, source) or (None, None)."""
    candidates = []
    if override:
        candidates.append((Path(override).expanduser(), "override"))
    candidates.append((REPO_ROOT / "build" / "ngscope" / "src" / "ngscope", "build tree"))

    which = shutil.which("ngscope")
    if which:
        candidates.append((Path(which), "PATH"))
    candidates.append((Path("/usr/local/bin/ngscope"), "/usr/local/bin"))

    for path, source in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path), source
    return None, None


class Runner:
    """Owns at most one ngscope process."""

    def __init__(self, on_lines, on_exit):
        self._on_lines = on_lines
        self._on_exit = on_exit
        self._proc = None
        self._master = None
        self._pending = []
        self._lock = threading.Lock()
        self._stopping = False
        self._reader_done = threading.Event()

    # ------------------------------------------------------------------ state

    @property
    def running(self):
        return self._proc is not None and self._proc.poll() is None

    @property
    def stopping(self):
        return self._stopping

    # ------------------------------------------------------------------ start

    def start(self, argv, cwd=None, env_extra=None):
        if self.running:
            raise RuntimeError("ngscope is already running")

        env = None
        if env_extra:
            env = dict(os.environ)
            env.update(env_extra)

        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=slave,
                stderr=slave,
                close_fds=True,
                # Own process group, so a stop signal reaches the decoder threads'
                # process and nothing else.
                start_new_session=True,
            )
        except OSError:
            os.close(master)
            os.close(slave)
            raise
        finally:
            # The parent must not hold the slave open, or reading the master never sees
            # EOF after the child exits.
            try:
                os.close(slave)
            except OSError:
                pass

        self._proc = proc
        self._master = master
        self._stopping = False
        self._pending = []
        self._reader_done.clear()

        threading.Thread(target=self._read_loop, name="ngscope-read", daemon=True).start()
        threading.Thread(target=self._flush_loop, name="ngscope-flush", daemon=True).start()
        threading.Thread(target=self._wait_loop, name="ngscope-wait", daemon=True).start()
        return proc.pid

    # ------------------------------------------------------------------ output

    def _read_loop(self):
        buf = ""
        while True:
            try:
                chunk = os.read(self._master, 65536)
            except OSError as exc:
                # EIO is the normal pty signal that the child closed its end.
                if exc.errno not in (errno.EIO, errno.EBADF):
                    self._queue([f"[gui] error reading output: {exc}"])
                break
            if not chunk:
                break

            buf += chunk.decode("utf-8", errors="replace")
            # Normalise CRLF and bare CR (progress-style rewrites) to line breaks so one
            # rewritten status line does not grow without bound.
            buf = buf.replace("\r\n", "\n").replace("\r", "\n")

            if "\n" in buf:
                *lines, buf = buf.split("\n")
                self._queue(lines)
            elif len(buf) >= MAX_LINE:
                self._queue([buf])
                buf = ""

        if buf:
            self._queue([buf])
        self._reader_done.set()

    def _queue(self, lines):
        with self._lock:
            self._pending.extend(lines)

    def _drain(self):
        with self._lock:
            if not self._pending:
                return []
            lines, self._pending = self._pending, []
        return lines

    def _flush_loop(self):
        # Runs until the reader has hit EOF *and* the queue is empty, so the last lines
        # before an early exit (a rejected config, say) still reach the console.
        while True:
            time.sleep(FLUSH_INTERVAL)
            lines = self._drain()
            if lines:
                self._on_lines(lines)
                continue
            if self._reader_done.is_set():
                return

    # ------------------------------------------------------------------ exit

    def _wait_loop(self):
        proc = self._proc
        code = proc.wait()

        # Let the reader reach EOF and the flusher deliver what is left before the exit
        # notice lands, so the console reads in the order things happened.
        self._reader_done.wait(timeout=3.0)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            with self._lock:
                if not self._pending:
                    break
            time.sleep(FLUSH_INTERVAL)

        try:
            os.close(self._master)
        except OSError:
            pass

        self._stopping = False
        self._on_exit(code)

    # ------------------------------------------------------------------ stop

    def stop(self):
        """Ask ngscope to exit; escalate if it does not. Returns immediately."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return False
        self._stopping = True
        # Bind the escalation to this exact process, so it cannot outlive the run and
        # signal whatever started next.
        threading.Thread(
            target=self._stop_sequence, args=(proc,), name="ngscope-stop", daemon=True
        ).start()
        return True

    def _signal(self, sig, proc=None):
        proc = proc if proc is not None else self._proc
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            pass

    @staticmethod
    def _wait_for_proc(proc, timeout):
        """Wait for *this* process, not for 'nothing is running'.

        The distinction matters as soon as runs are sequenced: an escalation thread that
        polls a global 'is something running' flag will see the *next* run and, when its
        grace period expires, signal that instead of the process it was asked to stop.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return True
            time.sleep(0.1)
        return proc.poll() is not None

    def _stop_sequence(self, proc):
        self._queue(["[gui] SIGINT sent -- waiting for ngscope to flush and exit"])
        self._signal(signal.SIGINT, proc)
        if self._wait_for_proc(proc, SIGINT_GRACE):
            return

        self._queue([f"[gui] still running after {SIGINT_GRACE:.0f}s, sending SIGTERM"])
        self._signal(signal.SIGTERM, proc)
        if self._wait_for_proc(proc, SIGTERM_GRACE):
            return

        self._queue([f"[gui] still running after {SIGTERM_GRACE:.0f}s, sending SIGKILL"])
        self._signal(signal.SIGKILL, proc)

    def kill_now(self):
        """Used on window close -- no point waiting for a graceful unwind."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            self._signal(signal.SIGINT, proc)
            if not self._wait_for_proc(proc, 3.0):
                self._signal(signal.SIGKILL, proc)


def describe_exit(code):
    if code == 0:
        return "exited cleanly", "ok"
    if code is not None and code < 0:
        name = signal.Signals(-code).name
        # ngscope's SIGINT handler sets go_exit and returns; the process itself normally
        # exits via main(), so a signal here means it was killed rather than asked.
        return f"killed by {name}", "warn" if -code in (signal.SIGINT, signal.SIGTERM) else "error"
    return f"exited with code {code}", "error"
