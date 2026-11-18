"""Replay -> compile -> classify for one recording.

Replay uses exactly the settings of IMSIGUARD/scripts/replay-ngscope.py (its CONFIG_TEMPLATE).
Processing is IMSIGUARD/scripts/compile_replays.py run as its own CLI, and classification is
rules.py. Recording config is generated here (record mode is sweep-only).
"""

import bz2
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

from . import earfcn as earfcn_mod, rules as rules_mod

COMPILE_SCRIPT = Path("/home/jhuddleston/IMSIGUARD/scripts/compile_replays.py")
TS_RE = re.compile(r"^\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}$")
TS_ANY_RE = re.compile(r"\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}")
WORKER = Path(__file__).with_name("compile_worker.py")

# Verbatim from replay-ngscope.py.
REPLAY_TEMPLATE = """remote_enable = false
decode_SIB = false
decode_RAR = true
decode_pdsch = true
rar_seed_tracker = false
mark_security_phase = true
rach_filter_only = true
pcap_mac = true
pcap_max_mb = 0
qam_retry = true
tracked_search = "solve_first"
rx_combine = "irc"
probe_blind_dci = false
enable_256qam = false
exit_on_desync = 0

[[rf_config]]
rf_freq = 0
N_id_2 = -1
rf_args = ""
location = ""
comment = ""
nof_thread = 7
nof_rx_ant = 2
mode = 2
replay_fname = "{replay_fname}"
decode_pdcch = true
log_dl = true
log_ul = true
log_phich = false
disable_plot = {disable_plot}
debug = false
silent = false
use_replay_hdr = true

[dci_log_config]
log_interval = -1
"""

# Record: every RACH and security-context setting off, uplink+downlink logging on,
# gain-only noise estimation (rx_combine = "off"), PDSCH decoded, plots displayed.
RECORD_TEMPLATE = """remote_enable = false
decode_SIB = false
decode_RAR = false
decode_pdsch = true
rar_seed_tracker = false
mark_security_phase = false
rach_filter_only = false
pcap_mac = false
pcap_max_mb = 0
qam_retry = false
tracked_search = "per_rnti"
rx_combine = "off"
probe_blind_dci = false
enable_256qam = false
exit_on_desync = 0

[[rf_config]]
rf_freq = {rf_freq}
N_id_2 = -1
rf_args = "{rf_args}"
location = ""
comment = ""
nof_thread = {nof_thread}
nof_rx_ant = {nof_rx_ant}
mode = 1
decode_pdcch = true
log_dl = true
log_ul = true
log_phich = false
disable_plot = false
debug = false
silent = false
use_replay_hdr = false

[dci_log_config]
log_interval = -1
"""


def _esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def record_config(path, freq_hz, rf_args="", nof_thread=4, nof_rx_ant=1):
    Path(path).write_text(RECORD_TEMPLATE.format(
        rf_freq=int(freq_hz), rf_args=_esc(rf_args), nof_thread=int(nof_thread),
        nof_rx_ant=int(nof_rx_ant)), encoding="utf-8")


def safe_tag(path):
    name = Path(path).name
    for suf in (".bz2", ".gz", ".xz", ".bin"):
        if name.endswith(suf):
            name = name[: -len(suf)]
    name = TS_ANY_RE.sub("ts", name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "recording"


class Cancelled(Exception):
    pass


def process_recording(rec_path, work_root, ngscope_bin, rules, listen, log,
                      timeout=900, processes=1, stage=lambda s: None, cancel=lambda: False,
                      set_proc=lambda p: None, run_ngscope=None, plots=False):
    """Run the whole replay pipeline for one recording. Returns the result dict."""
    rec_path = Path(rec_path)
    if not rec_path.is_file():
        raise FileNotFoundError(f"{rec_path} does not exist")
    if not COMPILE_SCRIPT.is_file():
        raise FileNotFoundError(f"{COMPILE_SCRIPT} is missing")

    # Deliberately not the YYYY_MM_DD_hh_mm_ss form: compile_replays.py treats any directory with
    # that pattern in its path as a run and walks up parents until the name matches.
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag_dir = Path(work_root) / "replays" / f"{safe_tag(rec_path)}-{stamp}"
    pending = tag_dir / "pending"
    pending.mkdir(parents=True, exist_ok=True)

    # ---- replay
    stage("replaying")
    cfg = pending / "replay-config.toml"
    cfg.write_text(REPLAY_TEMPLATE.format(replay_fname=_esc(rec_path),
                                          disable_plot="false" if plots else "true"),
                   encoding="utf-8")
    argv = [ngscope_bin, "-c", str(cfg), "-o", str(pending)]
    log("[replay] " + " ".join(argv))
    # run_ngscope streams the output to the console (and plot socket) and returns the exit code.
    code = run_ngscope(argv, str(pending), plots, tag_dir / "ngscope_output.txt.bz2", timeout)
    if cancel():
        raise Cancelled()
    log(f"[replay] ngscope exited {code}")

    runs = sorted(p for p in pending.iterdir() if p.is_dir() and TS_RE.match(p.name))
    if not runs:
        raise RuntimeError("replay produced no run directory (see ngscope_output.txt.bz2 in "
                           f"{tag_dir})")
    run = runs[-1]

    # ---- place under <tag>/unknown-<earfcn>/<timestamp> as compile_replays expects
    hdr = run / "replay_hdr_0.json"
    if not hdr.is_file():
        raise RuntimeError(f"{run.name}: no replay_hdr_0.json; the replay did not start")
    freq = _read_freq(hdr)
    cands = earfcn_mod.freq_to_earfcns(freq)
    if not cands:
        raise RuntimeError(f"No EARFCN matches recorded frequency {freq} Hz")
    ear = cands[0][0]
    dest_parent = tag_dir / f"unknown-{ear}"
    dest_parent.mkdir(exist_ok=True)
    dest = dest_parent / run.name
    shutil.move(str(run), str(dest))
    shutil.rmtree(pending, ignore_errors=True)

    # ---- compile (only the interval the classifier needs, no intermediate CSV)
    stage("compiling")
    csv = tag_dir / f"celldf_{int(listen)}s.csv"
    cmd = [sys.executable, str(WORKER), str(dest), str(int(listen)), str(csv)]
    log("[compile] " + " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            cwd=str(tag_dir))
    set_proc(proc)
    try:
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log("[compile] " + line)
        code = proc.wait()
    finally:
        set_proc(None)
    if cancel():
        raise Cancelled()
    if code != 0 or not csv.is_file():
        raise RuntimeError(f"compile failed (exit {code}); no decodable UEs in the replay?")
    celldf = pd.read_csv(csv)
    if celldf.empty:
        raise RuntimeError("compiled celldf is empty -- no UEs were decoded in the replay")

    # ---- classify
    stage("classifying")
    windows = rules_mod.classify(celldf, rules, listen)
    log(f"[classify] {len(windows)} window(s) of {int(listen)}s evaluated")
    return {"recording": str(rec_path), "work_dir": str(tag_dir), "celldf": str(csv),
            "earfcn": ear, "windows": windows, **rules_mod.summarize(windows)}


def _read_freq(path):
    text = Path(path).read_text()
    try:
        return float(json.loads(text)["rf_freq"])
    except (json.JSONDecodeError, KeyError):
        m = re.search(r"rf_freq\s*:\s*([0-9.eE+]+)", text)
        if not m:
            raise RuntimeError("rf_freq not found in replay header")
        return float(m.group(1))
