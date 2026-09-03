#!/usr/bin/env python3
"""Derive per-UE security outcomes for an NG-Scope run by dissecting its MAC pcapng.

Why this exists
---------------
NG-Scope used to parse RRC in-process to find SecurityModeCommand. Every time that parser
was compared against Wireshark on the same bytes it came up short -- it bailed on RLC
segmentation and on length-indicator chains, and it had no NAS layer at all. Wireshark
does all three. So ngscope now only writes the bytes, and every claim about what they mean
is made here.

What it reads
-------------
    mac-<rf>.pcapng     every downlink MAC PDU ngscope decoded, in decode-completion order
    rar_log-<rf>.csv    the RAR anchors: the denominator

What it writes
--------------
    security_events-<rf>.csv    one row per indicator occurrence (not per frame)
    security_sessions-<rf>.csv  one row per RAR-anchored session -- the funnel
    security_summary.json       provenance, validity checks, per-cell counts

The three files are created with their headers before anything that can fail, so an empty
file means "measured, found nothing" and an absent file means "never analysed". That
distinction is the whole point for IMSI-catcher detection, where finding nothing is the
positive result.

Ordering
--------
Wireshark's rlc-lte and pdcp-lte dissectors reassemble statefully and order-dependently,
so the capture is passed through reordercap first and the *reordered* file is the one that
gets dissected -- and the one that ships. Frame numbers in security_events index that file,
so every row is directly clickable in Wireshark.
"""

import argparse
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, defaultdict

# Wireshark has no registered link type for DLT 147 (DLT_USER0), so every invocation has
# to say what is inside. Same mapping documented in docs/pcap.md.
DLT_OPT = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'

# The tracker's window (SEC_TRACK_WINDOW_US, security_ctx.c). Bounds what could possibly
# have been *observed* for a UE, as distinct from what can be attributed to it.
TRACK_WINDOW_US = 10 * 1000 * 1000

# --------------------------------------------------------------------------- indicators

# Ordered: the first matching entry wins when one frame fires several, which only matters
# for the per-frame `signal` summary; every occurrence still gets its own event row.
#
# Deliberately the OUTER _element field, never ..._r8_element: the inner one is absent
# whenever the critical-extensions body fails to dissect, which silently drops real
# messages. And never _ws.col.Info, which holds one summary per frame, last writer wins --
# that undercounted SecurityModeCommand 7-vs-12 on a real capture.
RRC_FIELDS = [
    ("lte-rrc.securityModeCommand_element",              "securityModeCommand",              "established"),
    ("lte-rrc.rrcConnectionReestablishment_element",     "rrcConnectionReestablishment",     "reused"),
    ("lte-rrc.rrcConnectionResume_r13_element",          "rrcConnectionResume",              "reused"),
    ("lte-rrc.rrcConnectionReject_element",              "rrcConnectionReject",              "refused"),
    ("lte-rrc.rrcConnectionReestablishmentReject_element","rrcConnectionReestablishmentReject","refused"),
    ("lte-rrc.rrcConnectionSetup_element",               "rrcConnectionSetup",               "progress"),
    ("lte-rrc.rrcConnectionRelease_element",             "rrcConnectionRelease",             "released"),
]

# nas-eps.nas_msg_emm_type comes out as hex. A decimal map silently reports zero of
# everything, which is a plausible-looking wrong answer -- it cost an hour once.
NAS_TYPES = {
    0x42: ("nasAttachAccept",         "nas_accepted"),
    0x44: ("nasAttachReject",         "nas_refused"),
    0x4B: ("nasTauReject",            "nas_refused"),
    0x4E: ("nasServiceReject",        "nas_refused"),
    0x52: ("nasAuthenticationRequest","nas_progress"),
    0x54: ("nasAuthReject",           "nas_refused"),
    0x5D: ("nasSecurityModeCommand",  "nas_established"),
}

# nas-eps.security_header_type: 2 and 4 are "integrity protected AND ciphered". Unlike the
# AS layer, NAS states its own security in the clear, so this needs no inference.
NAS_PROTECTED_HEADERS = {2, 4}

TSHARK_FIELDS = [
    "frame.number", "frame.comment",
    "mac-lte.rnti", "mac-lte.dlsch.lcid",
    "mac-lte.rar.rapid", "mac-lte.rar.temporary-crnti", "mac-lte.rar.ta",
    "nas-eps.nas_msg_emm_type", "nas-eps.security_header_type",
    "rlc-lte.reassembly-info.number-of-segments",
    "rlc-lte.sequence-analysis.skipped-frames",
] + [f for f, _, _ in RRC_FIELDS]

EVENT_HEADER = ["frame", "rf_idx", "rnti", "src", "tti", "ct", "ts_us",
                "layer", "event", "field", "signal", "lcid",
                "rlc_segments", "rlc_skipped"]

SESSION_HEADER = ["rnti", "rar_tti", "rar_ct", "session_end_ct", "window_end_ct",
                  "outcome", "outcome_event", "outcome_ct", "ms_rar_to_outcome",
                  "nas_outcome", "nas_outcome_event",
                  "n_pdus", "n_srb_pdus", "n_events", "evidence"]

# Resolved highest-priority-first. `no_traffic` (nothing decoded at all) is kept apart from
# `none` (traffic decoded, no evidence): the first is a statement about the receiver, the
# second about the cell. Collapsing them would hide the difference that matters.
OUTCOME_PRIORITY = ["established", "reused", "refused", "released", "in_progress"]

NAS_PRIORITY = ["protected", "nas_smc", "rejected", "accepted", "auth_requested"]

_RE_RNTI = re.compile(r"rnti=0x([0-9a-fA-F]+)")
_RE_TTI = re.compile(r"tti=(\d+)")
_RE_CT = re.compile(r"ct=(\d+)")
_RE_SRC = re.compile(r"src=(\w+)")
_RE_RF = re.compile(r"rf=(\d+)")
_RE_TBS = re.compile(r"tbs=(\d+)")


# Mirrors ngscope_sec_is_unicast(): SI-RNTI, P-RNTI and RA-RNTI are not UE identities and
# have no security context, so they are "n/a" rather than "unknown".
BROADCAST_RNTIS = {0, 0xFFFF, 0xFFFE}
RARNTI_RANGE = range(1, 0x000B)


def is_unicast(rnti):
    return rnti is not None and rnti not in BROADCAST_RNTIS and rnti not in RARNTI_RANGE


def _ints(cell):
    """tshark -E occurrence=a comma-joins repeated fields within one frame."""
    out = []
    for tok in (cell or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok, 16) if tok.lower().startswith("0x") else int(tok))
        except ValueError:
            pass
    return out


def run_tshark(pcap, extra_filter=None):
    """One pass, every field. Returns a list of dicts keyed by field name."""
    argv = ["tshark", "-r", pcap, "-o", DLT_OPT, "-T", "fields", "-E", "occurrence=a"]
    if extra_filter:
        argv += ["-Y", extra_filter]
    for f in TSHARK_FIELDS:
        argv += ["-e", f]
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {(proc.stderr or '').strip().splitlines()[-1:]}")
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))
        rows.append(dict(zip(TSHARK_FIELDS, parts)))
    return rows


def reorder(src, dst):
    """Sort into timestamp order via reordercap. Returns (status, out_of_order|None).

    Not reimplemented in-process on purpose: the reordering window is unbounded, so no
    fixed-size sort would be correct, and reordercap already handles the pcapng block
    bookkeeping.
    """
    exe = shutil.which("reordercap")
    if exe is None:
        shutil.copyfile(src, dst)
        return ("reordercap not found (install wireshark-common); left in decode order", None)
    proc = subprocess.run([exe, src, dst], capture_output=True, text=True)
    if proc.returncode != 0 or not os.path.exists(dst):
        shutil.copyfile(src, dst)
        return (f"reordercap failed ({proc.returncode}); left in decode order", None)
    note = (proc.stdout or "").strip().splitlines()
    n = None
    if note:
        m = re.search(r"(\d+) out of order", note[-1])
        if m:
            n = int(m.group(1))
    return (note[-1] if note else "reordered", n)


def load_rar_anchors(run_dir, rf_idx):
    """Seed sessions from ngscope's RAR log: the denominator.

    Seeded before dissection so every anchored UE gets a row whether or not any evidence
    was found -- "no evidence" has to be a value in a column, not a missing row.
    """
    path = os.path.join(run_dir, f"rar_log-{rf_idx}.csv")
    if not os.path.isfile(path):
        return [], None
    anchors = []
    with open(path) as fh:
        for row in csv.DictReader(fh):
            try:
                anchors.append({
                    "rnti": int(row["temp_crnti"]),
                    "rar_tti": int(row["tti"]),
                    "rar_ct": int(row["collection_time"]),
                    "rapid": int(row.get("rapid") or -1),
                    "ta": int(row.get("ta_cmd") or -1),
                })
            except (KeyError, ValueError):
                continue
    anchors.sort(key=lambda a: (a["rnti"], a["rar_ct"]))
    return anchors, path


def build_events(rows):
    """One row per indicator occurrence. Also returns per-frame bookkeeping."""
    events = []
    frames = []
    for r in rows:
        cmt = r["frame.comment"] or ""
        m_rnti = _RE_RNTI.search(cmt)
        m_ct = _RE_CT.search(cmt)
        info = {
            "frame": int(r["frame.number"] or 0),
            "rnti": int(m_rnti.group(1), 16) if m_rnti else None,
            "ct": int(m_ct.group(1)) if m_ct else None,
            "tti": int(_RE_TTI.search(cmt).group(1)) if _RE_TTI.search(cmt) else None,
            "src": _RE_SRC.search(cmt).group(1) if _RE_SRC.search(cmt) else "",
            "rf_idx": int(_RE_RF.search(cmt).group(1)) if _RE_RF.search(cmt) else 0,
            "tbs": int(_RE_TBS.search(cmt).group(1)) if _RE_TBS.search(cmt) else None,
            "diss_rnti": _ints(r["mac-lte.rnti"]),
            "lcid": r["mac-lte.dlsch.lcid"] or "",
            "rar_crnti": _ints(r["mac-lte.rar.temporary-crnti"]),
            "rar_rapid": _ints(r["mac-lte.rar.rapid"]),
            "rar_ta": _ints(r["mac-lte.rar.ta"]),
            "has_comment": bool(cmt),
        }
        frames.append(info)

        segs = _ints(r["rlc-lte.reassembly-info.number-of-segments"])
        skipped = _ints(r["rlc-lte.sequence-analysis.skipped-frames"])

        def emit(layer, name, field, signal):
            events.append({
                "frame": info["frame"], "rf_idx": info["rf_idx"], "rnti": info["rnti"],
                "src": info["src"], "tti": info["tti"], "ct": info["ct"], "ts_us": "",
                "layer": layer, "event": name, "field": field, "signal": signal,
                "lcid": info["lcid"],
                "rlc_segments": segs[0] if segs else "",
                "rlc_skipped": skipped[0] if skipped else "",
            })

        for field, name, signal in RRC_FIELDS:
            for _ in range(len((r[field] or "").split(",")) if (r[field] or "").strip() else 0):
                emit("rrc", name, field, signal)

        for code in _ints(r["nas-eps.nas_msg_emm_type"]):
            name, signal = NAS_TYPES.get(code, (f"nasType0x{code:02x}", "nas_other"))
            emit("nas", name, f"nas-eps.nas_msg_emm_type=0x{code:02x}", signal)

        for hdr in _ints(r["nas-eps.security_header_type"]):
            if hdr in NAS_PROTECTED_HEADERS:
                emit("nas", "nasProtected",
                     f"nas-eps.security_header_type={hdr}", "nas_protected")

    return events, frames


def build_sessions(anchors, events, frames):
    """Attribute every event and PDU to the session that was open when it happened.

    Attribution is by collection_time -- the radio clock -- not the host wall clock, which
    in a replay advances at decode speed.
    """
    by_rnti = defaultdict(list)
    for a in anchors:
        by_rnti[a["rnti"]].append(a)

    sessions = []
    for rnti, group in by_rnti.items():
        for i, a in enumerate(group):
            nxt = group[i + 1]["rar_ct"] if i + 1 < len(group) else None
            sessions.append({
                **a,
                "session_end_ct": nxt,
                "window_end_ct": a["rar_ct"] + TRACK_WINDOW_US,
                "events": [], "n_pdus": 0, "n_srb_pdus": 0,
            })
    sessions.sort(key=lambda s: (s["rnti"], s["rar_ct"]))

    idx = defaultdict(list)
    for s in sessions:
        idx[s["rnti"]].append(s)

    def find(rnti, ct):
        best = None
        for s in idx.get(rnti, []):
            if ct is None or ct < s["rar_ct"]:
                continue
            if s["session_end_ct"] is not None and ct >= s["session_end_ct"]:
                continue
            best = s
        return best

    for f in frames:
        if f["src"] != "targeted" or f["rnti"] is None:
            continue
        s = find(f["rnti"], f["ct"])
        if s is None:
            continue
        s["n_pdus"] += 1
        if any(t.strip() in ("0x01", "0x02") for t in f["lcid"].split(",")):
            s["n_srb_pdus"] += 1

    for e in events:
        s = find(e["rnti"], e["ct"])
        if s is not None:
            s["events"].append(e)
    return sessions


def resolve_outcome(s):
    """AS outcome from RRC evidence only; NAS is reported separately.

    NAS security is a different context with a different peer -- SecurityModeCommand on the
    DCCH establishes AS security with the eNB, while the NAS Security mode command
    establishes NAS security with the MME. A UE can complete one without the other, and on
    the trolley capture exactly one did. Folding NAS into the AS outcome would have counted
    it as a boundary the eNB never sent.
    """
    rrc = [e for e in s["events"] if e["layer"] == "rrc"]
    signals = {e["signal"] for e in rrc}
    first = {}
    for e in rrc:
        first.setdefault(e["signal"], e)

    outcome, ev = None, None
    for cand in OUTCOME_PRIORITY:
        if cand in signals:
            outcome, ev = cand, first[cand]
            break
    if outcome is None:
        if "progress" in signals:
            outcome, ev = "in_progress", first["progress"]
        elif s["n_pdus"] == 0:
            outcome = "no_traffic"
        else:
            outcome = "none"

    nas_ev = next((e for e in s["events"] if e["layer"] == "nas"), None)
    nas_outcome = "none"
    if any(e["event"] == "nasProtected" for e in s["events"]):
        nas_outcome = "protected"
    elif any(e["event"] == "nasSecurityModeCommand" for e in s["events"]):
        nas_outcome = "nas_smc"
    elif any(e["layer"] == "nas" and e["signal"] == "nas_refused" for e in s["events"]):
        nas_outcome = "rejected"
    elif any(e["event"] == "nasAttachAccept" for e in s["events"]):
        nas_outcome = "accepted"
    elif any(e["event"] == "nasAuthenticationRequest" for e in s["events"]):
        nas_outcome = "auth_requested"

    return outcome, ev, nas_outcome, nas_ev


# --------------------------------------------------------------------------- sec= patch

# ngscope pads sec= to exactly 7 characters (mac_pcap.c, "%-7s") so this is a byte-for-byte
# splice: no block length, option length or padding changes. Every token below must fit.
SEC_FIELD_WIDTH = 7
_SEC_RE = re.compile(rb"sec=([a-z/ ]{7})")

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_EPB = 0x00000006
OPT_ENDOFOPT = 0
OPT_COMMENT = 1

# The seven values. `none` and `unknown` are NOT the same claim: `none` means we watched a
# UE with decoded traffic and saw no security evidence -- a measurement, and the signal an
# IMSI-catcher would produce -- while `unknown` means we could not watch. Collapsing them
# would hide the detection behind the coverage gap.
SEC_FROM_OUTCOME = {
    "reused": "reused",     # a context existed before this capture; nothing here precedes it
    "refused": "noctx",     # the network rejected the connection, so none was ever created
    "released": "none",     # traffic decoded, connection ended, no security ever seen
    "none": "none",
    "in_progress": "unknown",
    "no_traffic": "unknown",
}
for _t in list(SEC_FROM_OUTCOME.values()) + ["pre", "post", "n/a", "unknown"]:
    assert len(_t) <= SEC_FIELD_WIDTH, f"sec= token {_t!r} exceeds the fixed field width"


def _patch_epb(body, endian, verdict):
    """Splice the 7-char sec= field of one Enhanced Packet Block's comment."""
    if len(body) < 24:
        return body
    caplen = struct.unpack(endian + "I", body[12:16])[0]
    off = 20 + ((caplen + 3) & ~3)
    end = len(body) - 4
    out = bytearray(body)
    while off + 4 <= end:
        code, length = struct.unpack(endian + "HH", bytes(out[off:off + 4]))
        if code == OPT_ENDOFOPT:
            break
        val_start = off + 4
        if val_start + length > end:
            break
        if code == OPT_COMMENT:
            cmt = bytes(out[val_start:val_start + length])
            m = _SEC_RE.search(cmt)
            if m:
                new = verdict.encode().ljust(SEC_FIELD_WIDTH)
                if len(new) == SEC_FIELD_WIDTH:
                    out[val_start + m.start(1):val_start + m.end(1)] = new
        off = val_start + ((length + 3) & ~3)
    return bytes(out)


def patch_pcap(path, verdict_by_frame):
    """Rewrite sec= in place, keyed on frame number.

    Frame number rather than (rnti, timestamp) because tshark hands us an index into the
    file it dissected, and this patches that same file -- so two PDUs for one RNTI in one
    subframe stop being ambiguous. Streamed a block at a time; the file is never loaded.
    """
    tmp = path + ".patch.tmp"
    n = 0
    with open(path, "rb") as src, open(tmp, "wb") as dst:
        head = src.read(12)
        if len(head) < 12 or struct.unpack("<I", head[:4])[0] != PCAPNG_SHB:
            os.unlink(tmp)
            raise ValueError(f"{path}: not a pcapng section header")
        magic = head[8:12]
        endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
        total = struct.unpack(endian + "I", head[4:8])[0]
        dst.write(head)
        dst.write(src.read(total - 12))
        while True:
            hdr = src.read(8)
            if len(hdr) < 8:
                break
            btype, total = struct.unpack(endian + "II", hdr)
            if total < 12:
                break
            body = src.read(total - 8)
            if len(body) < total - 8:
                break
            if btype == PCAPNG_EPB:
                n += 1
                body = _patch_epb(body, endian, verdict_by_frame.get(n, "unknown"))
            dst.write(hdr)
            dst.write(body)
    os.replace(tmp, path)
    return n


def verify_patch(pcap, rows_before):
    """Re-dissect the patched file and assert the splice touched nothing but sec=.

    The patch rewrites 7 bytes inside a pcapng option; get the block or option lengths wrong
    and the file stays superficially readable while frames after the damage shift or vanish.
    That is the failure this catches, and it catches it on every run rather than whenever
    someone remembers to diff two dissections by hand.

    Everything except frame.comment must come back identical -- the comment is the one thing
    the patch is supposed to change.

    Returns (frames_before, frames_after, mismatches, error). A file that will not dissect at
    all comes back as an error string rather than an exception.
    """
    try:
        rows_after = run_tshark(pcap)
    except RuntimeError as exc:
        # The patched file no longer dissects at all -- the loudest possible failure, and
        # the one worth reporting rather than raising: the file has already been rewritten
        # in place, so a traceback would leave the operator with a bad artefact and no
        # statement about it.
        return len(rows_before), 0, len(rows_before), str(exc)
    mismatches = 0
    for a, b in zip(rows_before, rows_after):
        for f in TSHARK_FIELDS:
            if f == "frame.comment":
                continue
            if a[f] != b[f]:
                mismatches += 1
                break
    return len(rows_before), len(rows_after), mismatches, None


def write_csv(path, header, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_cell(run_dir, pcap, rf_idx, out_dir, do_reorder=True, do_verify=True):
    """Returns (summary_dict, sessions, events). Output files already exist by now."""
    work = os.path.join(out_dir, os.path.basename(pcap))
    if do_reorder:
        status, out_of_order = reorder(pcap, work)
    else:
        shutil.copyfile(pcap, work)
        status, out_of_order = ("not reordered (--no-reorder)", None)

    rows = run_tshark(work)
    events, frames = build_events(rows)
    anchors, rar_path = load_rar_anchors(run_dir, rf_idx)
    sessions = build_sessions(anchors, events, frames)
    idx_sessions = defaultdict(list)
    for s_ in sessions:
        idx_sessions[s_["rnti"]].append(s_)

    # --- validity check: two independent RAR parsers on the same bytes -----------------
    ws_rar = set()
    for f in frames:
        for c in f["rar_crnti"]:
            ws_rar.add(c)
    ng_rar = {a["rnti"] for a in anchors}
    rar_check = {
        "rar_log_rows": len(anchors),
        "pcap_rar_frames": sum(1 for f in frames if f["src"] == "rar"),
        "wireshark_distinct_crnti": len(ws_rar),
        "rar_log_distinct_crnti": len(ng_rar),
        "identical": sorted(ws_rar) == sorted(ng_rar),
        "only_in_pcap": sorted(ws_rar - ng_rar)[:20],
        "only_in_rar_log": sorted(ng_rar - ws_rar)[:20],
    }

    # --- validity check: the comment ngscope wrote vs what Wireshark dissected ---------
    mismatch = 0
    for f in frames:
        if f["rnti"] is None or not f["diss_rnti"]:
            continue
        if f["rnti"] not in f["diss_rnti"]:
            mismatch += 1

    ev_counts = Counter(e["event"] for e in events)
    out_counts = Counter()
    session_rows = []
    for s in sessions:
        outcome, ev, nas_outcome, nas_ev = resolve_outcome(s)
        out_counts[outcome] += 1
        ms = ""
        if ev is not None and ev["ct"] is not None:
            ms = round((ev["ct"] - s["rar_ct"]) / 1000.0, 3)
        session_rows.append([
            s["rnti"], s["rar_tti"], s["rar_ct"],
            s["session_end_ct"] if s["session_end_ct"] is not None else "",
            s["window_end_ct"], outcome,
            ev["event"] if ev else "", ev["ct"] if ev else "", ms,
            nas_outcome, nas_ev["event"] if nas_ev else "",
            s["n_pdus"], s["n_srb_pdus"], len(s["events"]),
            ";".join(e["event"] for e in s["events"]),
        ])

    # --- sec= verdict per frame, then the in-place splice ------------------------------
    established_ct = {}
    outcome_by_key = {}
    for s_, row in zip(sessions, session_rows):
        outcome_by_key[id(s_)] = row[5]
        if row[5] == "established":
            established_ct[id(s_)] = row[7]

    def verdict_for_frame(f):
        if not is_unicast(f["rnti"]):
            return "n/a"
        s_ = None
        for cand in idx_sessions.get(f["rnti"], []):
            if f["ct"] is None or f["ct"] < cand["rar_ct"]:
                continue
            if cand["session_end_ct"] is not None and f["ct"] >= cand["session_end_ct"]:
                continue
            s_ = cand
        if s_ is None:
            return "unknown"
        outcome = outcome_by_key.get(id(s_), "unknown")
        if outcome == "established":
            boundary = established_ct.get(id(s_))
            # Inclusive: the SecurityModeCommand is itself the last unciphered downlink
            # message; security activates when the UE answers, which is uplink and invisible.
            if boundary in ("", None) or f["ct"] is None:
                return "unknown"
            return "pre" if f["ct"] <= int(boundary) else "post"
        return SEC_FROM_OUTCOME.get(outcome, "unknown")

    verdicts = {f["frame"]: verdict_for_frame(f) for f in frames}
    patched = patch_pcap(work, verdicts)

    verify = None
    if do_verify:
        n_before, n_after, mism, err = verify_patch(work, rows)
        verify = {"frames_before": n_before, "frames_after": n_after,
                  "dissection_mismatches": mism, "error": err,
                  "ok": err is None and n_before == n_after and mism == 0}

    write_csv(os.path.join(run_dir, f"security_events-{rf_idx}.csv"), EVENT_HEADER,
              [[e[k] if e[k] is not None else "" for k in EVENT_HEADER] for e in events])
    write_csv(os.path.join(run_dir, f"security_sessions-{rf_idx}.csv"), SESSION_HEADER,
              session_rows)

    # Two denominators, both reported, neither privileged -- docs/security-measurement.md
    # "Which denominator to use". `raw` is every UE that RACHed and is comparable with the
    # historical figures. `with_traffic` drops sessions for which not one transport block
    # was decoded, which is a statement about the receiver rather than the cell -- but it
    # also drops UEs that RACHed and genuinely did nothing, so it is an upper bound, not a
    # correction. Quoting only one of these would move the headline by 40 points.
    total = sum(out_counts.values())
    with_traffic = total - out_counts.get("no_traffic", 0)
    established = out_counts.get("established", 0)
    summary = {
        "rf_idx": rf_idx,
        "pcap": os.path.basename(pcap),
        "pcap_md5": md5(pcap),
        "frames": len(frames),
        "reorder": {"status": status, "out_of_order": out_of_order},
        "rar_crosscheck": rar_check,
        "comment_vs_dissection_mismatches": mismatch,
        "sec_field_patched": patched,
        "verify": verify,
        "sec_distribution": dict(Counter(verdicts.values())),
        "sessions": dict(out_counts),
        "rate": {
            "established": established,
            "raw_denominator": total,
            "raw_pct": round(100.0 * established / total, 1) if total else 0.0,
            "with_traffic_denominator": with_traffic,
            "with_traffic_pct": round(100.0 * established / with_traffic, 1) if with_traffic else 0.0,
        },
        "events": dict(ev_counts),
        "coverage": {
            "srb_pdus": sum(1 for f in frames
                            if any(t.strip() in ("0x01", "0x02") for t in f["lcid"].split(","))),
            "rlc_reassembled": sum(1 for e in events if e["rlc_segments"] not in ("", None)),
        },
    }
    return summary, sessions, events


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", default=".",
                    help="one timestamped ngscope run directory (default: cwd)")
    ap.add_argument("--out-dir", default=None,
                    help="where the dissected/reordered pcap goes (default <run-dir>/pcap_joined)")
    ap.add_argument("--no-reorder", action="store_true",
                    help="the input is already sorted; skip reordercap")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the second tshark pass that checks the sec= splice left the "
                         "dissection otherwise unchanged. On by default: it costs one extra "
                         "pass and catches pcapng corruption that would otherwise look like "
                         "a clean file with frames quietly missing.")
    ap.add_argument("--compare", action="store_true",
                    help="diff the outcome against the retired in-process parser's "
                         "security_log-<rf>.csv, if present. This is the only moment two "
                         "independent parsers can be compared on the same bytes.")
    args = ap.parse_args()

    run_dir = os.path.abspath(args.run_dir)
    if not os.path.isdir(run_dir):
        sys.exit(f"error: {run_dir} is not a directory")

    caps = sorted(glob.glob(os.path.join(run_dir, "mac-*.pcapng")))
    if not caps:
        sys.exit(f"error: no mac-*.pcapng in {run_dir}\n"
                 "This tool reads the MAC capture; the run needs pcap_mac = true.")

    out_dir = args.out_dir or os.path.join(run_dir, "pcap_joined")
    os.makedirs(out_dir, exist_ok=True)

    # Step 0: the files exist, with headers, before anything that can fail. An empty file
    # then means "measured, found nothing" -- the positive result for catcher detection --
    # and an absent one means the run was never analysed.
    cells = []
    for cap in caps:
        m = re.search(r"mac-(\d+)\.pcapng$", cap)
        rf_idx = int(m.group(1)) if m else 0
        cells.append((cap, rf_idx))
        write_csv(os.path.join(run_dir, f"security_events-{rf_idx}.csv"), EVENT_HEADER, [])
        write_csv(os.path.join(run_dir, f"security_sessions-{rf_idx}.csv"), SESSION_HEADER, [])

    tsv = subprocess.run(["tshark", "--version"], capture_output=True, text=True)
    summary = {
        "tool": "security_scan.py",
        "tshark_version": (tsv.stdout or "").splitlines()[0] if tsv.stdout else "unknown",
        "fields_queried": TSHARK_FIELDS,
        "run_dir": run_dir,
        "cells": [],
    }

    failed = []
    for cap, rf_idx in cells:
        try:
            cell, sessions, events = scan_cell(run_dir, cap, rf_idx, out_dir,
                                               do_reorder=not args.no_reorder,
                                               do_verify=not args.no_verify)
        except (RuntimeError, ValueError, struct.error) as exc:
            # A capture that will not dissect is a bad input, not a bug here. Report it and
            # keep going: with several cells, one damaged file should not cost the others.
            # The header-only output files written above stay, which correctly reads as
            # "scanned, found nothing" -- so say plainly that this one was not scanned.
            print(f"### {os.path.basename(cap)}  (rf {rf_idx})")
            print(f"  ERROR: could not dissect this capture -- {exc}")
            print("  Its security_events / security_sessions files are empty because it was "
                  "NOT scanned,")
            print("  which is not the same as having been scanned and found nothing.")
            failed.append(f"rf {rf_idx}: {os.path.basename(cap)} did not dissect")
            continue
        summary["cells"].append(cell)

        print(f"### {os.path.basename(cap)}  (rf {rf_idx})")
        print(f"  frames            : {cell['frames']:,}   {cell['reorder']['status']}")
        rc = cell["rar_crosscheck"]
        print(f"  RAR cross-check   : rar_log {rc['rar_log_distinct_crnti']} vs "
              f"wireshark {rc['wireshark_distinct_crnti']}  identical={rc['identical']}")
        print(f"  comment vs dissect: {cell['comment_vs_dissection_mismatches']} mismatches")
        v = cell.get("verify")
        if v is None:
            print("  splice verify     : SKIPPED (--no-verify)")
        elif v["ok"]:
            print(f"  splice verify     : OK -- {v['frames_after']} frames re-dissected "
                  f"identically apart from the comment")
        elif v.get("error"):
            print(f"  splice verify     : FAILED -- the patched file no longer dissects: "
                  f"{v['error']}")
        else:
            print(f"  splice verify     : FAILED -- frames {v['frames_before']} -> "
                  f"{v['frames_after']}, {v['dissection_mismatches']} frames differ outside "
                  f"the comment")
        print(f"  sessions          : " +
              ", ".join(f"{k}={v}" for k, v in sorted(cell["sessions"].items())))
        r = cell["rate"]
        print(f"  rate              : {r['established']}/{r['raw_denominator']} = "
              f"{r['raw_pct']}% of all RACHing UEs")
        print(f"                      {r['established']}/{r['with_traffic_denominator']} = "
              f"{r['with_traffic_pct']}% of those we decoded any traffic for")
        if cell["events"]:
            print(f"  events            : " +
                  ", ".join(f"{k}={v}" for k, v in sorted(cell["events"].items())))
        else:
            print("  events            : none. The run measured this and found nothing --")
            print("                      check the session count and n_pdus before reading")
            print("                      that as a cell where no UE reached security.")

        if args.compare:
            compare_with_old(run_dir, rf_idx, sessions)

    with open(os.path.join(run_dir, "security_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nwrote security_events-*.csv, security_sessions-*.csv, security_summary.json")

    # A failed splice means the shipped pcap is damaged, and a failed RAR cross-check means
    # the denominator is wrong -- both make every number above untrustworthy. Exit non-zero
    # so run.sh and the GUI cannot report them as a clean run.
    bad = list(failed)
    for c in summary["cells"]:
        v = c.get("verify")
        if v is not None and not v["ok"]:
            bad.append(f"rf {c['rf_idx']}: sec= splice verification failed")
        if not c["rar_crosscheck"]["identical"]:
            bad.append(f"rf {c['rf_idx']}: RAR cross-check disagrees -- the denominator is "
                       f"not trustworthy")
    if bad:
        print("\nERROR: " + "\n       ".join(bad), file=sys.stderr)
        return 1
    return 0


def compare_with_old(run_dir, rf_idx, sessions):
    """The Stage 0 gate: the new detector must be a superset of the retired parser."""
    old_path = os.path.join(run_dir, f"security_log-{rf_idx}.csv")
    if not os.path.isfile(old_path):
        print("  compare           : no security_log to compare against")
        return
    old = set()
    with open(old_path) as fh:
        for row in csv.DictReader(fh):
            try:
                old.add((int(row["rnti"]), int(row["rar_tti"])))
            except (KeyError, ValueError):
                continue
    new = {(s["rnti"], s["rar_tti"]) for s in sessions
           if resolve_outcome(s)[0] == "established"}
    missing = sorted(old - new)
    print(f"  compare           : old parser {len(old)}, new {len(new)}, "
          f"new-only {len(new - old)}, MISSING {len(missing)}")
    if missing:
        print(f"    BLOCKER -- the new detector lost: {missing[:10]}")


if __name__ == "__main__":
    sys.exit(main() or 0)
