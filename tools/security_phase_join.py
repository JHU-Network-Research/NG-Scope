#!/usr/bin/env python3
"""Place every DCI relative to its UE's security context, by joining an NG-Scope run's
security_log against its .dciLog files.

Why this exists
---------------
With mark_security_phase on, ngscope stamps each DCI with a "security_phase" as the
subframe is decoded. That label is honest but necessarily incomplete for "pre": the
boundary is the SecurityModeCommand, which arrives *after* the DCIs it bounds, so a DCI
that precedes its own boundary cannot be recognised at the time it is written. On a band 12
capture the in-stream label proved 52 of 1,089 pre-security DCIs -- about 5%.

security_log-<rf>.csv records the boundary itself once known. Joining it back on rnti and
comparing timestamps places every DCI exactly, which is what this script does. Treat its
output as authoritative and the per-DCI label as a live approximation.

Output
------
    -f csv     (default) security_phase.csv: every DCI with the joined phase, plus
               ms_since_rar / ms_to_boundary and the in-stream label for comparison
    -f dcilog  dci_output_joined/: the .dciLog files rewritten with only security_phase
               replaced -- same keys, same order, same layout, same pre|post|unknown value
               domain -- so anything that already reads a .dciLog reads these unchanged
    -f pcapng  pcap_joined/: mac-<rf_idx>.pcapng rewritten with only the sec= field of each
               packet comment replaced. ngscope pads that field to a fixed width, so this
               is a byte-for-byte in-place patch: no block length, option length or padding
               changes, and everything else in the file is copied verbatim.

               The result is then passed through reordercap, because ngscope writes records
               in decode-completion order and Wireshark reassembles RLC order-dependently --
               an unsorted file loses RRC silently. --no-reorder skips that and leaves the
               byte-identical patch, which is how the patch's inertness is regression-tested
    -f both     csv + dcilog
    -f all      csv + dcilog + pcapng

Usage
-----
    tools/security_phase_join.py [run-dir] [-f csv|dcilog|both] [-o PATH] [--summary-only]

run-dir defaults to the current directory, so from inside a run you can just run the
script with no arguments.

<run-dir> is one timestamped run directory, e.g.
    ~/ngscope_out/2026_08_17_15_27_10/
or, for a sweep, .../earfcn-5035/2026_08_17_15_27_10/
"""

import argparse
import bisect
import struct
import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict

# Not UE identities, so they have no security context. Matches ngscope_sec_is_unicast():
# RNTI 0, SI-RNTI, P-RNTI, and the RA-RNTI range, which addresses a random-access occasion
# rather than a UE. Reporting those as "n/a" rather than "unknown" keeps the two apart --
# "unknown" means a UE this join could not place, which is the number that bounds how much
# of the capture is unaccounted for.
BROADCAST_RNTIS = {0, 0xFFFF, 0xFFFE}
RARNTI_RANGE = range(1, 0x000B)   # SRSRAN_RARNTI_START .. SRSRAN_RARNTI_END


def is_unicast(rnti):
    return rnti not in BROADCAST_RNTIS and rnti not in RARNTI_RANGE


def load_dcilog(path):
    """Parse one .dciLog. It is a JSON array kept append-friendly, so a run that was cut
    short can lack its closing bracket; fall back to per-record recovery."""
    with open(path, errors="replace") as fh:
        text = fh.read().strip()
    if not text:
        return []
    if not text.endswith("]"):
        text += "]"
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(m.group(0)) for m in re.finditer(r"\{[^{}]*\}", text)]


def load_boundaries(run_dir):
    """rnti -> sorted list of (rar_us, smc_us, rar_tti, smc_tti, rf_idx, rar_ct, smc_ct).

    rar_ct/smc_ct are the radio-domain collection times of the same two instants. The
    matching still uses the wall-clock values, because those are what the .dciLog and pcapng
    records carry, but every elapsed time reported below is computed from the collection
    times: wall clock advances at decode speed, so in a replay it stretches or compresses
    real intervals and any rate plotted against it is wrong.

    A list rather than a single value because an RNTI can be handed out again later in a
    long capture; ngscope re-arms on each RAR, so the same identity can carry several
    sessions with different boundaries.
    """
    by_rnti = defaultdict(list)
    files = sorted(glob.glob(os.path.join(run_dir, "security_log-*.csv")))
    if not files:
        return by_rnti, files

    for path in files:
        m = re.search(r"security_log-(\d+)\.csv$", path)
        rf_idx = int(m.group(1)) if m else 0
        with open(path) as fh:
            for row in csv.DictReader(fh):
                # Older runs have no collection_time columns; fall back to the wall clock so
                # the tool still works on them, at the cost of the distortion above.
                by_rnti[int(row["rnti"])].append((
                    int(row["rar_timestamp"]),
                    int(row["smc_timestamp"]),
                    int(row["rar_tti"]),
                    int(row["smc_tti"]),
                    rf_idx,
                    int(row.get("rar_collection_time") or row["rar_timestamp"]),
                    int(row.get("smc_collection_time") or row["smc_timestamp"]),
                ))
    for sessions in by_rnti.values():
        sessions.sort()
    return by_rnti, files


def session_for(sessions, ts_us):
    """The session a DCI at ts_us belongs to: the latest one whose RAR precedes it.

    None when the DCI predates every RAR for this RNTI -- it belongs to an earlier use of
    the identity that was never anchored, so it cannot be placed.
    """
    idx = bisect.bisect_right([s[0] for s in sessions], ts_us) - 1
    return sessions[idx] if idx >= 0 else None


def phase_for(rnti, ts_us, boundaries):
    """(phase, session). 'pre' up to and including the boundary: the SecurityModeCommand is
    itself the last unciphered downlink message, and security only activates once the UE
    answers with SecurityModeComplete."""
    if not is_unicast(rnti):
        return "n/a", None
    sessions = boundaries.get(rnti)
    if not sessions:
        return "unknown", None
    session = session_for(sessions, ts_us)
    if session is None:
        return "unknown", None
    return ("pre" if ts_us <= session[1] else "post"), session


# pcapng block and option codes, PCAP Next Generation Dump File Format section 4.
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_EPB = 0x00000006
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
OPT_ENDOFOPT = 0
OPT_COMMENT = 1

# "sec=" plus a field ngscope pads to exactly this width. That padding is what makes this an
# in-place byte patch: the replacement is the same length as the original, so no option
# length, no block length and no padding has to be recomputed, and a bug here cannot
# corrupt the block structure.
SEC_FIELD_WIDTH = 7

_SEC_RE = re.compile(rb"sec=([a-z/ ]{%d})" % SEC_FIELD_WIDTH)
_RNTI_RE = re.compile(rb"rnti=0x([0-9a-fA-F]{1,4})")


def _patch_comment(comment, boundaries, ts_us, stats):
    """Rewrite the sec= field of one packet comment. Returns the new bytes, same length.

    The RNTI is read from the comment rather than by dissecting the MAC PDU, which keeps
    this script free of any LTE knowledge -- it stays a join on (rnti, timestamp), exactly
    as the .dciLog path is.
    """
    m_sec = _SEC_RE.search(comment)
    if not m_sec:
        stats["no_sec_field"] += 1
        return comment
    m_rnti = _RNTI_RE.search(comment)
    if not m_rnti:
        stats["no_rnti_field"] += 1
        return comment

    rnti = int(m_rnti.group(1), 16)
    phase, _ = phase_for(rnti, ts_us, boundaries)
    stats[phase] += 1
    if b"src=blind" in comment:
        stats["blind"] += 1

    was = m_sec.group(1).strip().decode()
    if was in ("pre", "post") and phase in ("pre", "post") and was != phase:
        stats["disagree"] += 1

    new = phase.encode().ljust(SEC_FIELD_WIDTH)
    if len(new) != SEC_FIELD_WIDTH:
        stats["too_long"] += 1
        return comment
    return comment[:m_sec.start(1)] + new + comment[m_sec.end(1):]


def _patch_epb(body, endian, boundaries, stats):
    """Patch the comment option of one Enhanced Packet Block body, in place.

    body excludes the 8-byte block header but includes the trailing block-total-length.
    Layout: interface id, timestamp high, timestamp low, captured length, original length,
    packet data padded to 4, then options.
    """
    if len(body) < 24:
        return body
    _if_id, ts_hi, ts_lo, caplen, _origlen = struct.unpack(endian + "IIIII", body[:20])
    ts_us = (ts_hi << 32) | ts_lo

    off = 20 + ((caplen + 3) & ~3)
    end = len(body) - 4          # trailing block total length
    out = bytearray(body)
    while off + 4 <= end:
        code, length = struct.unpack(endian + "HH", body[off:off + 4])
        if code == OPT_ENDOFOPT:
            break
        val_start = off + 4
        val_end = val_start + length
        if val_end > end:
            break
        if code == OPT_COMMENT:
            patched = _patch_comment(bytes(body[val_start:val_end]), boundaries, ts_us, stats)
            if len(patched) == length:
                out[val_start:val_end] = patched
        off = val_start + ((length + 3) & ~3)
    return bytes(out)


def rewrite_pcapng(src, dst, boundaries, stats):
    """Copy src to dst, rewriting the sec= field of every packet comment.

    Streamed a block at a time rather than loading the file, since a busy cell can produce
    a capture far larger than memory. Endianness is taken from the section header's
    byte-order magic and applied to every block after it, as the format requires.
    """
    with open(src, "rb") as fh, open(dst, "wb") as out:
        head = fh.read(12)
        if len(head) < 12 or struct.unpack("<I", head[:4])[0] != PCAPNG_SHB:
            raise ValueError(f"{src}: not a pcapng file (no section header block)")
        if struct.unpack("<I", head[8:12])[0] == PCAPNG_BYTE_ORDER_MAGIC:
            endian = "<"
        elif struct.unpack(">I", head[8:12])[0] == PCAPNG_BYTE_ORDER_MAGIC:
            endian = ">"
        else:
            raise ValueError(f"{src}: bad byte-order magic in section header")

        total = struct.unpack(endian + "I", head[4:8])[0]
        if total < 12:
            raise ValueError(f"{src}: implausible section header length {total}")
        out.write(head)
        out.write(fh.read(total - 12))

        while True:
            hdr = fh.read(8)
            if len(hdr) < 8:
                break            # clean end, or a truncated trailing block
            btype, total = struct.unpack(endian + "II", hdr)
            if total < 12:
                raise ValueError(f"{src}: implausible block length {total} for type {btype:#x}")
            body = fh.read(total - 8)
            if len(body) < total - 8:
                break            # truncated final block: stop rather than emit a bad one
            if btype == PCAPNG_EPB:
                body = _patch_epb(body, endian, boundaries, stats)
                stats["packets"] += 1
            out.write(hdr)
            out.write(body)


def _ms_since(rec, ts_us, session, ct_idx, us_idx):
    """Milliseconds from a boundary to this record, in capture time when both ends have it.

    Falls back to the wall clock only when the record or the boundary predates the
    collection_time columns, so a mixed or older run still produces a number rather than a
    blank -- but a run made with current ngscope is measured in the radio domain throughout.
    """
    if session is None:
        return ""
    ct = rec.get("collection_time")
    if ct not in (None, ""):
        try:
            return round((int(ct) - session[ct_idx]) / 1000.0, 3)
        except (TypeError, ValueError):
            pass
    return round((ts_us - session[us_idx]) / 1000.0, 3)


def write_dcilog(path, records):
    """Reproduce dci_log.c's layout byte-for-byte: "[\n", one record per "{...}" with a
    field per line, records separated by "},{", closed with "}]".

    The records keep their original key order and their string-typed values, so the only
    difference from the input is the security_phase value. Anything that reads a .dciLog
    today reads this unchanged.
    """
    with open(path, "w") as fh:
        fh.write("[\n")
        for i, rec in enumerate(records):
            if i:
                fh.write(",{\n")
            else:
                fh.write("{\n")
            items = list(rec.items())
            for j, (k, v) in enumerate(items):
                comma = "," if j < len(items) - 1 else ""
                fh.write(f'"{k}": "{v}"{comma}\n')
            fh.write("}")
        fh.write("]")


def reorder_pcapng(path):
    """Sort a rewritten pcapng into timestamp order, in place, via reordercap.

    ngscope decodes subframes across several threads and writes each record as it
    completes, so the file is in decode-completion order, not TTI order. Wireshark's
    rlc-lte and pdcp-lte dissectors reassemble statefully and order-dependently, so an
    unsorted file yields spurious reassembly failures and silently missing RRC -- which is
    the same class of quiet undercount this whole tool exists to avoid.

    Not reimplemented here on purpose: reordercap ships with Wireshark and already handles
    the pcapng block bookkeeping correctly. If it is missing, say so and leave the file
    alone rather than half-doing it.

    Returns a short status string for the caller to print.
    """
    exe = shutil.which("reordercap")
    if exe is None:
        return ("reordercap not found (install wireshark-common); left in decode order -- "
                "sort it before any RLC/PDCP analysis")

    tmp = path + ".reorder.tmp"
    try:
        proc = subprocess.run([exe, path, tmp], capture_output=True, text=True)
    except OSError as exc:
        return f"reordercap could not run ({exc}); left in decode order"

    if proc.returncode != 0 or not os.path.exists(tmp):
        if os.path.exists(tmp):
            os.unlink(tmp)
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return f"reordercap failed ({detail[-1] if detail else proc.returncode}); left in decode order"

    # reordercap reports "N frames, M out of order" on stdout; worth surfacing, because a
    # large M is exactly why the unsorted file would have dissected badly.
    note = (proc.stdout or "").strip().splitlines()
    os.replace(tmp, path)
    return "reordered" + (f" ({note[-1]})" if note else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", default=".",
                    help="one timestamped ngscope run directory (default: the "
                         "current directory)")
    ap.add_argument("-o", "--out",
                    help="csv: output file (default <run-dir>/security_phase.csv). "
                         "dcilog: output directory (default <run-dir>/dci_output_joined). "
                         "pcapng: output directory (default <run-dir>/pcap_joined)")
    ap.add_argument("-f", "--format",
                    choices=("csv", "dcilog", "pcapng", "both", "all"), default="dcilog",
                    help="dcilog (default) rewrites the DL and UL .dciLog files in "
                         "place-compatible form -- same keys, order and layout, only "
                         "security_phase replaced -- so existing readers work unchanged. "
                         "csv writes a flat table with extra derived columns instead. "
                         "pcapng rewrites the sec= field of every packet comment in "
                         "mac-<rf_idx>.pcapng. both = csv+dcilog (unchanged meaning); "
                         "all = csv+dcilog+pcapng.")
    ap.add_argument("--no-reorder", action="store_true",
                    help="leave the rewritten pcapng in decode-completion order. The rewrite "
                         "is a byte-for-byte patch of the sec= field, so with this flag the "
                         "output is the same size as the input and dissects identically -- "
                         "which is how that inertness is regression-tested. Without it the "
                         "file is passed through reordercap, because Wireshark's RLC "
                         "reassembly is order-dependent and unsorted records lose RRC.")
    ap.add_argument("--summary-only", action="store_true", help="print the summary, write nothing")
    args = ap.parse_args()

    run_dir = os.path.abspath(args.run_dir)
    if not os.path.isdir(run_dir):
        sys.exit(f"error: {run_dir} is not a directory")

    boundaries, sec_files = load_boundaries(run_dir)
    if not sec_files:
        # Easy to be one level up: an output directory holds timestamped run directories,
        # and a sweep nests them another level under earfcn-<n>/. Point at them rather than
        # just refusing.
        candidates = sorted(
            os.path.dirname(p) for p in
            glob.glob(os.path.join(run_dir, "*", "security_log-*.csv")) +
            glob.glob(os.path.join(run_dir, "*", "*", "security_log-*.csv"))
        )
        msg = ["error: no security_log-*.csv in " + run_dir]
        if candidates:
            msg.append("")
            one = len(candidates) == 1
            msg.append(f"{len(candidates)} run director{'y' if one else 'ies'} below this one "
                       f"{'does' if one else 'do'} have one:")
            msg += [f"    {os.path.relpath(c, run_dir)}" for c in candidates[:10]]
            if len(candidates) > 10:
                msg.append(f"    ... and {len(candidates) - 10} more")
        else:
            # Deliberately not asserting the cause. Since ngscope creates this file up front
            # when mark_security_phase is on, an absent one means the setting was off, the
            # run predates that change, or this is not a run directory -- and guessing wrong
            # sends the reader after the wrong thing. Note what it does NOT mean, because
            # that is the reading that matters.
            msg.append("The file is created at startup when mark_security_phase = true, so an")
            msg.append("absent one means the run did not measure security -- it does not mean")
            msg.append("no UE reached it. Either the setting was off, or the run predates that")
            msg.append("behaviour, or this is not a run directory.")
        sys.exit("\n".join(msg))

    dci_files = sorted(glob.glob(os.path.join(run_dir, "dci_output", "*.dciLog")))
    if not dci_files:
        sys.exit(f"error: no .dciLog files under {os.path.join(run_dir, 'dci_output')}")

    rf_indices = {s[4] for sessions in boundaries.values() for s in sessions}
    if len(rf_indices) > 1:
        # .dciLog files are named by frequency, not rf_idx, so records cannot be attributed
        # to a cell from the filename alone. Say so rather than guess.
        print(f"warning: {len(rf_indices)} cells present; boundaries are merged across them. "
              "An RNTI reused by two cells in one run could be mis-joined.", file=sys.stderr)

    rows = []
    counts = Counter()
    disagree = 0
    per_rnti = defaultdict(Counter)
    rewritten = {}
    want_dcilog = args.format in ("dcilog", "both", "all") and not args.summary_only

    for path in dci_files:
        name = os.path.basename(path)
        if name.startswith("dci_raw_log_dl_"):
            direction = "dl"
        elif name.startswith("dci_raw_log_ul_"):
            direction = "ul"
        else:
            direction = "phich"   # phich_log_ul_freq_*.dciLog -- also matches "_ul_"
        if want_dcilog and direction in ("dl", "ul"):
            rewritten[path] = []
        for rec in load_dcilog(path):
            try:
                rnti = int(rec["rnti"])
                ts = int(rec["timestamp_us"])
                tti = int(rec["tti"])
            except (KeyError, ValueError):
                continue

            phase, session = phase_for(rnti, ts, boundaries)
            counts[phase] += 1
            if phase in ("pre", "post"):
                per_rnti[rnti][phase] += 1

            streamed = rec.get("security_phase", "")
            if want_dcilog and direction in ("dl", "ul"):
                # ngscope only ever writes pre|post|unknown, so collapse the CSV's richer
                # "n/a" back to "unknown" here. A drop-in replacement must not introduce a
                # fourth value that existing readers have never had to handle; the
                # distinction stays available in the CSV output.
                dcilog_phase = "unknown" if phase == "n/a" else phase
                # Mutating the parsed record preserves key order and the string values, so
                # the field lands exactly where ngscope put it rather than appended.
                if "security_phase" in rec:
                    rec["security_phase"] = dcilog_phase
                else:
                    rec = {"tti": rec.get("tti"), "rnti": rec.get("rnti"),
                           "security_phase": dcilog_phase,
                           **{k: v for k, v in rec.items() if k not in ("tti", "rnti")}}
                rewritten[path].append(rec)
            # The live label may be unknown where this join is decisive, but it must never
            # say the opposite. If it does, the two disagree about the same instant.
            if streamed in ("pre", "post") and phase in ("pre", "post") and streamed != phase:
                disagree += 1

            if not args.summary_only:
                rows.append({
                    "direction": direction,
                    "tti": tti,
                    "rnti": rnti,
                    "timestamp_us": ts,
                    "collection_time": rec.get("collection_time", ""),
                    "security_phase": phase,
                    "security_phase_in_stream": streamed,
                    "rar_tti": session[2] if session else "",
                    "smc_tti": session[3] if session else "",
                    "rar_collection_time": session[5] if session else "",
                    "smc_collection_time": session[6] if session else "",
                    # Capture time where the record carries it, so these are real elapsed
                    # milliseconds over the air rather than decode-clock milliseconds.
                    "ms_since_rar": _ms_since(rec, ts, session, 5, 0),
                    "ms_to_boundary": _ms_since(rec, ts, session, 6, 1),
                    "prb": rec.get("prb", ""),
                    "harq": rec.get("harq", ""),
                    "tbs": rec.get("TB1_tbs", ""),
                })

    total = sum(counts.values())
    print(f"run            : {run_dir}")
    nof_boundaries = sum(len(v) for v in boundaries.values())
    print(f"boundaries     : {nof_boundaries} "
          f"over {len(boundaries)} RNTIs, from {len(sec_files)} security_log file(s)")
    if nof_boundaries == 0:
        # An empty-but-present security_log is a measurement, not a failure: the run tracked
        # UEs and none of them reached security. For IMSI-catcher detection that is the
        # result of interest, so it gets said out loud rather than left to be inferred from
        # a table of zeroes. Every record below is correctly labelled "unknown" -- the
        # boundary was never observed, which is not the same as "there was none".
        print("                 the run measured this and found none. Every record below is "
              "'unknown';")
        print("                 check the RAR count and the teardown coverage lines before "
              "reading that as a cell with no security.")
    print(f"dci records    : {total:,} from {len(dci_files)} .dciLog file(s)")
    print()
    for phase in ("pre", "post", "unknown", "n/a"):
        n = counts.get(phase, 0)
        print(f"  {phase:<8} {n:>10,}  {100 * n / total if total else 0:5.1f}%")
    both = sum(1 for c in per_rnti.values() if c["pre"] and c["post"])
    print(f"\n  {len(per_rnti):,} RNTIs placed; {both:,} of them span the boundary")
    if disagree:
        print(f"\n  WARNING: {disagree:,} records where the in-stream label contradicts this "
              "join. That should not happen -- please report it.")

    if args.summary_only:
        return

    if args.format in ("csv", "both", "all"):
        out = (args.out if args.format == "csv" and args.out
               else os.path.join(run_dir, "security_phase.csv"))
        with open(out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["rnti"])
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {len(rows):,} rows to {out}")

    if args.format in ("dcilog", "both", "all"):
        out_dir = (args.out if args.format == "dcilog" and args.out
                   else os.path.join(run_dir, "dci_output_joined"))
        os.makedirs(out_dir, exist_ok=True)
        # New directory rather than overwriting dci_output/: the originals are what ngscope
        # actually observed, and this is a derived view of them.
        for src, records in rewritten.items():
            dst = os.path.join(out_dir, os.path.basename(src))
            write_dcilog(dst, records)
            print(f"wrote {len(records):,} records to {dst}")

        # Mirror anything not rewritten so the directory is a complete stand-in for
        # dci_output/. PHICH records carry no security_phase, and inventing one would
        # change a format this tool does not own.
        for src in dci_files:
            if src in rewritten:
                continue
            dst = os.path.join(out_dir, os.path.basename(src))
            shutil.copyfile(src, dst)
            print(f"copied {os.path.basename(src)} unchanged (no security_phase field)")

    if args.format in ("pcapng", "all"):
        caps = sorted(glob.glob(os.path.join(run_dir, "mac-*.pcapng")))
        if not caps:
            print("\nno mac-*.pcapng in this run (was it made with pcap_mac = true?)")
        else:
            out_dir = (args.out if args.format == "pcapng" and args.out
                       else os.path.join(run_dir, "pcap_joined"))
            os.makedirs(out_dir, exist_ok=True)
            pstats = Counter()
            print()
            for src in caps:
                dst = os.path.join(out_dir, os.path.basename(src))
                try:
                    rewrite_pcapng(src, dst, boundaries, pstats)
                except (ValueError, struct.error) as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    continue
                status = ("left in decode-completion order (--no-reorder)"
                          if args.no_reorder else reorder_pcapng(dst))
                print(f"wrote {os.path.basename(dst)} to {out_dir} -- {status}")

            placed = pstats["pre"] + pstats["post"]
            print(f"\npcapng packets : {pstats['packets']:,}")
            for phase in ("pre", "post", "unknown", "n/a"):
                n = pstats.get(phase, 0)
                pct = 100 * n / pstats["packets"] if pstats["packets"] else 0
                print(f"  {phase:<8} {n:>10,}  {pct:5.1f}%")
            if pstats["blind"]:
                # These carry an RNTI recovered from a descrambled PDCCH CRC rather than
                # checked against a known one, so the identity may be fictional -- and any
                # phase joined onto it inherits that. Counted separately so a reader does
                # not treat them as equally attributed.
                print(f"  {'blind':<8} {pstats['blind']:>10,}         "
                      f"(rnti unverified; joined phase inherits that)")
            if placed:
                print(f"\n  {placed:,} packets placed by the join")
            for key, note in (("no_sec_field", "no sec= field"),
                              ("no_rnti_field", "no rnti= field"),
                              ("too_long", "phase longer than the padded field")):
                if pstats[key]:
                    print(f"  WARNING: {pstats[key]:,} comments skipped -- {note}")
            if pstats["disagree"]:
                print(f"  WARNING: {pstats['disagree']:,} packets where the in-stream label "
                      "contradicts this join. That should not happen -- please report it.")


if __name__ == "__main__":
    main()
