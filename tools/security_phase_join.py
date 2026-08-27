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
    -f both

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
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

# Not UE identities, so they have no security context. Matches ngscope_sec_is_unicast().
BROADCAST_RNTIS = {0, 0xFFFF, 0xFFFE}


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
    """rnti -> sorted list of (rar_us, smc_us, rar_tti, smc_tti, rf_idx).

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
                by_rnti[int(row["rnti"])].append((
                    int(row["rar_timestamp"]),
                    int(row["smc_timestamp"]),
                    int(row["rar_tti"]),
                    int(row["smc_tti"]),
                    rf_idx,
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
    if rnti in BROADCAST_RNTIS:
        return "n/a", None
    sessions = boundaries.get(rnti)
    if not sessions:
        return "unknown", None
    session = session_for(sessions, ts_us)
    if session is None:
        return "unknown", None
    return ("pre" if ts_us <= session[1] else "post"), session


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


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", default=".",
                    help="one timestamped ngscope run directory (default: the "
                         "current directory)")
    ap.add_argument("-o", "--out",
                    help="csv: output file (default <run-dir>/security_phase.csv). "
                         "dcilog: output directory (default <run-dir>/dci_output_joined)")
    ap.add_argument("-f", "--format", choices=("csv", "dcilog", "both"), default="csv",
                    help="csv adds derived columns; dcilog rewrites the .dciLog files in "
                         "place-compatible form, same keys and order, with only "
                         "security_phase replaced, so existing readers work unchanged")
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
            msg.append("Was the run made with mark_security_phase = true?")
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
    want_dcilog = args.format in ("dcilog", "both") and not args.summary_only

    for path in dci_files:
        direction = "ul" if re.search(r"_ul_", os.path.basename(path)) else "dl"
        if want_dcilog:
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
            if want_dcilog:
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
                    "security_phase": phase,
                    "security_phase_in_stream": streamed,
                    "rar_tti": session[2] if session else "",
                    "smc_tti": session[3] if session else "",
                    "ms_since_rar": round((ts - session[0]) / 1000.0, 3) if session else "",
                    "ms_to_boundary": round((ts - session[1]) / 1000.0, 3) if session else "",
                    "prb": rec.get("prb", ""),
                    "harq": rec.get("harq", ""),
                    "tbs": rec.get("TB1_tbs", ""),
                })

    total = sum(counts.values())
    print(f"run            : {run_dir}")
    print(f"boundaries     : {sum(len(v) for v in boundaries.values())} "
          f"over {len(boundaries)} RNTIs, from {len(sec_files)} security_log file(s)")
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

    if args.format in ("csv", "both"):
        out = (args.out if args.format == "csv" and args.out
               else os.path.join(run_dir, "security_phase.csv"))
        with open(out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["rnti"])
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {len(rows):,} rows to {out}")

    if args.format in ("dcilog", "both"):
        out_dir = (args.out if args.format == "dcilog" and args.out
                   else os.path.join(run_dir, "dci_output_joined"))
        os.makedirs(out_dir, exist_ok=True)
        # New directory rather than overwriting dci_output/: the originals are what ngscope
        # actually observed, and this is a derived view of them.
        for src, records in rewritten.items():
            dst = os.path.join(out_dir, os.path.basename(src))
            write_dcilog(dst, records)
            print(f"wrote {len(records):,} records to {dst}")


if __name__ == "__main__":
    main()
