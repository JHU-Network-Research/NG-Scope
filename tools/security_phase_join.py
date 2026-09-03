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


def load_sessions(run_dir):
    """rnti -> sessions, from security_sessions-<rf>.csv written by tools/security_scan.py.

    That file replaced security_log-<rf>.csv when detection moved offline. It carries one row
    per RAR-anchored session rather than one per boundary, so a UE that reached no boundary
    still has a row -- which is what lets "no evidence" be a value rather than a missing
    record.

    Keyed on collection_time throughout: the radio clock. The old join matched on
    timestamp_us, the host wall clock, which in a replay advances at decode speed -- measured
    overstating RAR-to-SMC by 26.5 ms at the median and up to 1046 ms.
    """
    by_rnti = defaultdict(list)
    files = sorted(glob.glob(os.path.join(run_dir, "security_sessions-*.csv")))
    if not files:
        return by_rnti, files
    for path in files:
        m = re.search(r"security_sessions-(\d+)\.csv$", path)
        rf_idx = int(m.group(1)) if m else 0
        with open(path) as fh:
            for row in csv.DictReader(fh):
                try:
                    by_rnti[int(row["rnti"])].append({
                        "rar_ct": int(row["rar_ct"]),
                        "end_ct": int(row["session_end_ct"]) if row["session_end_ct"] else None,
                        "outcome": row["outcome"],
                        "outcome_ct": int(row["outcome_ct"]) if row["outcome_ct"] else None,
                        "rar_tti": int(row["rar_tti"]),
                        "rf_idx": rf_idx,
                    })
                except (KeyError, ValueError):
                    continue
    for v in by_rnti.values():
        v.sort(key=lambda x: x["rar_ct"])
    return by_rnti, files


def load_identity_events(run_dir):
    """(rnti, ct) -> exposure label, from security_events-<rf>.csv.

    Marks the individual DCI that carried an identity-revealing message, which is a
    different question from the per-UE column in security_sessions: this says "this grant
    is the one", so a reader can go from a rate straight to the subframe.

    Only the strongest exposure is kept per (rnti, ct) -- one transport block can hold
    several messages, and a summary field must not depend on emission order.
    """
    rank = {"imsi_in_clear": 4, "imsi_requested": 3, "imeisv_requested": 2,
            "imei_requested": 1, "tmsi_requested": 0}
    signal_to_label = {
        "identity_imsi_clear": "imsi_in_clear",
        "identity_imsi":       "imsi_requested",
        "identity_imei":       "imei_requested",
        "identity_tmsi":       "tmsi_requested",
    }
    by_key = {}
    for path in sorted(glob.glob(os.path.join(run_dir, "security_events-*.csv"))):
        with open(path) as fh:
            for row in csv.DictReader(fh):
                label = signal_to_label.get(row.get("signal", ""))
                if label is None:
                    continue
                try:
                    key = (int(row["rnti"]), int(row["ct"]))
                except (KeyError, ValueError, TypeError):
                    continue
                cur = by_key.get(key)
                if cur is None or rank[label] > rank[cur]:
                    by_key[key] = label
    return by_key


# The seven values a record can carry. `none` and `unknown` are different claims: `none`
# means the UE was watched, with decoded traffic, and showed no security evidence -- the
# signal an IMSI-catcher produces -- while `unknown` means it could not be watched.
VERDICT_FROM_OUTCOME = {
    "reused": "reused",
    "refused": "noctx",
    "released": "none",
    "none": "none",
    "in_progress": "unknown",
    "no_traffic": "unknown",
}


def session_for(sessions, ct):
    best = None
    for s in sessions:
        if ct is None or ct < s["rar_ct"]:
            continue
        if s["end_ct"] is not None and ct >= s["end_ct"]:
            continue
        best = s
    return best


def verdict_for(rnti, ct, sessions_by_rnti):
    """(verdict, session). 'pre' up to and including the boundary: the SecurityModeCommand
    is itself the last unciphered downlink message, and security only activates once the UE
    answers with SecurityModeComplete, which is uplink and invisible here."""
    if not is_unicast(rnti):
        return "n/a", None
    sessions = sessions_by_rnti.get(rnti)
    if not sessions:
        return "unknown", None
    s = session_for(sessions, ct)
    if s is None:
        return "unknown", None
    if s["outcome"] == "established":
        if s["outcome_ct"] is None or ct is None:
            return "unknown", s
        return ("pre" if ct <= s["outcome_ct"] else "post"), s
    return VERDICT_FROM_OUTCOME.get(s["outcome"], "unknown"), s


# The pcapng sec= patch moved to tools/security_scan.py. It keys on frame number there --
# an index into the very file it dissected -- which removes the ambiguity this module had
# when two PDUs for one RNTI landed in the same subframe.


def _ms_since(rec, session, key):
    """Milliseconds from a session instant to this record, in capture time.

    Both sides are collection_time now -- the radio clock -- so there is no wall-clock
    fallback left to get wrong. Blank when the session has no such instant, which is the
    honest answer for a UE that never reached a boundary.
    """
    if session is None or session.get(key) is None:
        return ""
    ct = rec.get("collection_time")
    if ct in (None, ""):
        return ""
    try:
        return round((int(ct) - int(session[key])) / 1000.0, 3)
    except (TypeError, ValueError):
        return ""


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

    boundaries, sec_files = load_sessions(run_dir)

    if not sec_files:
        # security_sessions is produced by the scan, and the scan needs Wireshark. Run it
        # rather than refusing, so `security_phase_join.py . -f all` stays the one command
        # anyone has to remember -- but keep this module usable on a box without tshark,
        # which is its current de facto property.
        scan = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_scan.py")
        if os.path.isfile(scan) and shutil.which("tshark") and \
                glob.glob(os.path.join(run_dir, "mac-*.pcapng")):
            print("no security_sessions-*.csv yet; running security_scan.py first\n",
                  flush=True)
            rc = subprocess.run([sys.executable, scan, run_dir]).returncode
            if rc == 0:
                boundaries, sec_files = load_sessions(run_dir)
            print()

    if not sec_files:
        # Easy to be one level up: an output directory holds timestamped run directories,
        # and a sweep nests them another level under earfcn-<n>/. Point at them rather than
        # just refusing.
        candidates = sorted(
            os.path.dirname(p) for p in
            glob.glob(os.path.join(run_dir, "*", "security_sessions-*.csv")) +
            glob.glob(os.path.join(run_dir, "*", "*", "security_sessions-*.csv"))
        )
        msg = ["error: no security_sessions-*.csv in " + run_dir]
        if candidates:
            msg.append("")
            one = len(candidates) == 1
            msg.append(f"{len(candidates)} run director{'y' if one else 'ies'} below this one "
                       f"{'does' if one else 'do'} have one:")
            msg += [f"    {os.path.relpath(c, run_dir)}" for c in candidates[:10]]
            if len(candidates) > 10:
                msg.append(f"    ... and {len(candidates) - 10} more")
        else:
            # Deliberately not asserting the cause. An absent file means this run was never
            # scanned -- it does NOT mean no UE reached security, which is what a
            # header-only security_sessions-<rf>.csv would mean. That is the reading that
            # matters, so state it rather than guessing at the configuration.
            msg.append("tools/security_scan.py writes it, from mac-<rf>.pcapng. An absent file")
            msg.append("means this run was never scanned -- it does not mean no UE reached")
            msg.append("security; that would be a file with a header and no rows. Either the")
            msg.append("run had pcap_mac off, or tshark is missing, or this is not a run dir.")
        sys.exit("\n".join(msg))

    dci_files = sorted(glob.glob(os.path.join(run_dir, "dci_output", "*.dciLog")))
    if not dci_files:
        sys.exit(f"error: no .dciLog files under {os.path.join(run_dir, 'dci_output')}")

    rf_indices = {s["rf_idx"] for sessions in boundaries.values() for s in sessions}
    if len(rf_indices) > 1:
        # .dciLog files are named by frequency, not rf_idx, so records cannot be attributed
        # to a cell from the filename alone. Say so rather than guess.
        print(f"warning: {len(rf_indices)} cells present; boundaries are merged across them. "
              "An RNTI reused by two cells in one run could be mis-joined.", file=sys.stderr)

    rows = []
    identity_by_key = load_identity_events(run_dir)
    identity_counts = Counter()
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

            # collection_time is the radio clock and is on both sides; timestamp_us is the
            # host wall clock, which in a replay advances at decode speed. Fall back only
            # for runs that predate the ct columns.
            try:
                ct = int(rec.get("collection_time") or 0) or None
            except ValueError:
                ct = None
            phase, session = verdict_for(rnti, ct if ct is not None else ts, boundaries)
            counts[phase] += 1
            if phase in ("pre", "post"):
                per_rnti[rnti][phase] += 1

            # Identity exposure is per-DCI, not per-UE: the value marks the grant that
            # actually carried the message. `none` is watched-and-clean, matching the
            # convention everywhere else here.
            identity = identity_by_key.get((rnti, ct), "none") if ct is not None else "unknown"
            if identity != "none":
                identity_counts[identity] += 1

            streamed = rec.get("security_phase", "")
            if want_dcilog and direction in ("dl", "ul"):
                # The full seven-value domain goes in. ngscope now writes one constant
                # ("unknown") into every record, so there is no in-stream vocabulary left to
                # stay compatible with, and collapsing values here would discard exactly the
                # distinctions the offline scan exists to make.
                dcilog_phase = phase
                # Mutating the parsed record preserves key order and the string values, so
                # the field lands exactly where ngscope put it rather than appended.
                if "security_phase" in rec:
                    rec["security_phase"] = dcilog_phase
                    # A new key, appended rather than replacing anything: the joined
                    # .dciLog is a derived artefact, and ngscope writes no such field.
                    rec["identity_exposure"] = identity
                else:
                    rec = {"tti": rec.get("tti"), "rnti": rec.get("rnti"),
                           "security_phase": dcilog_phase,
                           **{k: v for k, v in rec.items() if k not in ("tti", "rnti")}}
                rewritten[path].append(rec)
            # No in-stream label survives to disagree with: ngscope writes "unknown" on
            # every record now. Kept as a tripwire in case an old run is re-joined.
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
                    "identity_exposure": identity,
                    "rar_tti": session["rar_tti"] if session else "",
                    "outcome": session["outcome"] if session else "",
                    "rar_collection_time": session["rar_ct"] if session else "",
                    "outcome_collection_time": (session["outcome_ct"] if session and
                                                session["outcome_ct"] is not None else ""),
                    # Radio-domain elapsed times: real milliseconds over the air, not
                    # decode-clock milliseconds.
                    "ms_since_rar": _ms_since(rec, session, "rar_ct"),
                    "ms_to_outcome": _ms_since(rec, session, "outcome_ct"),
                    "prb": rec.get("prb", ""),
                    "harq": rec.get("harq", ""),
                    "tbs": rec.get("TB1_tbs", ""),
                })

    total = sum(counts.values())
    print(f"run            : {run_dir}")
    nof_boundaries = sum(1 for v in boundaries.values() for s in v
                         if s["outcome"] == "established")
    nof_sessions = sum(len(v) for v in boundaries.values())
    print(f"sessions       : {nof_sessions} over {len(boundaries)} RNTIs, from "
          f"{len(sec_files)} security_sessions file(s); {nof_boundaries} established")
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
    if identity_by_key:
        print(f"identity       : {sum(identity_counts.values()):,} DCI record(s) carried an "
              f"identity-revealing message -- " +
              ", ".join(f"{k}={v}" for k, v in sorted(identity_counts.items())))
        print("                 marked per record as identity_exposure; the per-UE view is "
              "the identity_exposure")
        print("                 column of security_sessions.")
    print()
    # All seven, in the order they tell a story: placed relative to a boundary, then the
    # outcomes that mean no boundary was ever going to exist, then the two absences.
    for phase in ("pre", "post", "reused", "noctx", "none", "unknown", "n/a"):
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
        # The pcapng is written by tools/security_scan.py, which reorders it, dissects that
        # same file and patches sec= by frame number. Doing it again here would be a second
        # source of truth for the same field.
        joined = sorted(glob.glob(os.path.join(run_dir, "pcap_joined", "mac-*.pcapng")))
        print()
        if joined:
            print(f"pcapng         : {len(joined)} file(s) already written by "
                  f"security_scan.py in pcap_joined/ -- reordered and sec=-patched there")
        else:
            print("pcapng         : none in pcap_joined/. Run tools/security_scan.py over "
                  "this run to produce it;")
            print("                 this tool only labels the .dciLog files.")
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
