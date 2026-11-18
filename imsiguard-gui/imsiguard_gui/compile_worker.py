"""Compile one replay run into a single celldf, in a subprocess.

Runs IMSIGUARD/scripts/compile_replays.py's own load_replay_dir() and build_celldf() for the one
interval the classifier needs, skipping the CLI's directory scan, the compiled_data.csv dump and
the other five intervals.

Usage: compile_worker.py <run_dir> <interval_s> <out_csv>
"""
import importlib.util
import os
import sys
import time
from pathlib import Path

SCRIPT = str(Path(os.environ.get("IMSIGUARD_REPO", Path.home() / "IMSIGUARD")) / "scripts" / "compile_replays.py")


def main():
    run_dir, interval, out_csv = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    spec = importlib.util.spec_from_file_location("compile_replays", SCRIPT)
    cr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cr)

    t = time.time()
    df = cr.load_replay_dir(run_dir)
    print(f"loaded {len(df)} DCIs in {time.time() - t:.1f}s", flush=True)
    if df.empty:
        print("no decodable DCIs (missing mac-0.pcapng or no DCI logs)", flush=True)
        return 2
    t = time.time()
    celldf = cr.build_celldf(df, interval)
    print(f"built {len(celldf)} cell window(s) in {time.time() - t:.1f}s", flush=True)
    celldf.to_csv(out_csv, index=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
