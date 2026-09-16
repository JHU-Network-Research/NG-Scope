#!/usr/bin/env python3
"""Is this IQ recording intact, or does it have holes in it?

Every frame header carries nof_samples and a timestamp. On a capture that lost nothing, the
timestamp of frame N+1 is the timestamp of frame N plus nof_samples/sample_rate. Anything
else means the radio handed over a discontinuity -- samples that were dropped between the
antenna and the file.

This matters because a capture with holes does not look broken. It looks like weak signal:
srsran_ue_sync simply fails to track, the DCI yield collapses, and every conclusion drawn
from the replay is quietly wrong -- and UHD's overflow characters are invisible the whole
time, because "Fastpath logging disabled at runtime" suppresses them.

Measured on this project, same cell minutes apart: recording with PDCCH decoding on lost
2.66% of the window and replayed at 424 DCI/s, against 1.05% and 803 DCI/s with nothing
decoding. Adding SIB and RAR decoding on top was far worse again -- about 13 DCI/s, with
ue_sync failing on roughly 76% of subframes.

So check the file, not the yield. Run it on every capture before trusting one.

Usage: tools/check_recording.py <recorded-samples.bin> [--max-frames N]
"""
import argparse
import os
import struct
import sys

FRAME_HDR = struct.Struct("<QQd")      # nof_samples, timestamp_full_secs, timestamp_frac_secs
RECORD_HDR = struct.Struct("<IId")     # nof_rx_antenna, (padding), rf_freq
SAMPLE_BYTES = 8                       # cf_t: two float32

# A sample period at 11.52 Msps is 87 ns. Timestamps are doubles carrying whole seconds, so
# the representable resolution near a large epoch is coarse; allow a slack of a few samples
# before calling a gap a gap.
SLACK_SAMPLES = 8


def read_record_header(fh):
    """Returns (nof_rx_antenna, rf_freq, header_size) or (None, None, 0) when absent.

    A legacy capture starts straight into a frame header, whose first field is nof_samples --
    a number in the thousands. A record header's first field is an antenna count in 1..4, so
    the two are distinguishable without a magic number.
    """
    head = fh.read(RECORD_HDR.size)
    fh.seek(0)
    if len(head) < RECORD_HDR.size:
        return None, None, 0
    nof_ant, _pad, rf_freq = RECORD_HDR.unpack(head)
    if 1 <= nof_ant <= 4 and 0.0 <= rf_freq < 1e11:
        return nof_ant, rf_freq, RECORD_HDR.size
    return None, None, 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--max-frames", type=int, default=0,
                    help="stop after N frames (0 = whole file)")
    ap.add_argument("--channels", type=int, default=0,
                    help="channels per frame; default: from the record header, else 1")
    args = ap.parse_args()

    total = os.path.getsize(args.path)
    fh = open(args.path, "rb")
    nof_ant, rf_freq, hdr_size = read_record_header(fh)
    channels = args.channels or nof_ant or 1

    print(f"file      : {args.path}")
    print(f"size      : {total / 1e9:.2f} GB")
    if hdr_size:
        print(f"header    : nof_rx_antenna={nof_ant}, rf_freq={rf_freq / 1e6:.1f} MHz")
    else:
        print("header    : none (legacy capture) -- assuming "
              f"{channels} channel{'' if channels == 1 else 's'}")

    # Pass 1: what size is a steady-state frame on this capture?
    #
    # It cannot be assumed and it cannot be taken from the first frame. A recording opens with
    # the cell-search phase -- a few hundred frames at 1.92 Msps, some at other rates, then a
    # retune -- before it settles into one subframe per frame at the cell's bandwidth. Taking
    # the first plausible frame size gives the search rate and makes every later timestamp
    # look wrong.
    off = hdr_size
    fh.seek(off)
    sizes = {}
    frame_sizes = []
    n_frames = 0
    while off < total:
        raw = fh.read(FRAME_HDR.size)
        if len(raw) < FRAME_HDR.size:
            break
        nof_samples = FRAME_HDR.unpack(raw)[0]
        if not (1 <= nof_samples <= 1 << 20):
            print(f"\nCHAIN BROKEN at byte {off}: implausible nof_samples={nof_samples}.")
            print("The stream is not being parsed at its frame boundaries -- wrong channel "
                  "count, or a truncated write.")
            return 2
        sizes[nof_samples] = sizes.get(nof_samples, 0) + 1
        frame_sizes.append(nof_samples)
        n_frames += 1
        off += FRAME_HDR.size + nof_samples * SAMPLE_BYTES * channels
        fh.seek(off)
        if args.max_frames and n_frames >= args.max_frames:
            break

    if not sizes:
        print("\nEMPTY: no frames.")
        return 2
    dominant = max(sizes.items(), key=lambda kv: kv[1])[0]
    rate = dominant * 1000.0        # ngscope writes one subframe (1 ms) per frame

    # Where does the capture actually settle?
    #
    # A recording opens with cell search and a retune, and for a few frames after the retune
    # the radio is still restarting its stream -- on a known-good field capture that shows up
    # as two discontinuities inside the first hundred frames and none in the next twenty
    # thousand. That transient is the receiver starting up, not samples being lost, so the
    # verdict is taken from the frames after the last rate change. They are reported anyway,
    # because a transient that grows is worth seeing.
    # "Dominant" has to tolerate a sample of jitter. Frame sizes of 11519 and 11520 appear
    # side by side throughout a capture; treating the odd one as a rate change would mark the
    # stream as re-settling every few thousand frames, and an earlier version of this check
    # did exactly that -- pushing the settle point to frame 25,430 of 30,000 and passing
    # everything by ignoring almost all of it.
    def dominant_ish(sz):
        return abs(sz - dominant) <= 4

    # Settling is the START of the capture, not the last odd frame anywhere in it. Find the
    # first point from which the stream runs at the dominant size for a solid stretch.
    RUN = 100
    settle_idx = 0
    run = 0
    for i, sz in enumerate(frame_sizes):
        if dominant_ish(sz):
            run += 1
            if run >= RUN:
                settle_idx = i - run + 1
                break
        else:
            run = 0
    # ...plus the acquisition transient. After the last rate change the radio restarts its
    # stream, and ue_sync takes a moment to acquire: on a known-good field capture that is two
    # discontinuities within ~100 ms of tracking (one of them 1.17 s long), followed by twenty
    # thousand clean frames. One second of grace covers it without hiding anything a recorder
    # problem would produce, because recorder loss is spread across the whole capture rather
    # than confined to its first moments.
    ACQUIRE_FRAMES = 1000        # 1 s, at one subframe per frame
    settle_idx += ACQUIRE_FRAMES

    # Pass 2: continuity, but only where the stream is actually streaming.
    #
    # Judge a pair of frames only when both are dominant-size. A frame of any other size is
    # cell search or a retune, and the discontinuity around it is the radio changing rate --
    # expected, not loss. Anything still flagged happened while the receiver was settled,
    # which is the only time a gap means samples went missing.
    fh.seek(hdr_size)
    off = hdr_size
    n_frames = 0
    prev_end = None
    prev_dominant = False
    gaps = []
    overlaps = 0
    startup_gaps = 0
    missing_samples = 0.0
    steady_frames = 0

    while off < total:
        raw = fh.read(FRAME_HDR.size)
        if len(raw) < FRAME_HDR.size:
            break
        nof_samples, ts_full, ts_frac = FRAME_HDR.unpack(raw)
        if not (1 <= nof_samples <= 1 << 20):
            break
        ts = ts_full + ts_frac
        is_dominant = dominant_ish(nof_samples)

        if is_dominant and prev_dominant and prev_end is not None:
            samples_off = (ts - prev_end) * rate
            if samples_off > SLACK_SAMPLES:
                if n_frames > settle_idx:
                    gaps.append((n_frames, ts - prev_end, samples_off))
                    missing_samples += samples_off
                else:
                    startup_gaps += 1
            elif samples_off < -SLACK_SAMPLES:
                if n_frames > settle_idx:
                    overlaps += 1
        if is_dominant:
            steady_frames += 1

        prev_end = ts + nof_samples / rate
        prev_dominant = is_dominant
        n_frames += 1
        off += FRAME_HDR.size + nof_samples * SAMPLE_BYTES * channels
        fh.seek(off)
        if args.max_frames and n_frames >= args.max_frames:
            break

    radio_seconds = steady_frames * dominant / rate

    walked_pct = 100.0 * off / total if total else 0.0
    print(f"frames    : {n_frames}, walked {walked_pct:.1f}% of the file")
    print(f"rate      : {rate / 1e6:.2f} Msps ({dominant} samples/frame, the dominant size)")
    print(f"steady    : {steady_frames} frames at that size = {radio_seconds:.1f} s of "
          "tracked radio time")
    print(f"settled at: frame {settle_idx} (cell search, retune and 1 s of acquisition "
          "precede it)")
    top = sorted(sizes.items(), key=lambda kv: -kv[1])[:4]
    print("frame size: " + ", ".join(f"{k} samples x{v}" for k, v in top))

    print()
    if steady_frames < 2:
        print("INCONCLUSIVE: the capture never settled at a steady frame size, so continuity")
        print("could not be checked. Usually means cell search never completed.")
        return 1

    lost_s = missing_samples / rate
    lost_pct = 100.0 * lost_s / (radio_seconds + lost_s) if radio_seconds else 0.0
    per_sec = len(gaps) / radio_seconds if radio_seconds else 0.0

    if gaps:
        print(f"GAPS: {len(gaps)} discontinuities while tracking ({per_sec:.2f}/s), "
              f"{missing_samples:,.0f} samples ({lost_s:.3f} s) missing -- {lost_pct:.2f}% of "
              "the tracked window.")
        print("Worst:")
        for idx, delta, samp in sorted(gaps, key=lambda g: -g[2])[:5]:
            print(f"  frame {idx}: {samp:,.0f} samples ({delta * 1000:.2f} ms) missing")
        print()

    # Graduated, because some loss is normal and the question is how much.
    #
    # Calibration from this project's own field captures, which all replay usefully:
    #   mt_airy02/5110   1 gap,   1.17% lost
    #   mt_airy02/5330   2 gaps,  1.26% lost
    #   att_trolley     79 gaps, 11.50% lost   (the one CLAUDE.md notes segments heavily)
    #
    # So single-digit percentages are the normal field band. What is NOT normal is the
    # failure this tool was written for: recording while decoding. PDCCH decoding alone
    # roughly halves the yield (2.66% lost against 1.05%); adding SIB and RAR decoding takes
    # it to about 13 DCI/s against 803, with ue_sync failing on ~76% of subframes. That last
    # case is a different order of magnitude, and it is invisible in the log because UHD's
    # overflow characters are suppressed by "Fastpath logging disabled".
    if lost_pct >= 25.0:
        print(f"CORRUPT: {lost_pct:.1f}% of the tracked window is missing. This capture will "
              "replay as if")
        print("the signal were weak -- ue_sync will fail to track and the DCI yield will be a")
        print("property of the recorder, not the cell.")
        print("Re-record with decode_pdcch = false and nothing else decoding.")
        return 2
    if gaps:
        print(f"USABLE, WITH LOSS: {lost_pct:.1f}% missing, in the band this project's field "
              "captures sit in")
        print("(1.2% to 11.5%). ue_sync re-acquires after each gap. Worth quoting beside any "
              "rate")
        print("computed from it, since a UE inside a gap is indistinguishable from one that "
              "never appeared.")
        return 0

    if overlaps:
        print(f"WARNING: {overlaps} frames whose timestamps go backwards. Not a loss, but the "
              "stream is not monotonic.")
        return 1

    print("INTACT: after the stream settled, every frame's timestamp follows the previous "
          "one by")
    print("exactly its sample count. No samples were lost between the antenna and the file.")
    if startup_gaps:
        print(f"({startup_gaps} discontinuit{'y' if startup_gaps == 1 else 'ies'} before "
              f"frame {settle_idx} -- cell search, retune and acquisition, not loss.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
