#!/usr/bin/env bash
#
# What does a second receive antenna buy on a 4-port cell?
#
# Records one capture with two RX channels, then replays THE SAME BYTES at nof_rx_ant = 1 and
# at 2 and compares. Same bytes is the whole point: two separate recordings differ in the
# channel as much as in the receiver, and the question is about the receiver.
#
# This is possible because replay no longer takes its antenna count from the recording header
# -- the header says how many channels the file holds, which is a different question. Surplus
# channels are read and dropped; missing ones are zero-filled. See docs/configuration.md
# "Channel count in replay".
#
# Expectation worth writing down before the run, so the result can disagree with it: on a
# 4-port cell the second antenna is an MRC gain on transmit-diversity grants -- which is what
# every pre-security message uses -- and buys nothing on spatial multiplexing, which srsRAN
# cannot predecode at 4 ports either way. So `DIVERSITY ... CRC failures` should fall and the
# SPATIALMUX bucket should not move.
#
# Usage: measurements/two_antenna_ab.sh [seconds] [outdir]

set -u -o pipefail

SECS="${1:-180}"
OUT="${2:-$HOME/ngscope-data/two_antenna_5330}"

# EARFCN 5330 is band 14: 758 + 0.1*(5330-5280) = 763.0 MHz.
RF_FREQ=763000000
NGSCOPE=/home/amarder/NG-Scope/build/ngscope/src/ngscope
SCAN=/home/amarder/NG-Scope/tools/security_scan.py
CHECK=/home/amarder/NG-Scope/tools/check_recording.py

# 50 PRB is 11.52 Msps; 8 bytes per complex sample, two channels.
RATE_MB_S=185
NEED_GB=$(( SECS * RATE_MB_S / 1000 + 2 ))

# How long to let cell search run before giving up. It loops forever by design ("Cell not
# found after N trials. Trying again"), so without a bound a cell that is not receivable here
# looks identical to one that is just slow to lock.
#
# Measured at 763 MHz on this box: locks in roughly 75-90 s, and sometimes not on the first
# attempt, so a 90 s bound rejects a perfectly good cell about half the time. Note the
# recorder is already writing during the search -- the file grows by ~185 MB per second spent
# looking -- which is why this is bounded at all rather than left to run.
SEARCH_TIMEOUT=300

say() { printf '\n=== %s ===\n' "$*"; }

mkdir -p "$OUT" || exit 1
AVAIL_GB=$(df -BG --output=avail "$OUT" | tail -1 | tr -dc '0-9')
say "two-antenna A/B on EARFCN 5330 (band 14, 763.0 MHz)"
echo "duration      : ${SECS}s"
echo "expected size : ~${NEED_GB} GB at ${RATE_MB_S} MB/s (two channels, 11.52 Msps)"
echo "disk available: ${AVAIL_GB} GB"
if [ "$AVAIL_GB" -lt "$NEED_GB" ]; then
    echo "REFUSING: not enough space. Free some, or ask for a shorter recording." >&2
    exit 1
fi

if ! timeout 60 uhd_find_devices 2>&1 | grep -qiE "B210|B200|type: b200"; then
    echo "REFUSING: no USRP on the USB bus (uhd_find_devices finds nothing)." >&2
    echo "Plug the B210 in and re-run; nothing has been written." >&2
    exit 1
fi

# ---------------------------------------------------------------- 1. record
REC="$OUT/record"
mkdir -p "$REC"
# Decode as little as possible while recording. The run is writing 185 MB/s into an 8 GB
# ring buffer, so CPU spent decoding is CPU not spent draining it, and a recorder that falls
# behind drops frames -- which would corrupt the very bytes the A/B depends on being
# identical between the two replays.
#
# decode_SIB in particular is OFF here on purpose: it segfaults on this cell (PCI 206) inside
# srsran_ue_dl_find_and_decode_sib1 about two minutes in. Pre-existing, reproduces on a stock
# build, docs/security-implementation.md section 7 has the trace -- and on a 180 s record it
# would truncate the capture at ~120 s with no warning. Nothing about recording needs it: the
# cell search that must succeed first does not read SIBs.
#
# Decoding nothing while recording is a correctness requirement, not an optimisation, and it
# was measured. record_ring_buffer_insert() is called synchronously inside the receive
# callback, so anything competing for that thread costs samples straight off the radio -- and
# UHD's overflow characters are invisible here, because "Fastpath logging disabled at
# runtime" suppresses them. Same cell, minutes apart, normalised per second of tracked time:
#
#   decode_pdcch = true, SIB and RAR off  ->  2.66% of the window lost,  424 DCI/s, 0.13 RAR/s
#   nothing decoding                      ->  1.05% lost,                803 DCI/s, 0.21 RAR/s
#
# So PDCCH decoding alone roughly halves the yield. Turning SIB and RAR decoding on as well
# is far worse again -- a capture taken that way replayed at about 13 DCI/s, two orders off,
# with srsran_ue_sync failing on ~76% of subframes. That failure mode is worth naming because
# it is indistinguishable from weak signal at the point where you notice it.
#
# The all-off recording matches live reception on the same cell (803 DCI/s recorded against
# 582 DCI/s live), which is the check that says nothing is being lost. Decode afterwards, in
# replay, where the scheduler blocks instead of dropping subframes.
cat > "$REC/run.toml" <<EOF
nof_rf_dev = 1
remote_enable = false
decode_SIB = false
decode_RAR = false
rar_seed_tracker = false
mark_security_phase = false
rach_filter_only = false
pcap_mac = false
pcap_max_mb = 0
qam_retry = false
enable_256qam = true
probe_blind_dci = false

[[rf_config]]
rf_freq = $RF_FREQ
N_id_2 = -1
rf_args = ""
nof_thread = 5
nof_rx_ant = 2
mode = 1
replay_fname = ""
decode_pdcch = false
log_dl = true
log_ul = true
log_phich = false
disable_plot = true
debug = false
silent = true

[dci_log_config]
log_interval = -1
EOF

say "recording ${SECS}s with two RX channels"
cd "$REC" || exit 1
# stdbuf, because the lock detection below greps this log while it is being written. With
# stdout redirected to a file libc block-buffers it, so "Decoding PBCH for cell" can sit
# unflushed for minutes -- long enough for a perfectly good recording to be declared NO CELL
# and thrown away. That happened twice before this line existed; one of the runs was aborted
# while it was happily capturing 193 s of a locked cell.
stdbuf -oL -eL "$NGSCOPE" -c run.toml > stdout.log 2>&1 &
NG_PID=$!

# Cell search must succeed before any samples are written, so wait for it explicitly rather
# than assuming the recording started.
for i in $(seq "$SEARCH_TIMEOUT"); do
    kill -0 "$NG_PID" 2>/dev/null || break
    grep -q "Decoding PBCH for cell" stdout.log 2>/dev/null && break
    sleep 1
done
if ! grep -q "Decoding PBCH for cell" stdout.log 2>/dev/null; then
    kill -INT "$NG_PID" 2>/dev/null; wait "$NG_PID" 2>/dev/null
    echo "NO CELL: nothing locked at 763.0 MHz within ${SEARCH_TIMEOUT}s." >&2
    echo "5330 is not receivable from here right now -- check the antenna, or try another" >&2
    echo "EARFCN. Last lines of the run:" >&2
    tail -5 stdout.log >&2
    exit 1
fi
grep -m1 "Decoding PBCH for cell" stdout.log

sleep "$SECS"
kill -INT "$NG_PID" 2>/dev/null
wait "$NG_PID" 2>/dev/null

BIN=$(find "$REC/ngscope_out" -name recorded-samples.bin | head -1)
if [ ! -s "${BIN:-/nonexistent}" ]; then
    echo "NO DATA: cell locked but no samples were written. See $REC/stdout.log" >&2
    exit 1
fi
say "recorded $(du -h "$BIN" | cut -f1) to $BIN"

# Check the capture before replaying it twice. A recording with holes replays as if the
# signal were weak, so without this the A/B could compare two runs over corrupt bytes and
# report the difference as an antenna effect.
python3 "$CHECK" "$BIN"
CHECK_RC=$?
if [ "$CHECK_RC" -ge 2 ]; then
    echo "REFUSING to replay a corrupt capture. Nothing else was running, so this is worth" >&2
    echo "investigating rather than retrying blindly." >&2
    exit 1
fi

# ---------------------------------------------------------------- 2. replay at 1 and 2
for ANT in 1 2; do
    D="$OUT/replay_${ANT}ant"
    rm -rf "$D"; mkdir -p "$D"
    # decode_SIB off for the same crash, and because it must be identical across the two
    # runs or the comparison is not about the antenna.
    cat > "$D/run.toml" <<EOF
nof_rf_dev = 1
remote_enable = false
decode_SIB = false
decode_RAR = true
rar_seed_tracker = false
mark_security_phase = true
rach_filter_only = true
pcap_mac = true
pcap_max_mb = 0
qam_retry = true
enable_256qam = true
probe_blind_dci = true

[[rf_config]]
rf_freq = $RF_FREQ
N_id_2 = -1
rf_args = ""
nof_thread = 5
nof_rx_ant = $ANT
mode = 2
use_replay_hdr = true
replay_fname = "$BIN"
decode_pdcch = true
log_dl = true
log_ul = true
log_phich = false
disable_plot = true
debug = false
silent = true

[dci_log_config]
log_interval = -1
EOF
    say "replaying the same bytes at nof_rx_ant = $ANT"
    ( cd "$D" && stdbuf -oL -eL "$NGSCOPE" -c run.toml > stdout.log 2>&1 )
    RD=$(find "$D/ngscope_out" -maxdepth 1 -mindepth 1 -type d | head -1)
    [ -n "$RD" ] && ( cd "$RD" && timeout 1800 python3 "$SCAN" . > scan.log 2>&1 )
done

# ---------------------------------------------------------------- 3. compare
say "RESULT -- same bytes, one antenna vs two"
for ANT in 1 2; do
    D="$OUT/replay_${ANT}ant"
    RD=$(find "$D/ngscope_out" -maxdepth 1 -mindepth 1 -type d | head -1)
    echo
    echo "--- nof_rx_ant = $ANT ---"
    grep -hE "^SECURITY \(cell 0\): [0-9]|tx scheme|DCI by format|^RACH filter \(cell 0\): [0-9]" "$D/stdout.log"
    [ -f "$RD/scan.log" ] && grep -hE "rate |established=|served, no RACH|RAR cross-check|mismatches" "$RD/scan.log"
done

# ---------------------------------------------------------------- 4. preamble boundary
# Separate, short, and allowed to fail. The contention-free preamble boundary comes only from
# SIB2, and decode_SIB crashes on this cell partway in -- but SIB2 arrives in the first
# seconds, so a truncated run still leaves rach_config.json behind. Kept out of the A/B runs
# above so a crash cannot take the measurement with it.
say "preamble boundary (separate short run; crashing partway is expected on this cell)"
SIBD="$OUT/sib_probe"
rm -rf "$SIBD"; mkdir -p "$SIBD"
sed -e 's/^decode_SIB = false/decode_SIB = true/' -e 's/^nof_rx_ant = 2/nof_rx_ant = 2/' \
    "$OUT/replay_2ant/run.toml" > "$SIBD/run.toml"
( cd "$SIBD" && timeout 180 stdbuf -oL -eL "$NGSCOPE" -c run.toml > stdout.log 2>&1 )
if grep -q "rach-ConfigCommon" "$SIBD/stdout.log" 2>/dev/null; then
    grep -m1 "rach-ConfigCommon" "$SIBD/stdout.log"
    RC=$(find "$SIBD" -name rach_config.json | head -1)
    [ -n "$RC" ] && cp "$RC" "$OUT/replay_1ant/ngscope_out/"*/ 2>/dev/null
    [ -n "$RC" ] && cp "$RC" "$OUT/replay_2ant/ngscope_out/"*/ 2>/dev/null
    echo "copied rach_config.json into both replay dirs; re-run security_scan.py there to"
    echo "classify RACH type"
else
    echo "SIB2 not decoded -- RACH type stays 'unknown', which is the honest value. It is not"
    echo "a synonym for 'contention': guessing the boundary would manufacture handovers."
fi

cat <<'NOTE'

How to read it
--------------
The comparison that matters is the DIVERSITY bucket and its CRC failures: that is where a
second antenna can help, and it is what carries every pre-security message. SPATIALMUX should
be unchanged -- srsRAN cannot predecode it at 4 ports at any antenna count, so a difference
there means something other than the antenna moved.

`established` and `served, no RACH` are the end-to-end figures. They are noisier than the
decode counters because they depend on which UEs happened to be active, but both runs saw the
identical bytes, so any difference is the receiver.
NOTE
