#!/usr/bin/env bash
#
# Record one cell with two channels, replay it, and scan the result. The whole pipeline for
# "what is on this frequency, and what can we prove about the UEs on it".
#
# Recording decodes nothing at all: record_ring_buffer_insert() runs inside the receive
# callback, so anything competing for that thread costs samples off the radio, and UHD's
# overflow characters are suppressed by "Fastpath logging disabled at runtime" -- a holed
# capture looks exactly like weak signal. See docs/configuration.md, "Recording hygiene".
# Decoding happens afterwards in replay, where the scheduler blocks rather than dropping.
#
# Usage: measurements/try_cell.sh <name> <freq_hz> <seconds>
#
#   measurements/try_cell.sh b12_5110 739000000 240
set -u
NAME=$1; FREQ=$2; SECS=$3
NG=/home/amarder/NG-Scope/build/ngscope/src/ngscope
R=~/ngscope-data/try_$NAME; rm -rf $R; mkdir -p $R

# Look before spending the disk: the recorder writes at ~185 MB/s while cell search runs, and
# that search can fail without ever returning. See measurements/lib_precheck.sh.
. /home/amarder/NG-Scope/measurements/lib_precheck.sh
if ! precheck "$FREQ" 180 "$R/precheck"; then
    echo "$NAME: not recording."
    exit 1
fi

mkdir -p $R/record; cd $R/record
cat > run.toml <<TOML
nof_rf_dev = 1
decode_SIB = false
decode_RAR = false
rach_filter_only = false
pcap_mac = false
qam_retry = false
enable_256qam = true
probe_blind_dci = false
mark_security_phase = false

[[rf_config]]
rf_freq = $FREQ
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
TOML
# Wait for the cell, by watching for a FILE rather than a log line.
#
# ngscope writes cell_type.json immediately after cell search succeeds, and a written-and-
# closed file cannot sit in a buffer. Grepping stdout for "Decoding PBCH for cell" cannot be
# relied on: with stdout redirected libc block-buffers it, stdbuf does not take effect on
# this binary, and ngscope only flushes on SIGINT. That combination has now twice declared a
# NO CELL on a run that had locked and was recording at full rate -- once after 193 s of good
# capture, once at 739 MHz with cell_type.json already on disk.
wait_for_lock() {
    local dir="$1" secs="$2"
    for _ in $(seq "$secs"); do
        kill -0 "$P" 2>/dev/null || return 1
        find "$dir" -name cell_type.json 2>/dev/null | grep -q . && return 0
        sleep 1
    done
    return 1
}

$NG -c run.toml > stdout.log 2>&1 &
P=$!
if ! wait_for_lock "$R/record" 300; then
  kill -INT $P 2>/dev/null; wait $P 2>/dev/null; echo "$NAME: NO CELL LOCK"; exit 1; fi
echo "$NAME: locked -- $(find $R/record -name cell_type.json -exec cat {} \; | tr -d '\n ')"
sleep $SECS; kill -INT $P; wait $P 2>/dev/null
BIN=$(find $R/record/ngscope_out -name recorded-samples.bin|head -1)
echo "$NAME: recorded $(du -h $BIN|cut -f1)"
python3 /home/amarder/NG-Scope/tools/check_recording.py "$BIN" | grep -E "rate |steady|GAPS|INTACT|USABLE|CORRUPT"

D=$R/replay; mkdir -p $D; cd $D
sed -e 's/^mode = 1/mode = 2/' -e 's/^decode_RAR = false/decode_RAR = true/' \
    -e 's/^decode_pdcch = false/decode_pdcch = true/' -e 's/^rach_filter_only = false/rach_filter_only = true/' \
    -e 's/^mark_security_phase = false/mark_security_phase = true/' -e 's/^pcap_mac = false/pcap_mac = true/' \
    -e 's/^qam_retry = false/qam_retry = true/' -e 's/^probe_blind_dci = false/probe_blind_dci = true/' \
    -e '/^decode_SIB/d' -e "s|^replay_fname = .*|replay_fname = \"$BIN\"|" $R/record/run.toml > run.toml
echo 'use_replay_hdr = true' >> run.toml
stdbuf -oL -eL $NG -c run.toml > stdout.log 2>&1
grep -hE "^config: decode_SIB|rach-ConfigCommon|^RACH filter \(cell 0\): [0-9]|^SECURITY \(cell 0\): [0-9]|tx scheme|DCI by format|^PDCCH ORDER \(cell" stdout.log
RD=$(find $D/ngscope_out -maxdepth 1 -mindepth 1 -type d|head -1)
cat $RD/cell_type.json 2>/dev/null | tr -d '\n '
echo
(cd $RD && timeout 1800 python3 /home/amarder/NG-Scope/tools/security_scan.py . 2>&1 | grep -E "sessions  |rate  |^ +[0-9]+/|served, no RACH|their outcomes|provenance|RACH type|RAR cross|mismatch|events ")
