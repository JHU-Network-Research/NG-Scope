# Confirm a cell is receivable before committing to a recording.
#
# Cell search has to succeed before a single usable sample is written, but the recorder is
# already running while it looks -- at 185 MB/s for a two-channel 50 PRB capture. And the
# search does not fail cleanly: it loops forever by design, and has twice been observed never
# returning at all, with not even a "Cell not found after N trials" line to show for it. Both
# times a live run at the same frequency locked in seconds moments later, so it is not the
# signal. The cost of finding that out the expensive way is about 50 GB per attempt.
#
# So look first, live, where nothing is written. It also answers the questions worth knowing
# before spending the disk: how many ports, and how many preambles the cell reserves -- a
# cell that reserves none cannot show a handover at all, which may well decide whether the
# recording is worth taking.
#
# Usage: precheck <freq_hz> <seconds> <workdir>   -> 0 and prints a summary, or 1.

precheck() {
    local freq="$1" secs="$2" dir="$3"
    local ng=/home/amarder/NG-Scope/build/ngscope/src/ngscope

    rm -rf "$dir"; mkdir -p "$dir" || return 1
    cat > "$dir/run.toml" <<TOML
nof_rf_dev = 1
decode_SIB = true
decode_RAR = true
rach_filter_only = false
pcap_mac = false
enable_256qam = true

[[rf_config]]
rf_freq = $freq
N_id_2 = -1
rf_args = ""
nof_thread = 5
nof_rx_ant = 2
mode = 0
replay_fname = ""
decode_pdcch = true
log_dl = true
log_ul = true
log_phich = false
disable_plot = true
debug = false
silent = true

[dci_log_config]
log_interval = -1
TOML

    # -s INT, not the default SIGTERM: ngscope flushes stdout on SIGINT and loses the whole
    # buffer on SIGTERM, so a TERM-killed run looks like it printed nothing at all. stdbuf
    # for the same reason -- the log is read while it is still being written.
    ( cd "$dir" && timeout -s INT "$secs" stdbuf -oL -eL "$ng" -c run.toml > stdout.log 2>&1 )

    # cell_type.json is written and closed right after cell search, so it is the one lock
    # signal that cannot be lost to stdout buffering. Safe to grep the log for the rest:
    # by here the process has exited on SIGINT, which flushes.
    if ! find "$dir" -name cell_type.json 2>/dev/null | grep -q .; then
        echo "PRE-CHECK: nothing locked at $((freq / 1000000)) MHz within ${secs}s." >&2
        echo "PRE-CHECK: not recording. Nothing was written." >&2
        return 1
    fi

    grep -m1 "Decoding PBCH for cell" "$dir/stdout.log"
    local ct rar
    ct=$(cat "$dir"/ngscope_out/*/cell_type.json 2>/dev/null | tr -d '\n ')
    [ -n "$ct" ] && echo "PRE-CHECK: $ct"
    grep -m1 "rach-ConfigCommon" "$dir/stdout.log" || \
        echo "PRE-CHECK: no SIB2 -- the preamble boundary is unknown, so no RACH on the"
    grep -q "rach-ConfigCommon" "$dir/stdout.log" || \
        echo "PRE-CHECK: recording will be classifiable as contention-free."
    rar=$(ls "$dir"/ngscope_out/*/rar_log-0.csv 2>/dev/null | head -1)
    if [ -n "$rar" ]; then
        echo "PRE-CHECK: $(( $(wc -l < "$rar") - 1 )) RARs in ${secs}s live -- if this is 0 the"
        echo "PRE-CHECK: cell is idle and a recording of it will measure nothing."
    fi
    return 0
}
