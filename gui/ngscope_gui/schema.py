"""Configuration schema, mirrored from the C side.

The authoritative tables are the X-macros in ngscope/hdr/dciLib/load_config.h:

    NGSCOPE_TOP_LEVEL_KEYS  ->  TOP_LEVEL
    NGSCOPE_RF_DEV_KEYS     ->  RF_DEV
    NGSCOPE_LOG_KEYS        ->  LOG

Each entry here carries the same (type, key, default, required) as the C table plus the UI
label and the help text, which is lifted from the comments in ngscope/config.toml. The
form is rendered from these lists, so adding a setting is one line here and one line in
load_config.h -- no widget code to touch.

`nof_rf_dev` is deliberately absent: in TOML the device count is the length of the
[[rf_config]] array (load_config_toml.c:174-183), and emitting the key would be ignored at
best and misleading at worst.
"""

# Compile-time limits from ngscope/hdr/dciLib/ngscope_def.h
MAX_NOF_RF_DEV = 4
MAX_NOF_DCI_DECODER = 8
# rf_args is char[100] in rf_dev_config_t, so 99 usable characters.
RF_ARGS_MAX_LEN = 99

MODE_NORMAL, MODE_RECORD, MODE_REPLAY = 0, 1, 2

# Bump when the persisted state layout changes incompatibly.
STATE_VERSION = 1


def _f(key, type_, default, label, help_, required=False, **extra):
    field = {
        "key": key,
        "type": type_,
        "default": default,
        "label": label,
        "help": help_,
        "required": required,
    }
    field.update(extra)
    return field


# --------------------------------------------------------------------------- top level

TOP_LEVEL = [
    _f(
        "rnti", "int", 0, "Target RNTI",
        "Required: there is no safe default. 0 is not inert -- it matches empty "
        "decoder-tree slots and floods the output.",
        required=True, min=0, max=65535,
    ),
    _f(
        "remote_enable", "bool", False, "Remote sink",
        "Stream decoded DCIs to remote subscribers over the network (the DCI sink server).",
    ),
    _f(
        "decode_single_ue", "bool", False, "Single-UE decode",
        "Decode only the target RNTI instead of running the multi-UE blind search. "
        "Much cheaper.",
    ),
    _f(
        "decode_SIB", "bool", False, "Decode SIB",
        "Decode SIB1/SIB2 and write cell identity and reference signal power to "
        "cellcfg.json.",
    ),
    _f(
        "decode_RAR", "bool", False, "Decode RAR",
        "Decode Random Access Responses (Msg2), one row per RAR in rar_log-<rf_idx>.csv. "
        "Gives the TTI at which each RNTI was assigned. Roughly +25% decode time per "
        "subframe; does not change the DCI output.",
    ),
    _f(
        "rar_seed_tracker", "bool", False, "Seed tracker from RACH",
        "Prime the UE tracker with each RACH-assigned RNTI so its next genuine PDCCH "
        "sighting promotes it to active instead of needing two. Measured effect on DCI "
        "yield: none.",
    ),
    _f(
        "mark_security_phase", "bool", False, "Mark security phase",
        "Label each unicast DCI pre, post or unknown relative to the UE establishing an AS "
        "security context. The boundary is observed, not inferred: NG-Scope decodes the "
        "UE's still-unciphered RRC looking for securityModeCommand, and a DCI it cannot "
        "place stays unknown.",
    ),
    _f(
        "rach_filter_only", "bool", False, "RACH filter only",
        "Record only DCIs whose RNTI was observed being assigned to a UE that successfully "
        "completed RACH, plus SI-RNTI/P-RNTI/RA-RNTI which never RACH. Implies decode_RAR, "
        "since the RNTI set is built from decoded RARs.",
    ),
    _f(
        "pcap_mac", "bool", False, "MAC pcap",
        "Write every decoded downlink MAC PDU to mac-<rf_idx>.pcapng, readable in Wireshark "
        "once DLT_USER0 (147) is mapped to mac-lte-framed. See docs/pcap.md.",
    ),
    _f(
        "pcap_max_mb", "int", 0, "pcap cap (MB)",
        "Per-file size cap in MB; 0 is unlimited. A busy 20 MHz cell can produce around a "
        "gigabyte a minute.",
        min=0,
    ),
    _f(
        "enable_256qam", "bool", True, "256QAM table",
        "Use the 256QAM MCS->TBS table for C-RNTI Format1/2 grants. Only correct when the "
        "cell configures altCQI-Table-r12, which a downlink sniffer cannot observe, so this "
        "is a guess. It sets the tbs values in the .dciLog files, so getting it wrong gives "
        "wrong throughput figures. SIB, RAR and paging are unaffected either way.",
    ),
]

# --------------------------------------------------------------------------- per RF device

RF_DEV = [
    _f(
        "rf_freq", "int64", 0, "Downlink frequency (Hz)",
        "Downlink centre frequency in Hz. Required. Two devices may not share a frequency.",
        required=True, min=0,
    ),
    _f(
        "N_id_2", "int", -1, "N_id_2",
        "Force the PSS sequence (0-2), or -1 to search all three.",
        min=-1, max=2,
    ),
    _f(
        "rf_args", "str", "", "RF args",
        'Passed straight to the SDR driver, e.g. "type=b200,clock_source=external".',
        maxlen=RF_ARGS_MAX_LEN,
    ),
    _f(
        "nof_thread", "int", 4, "Decoder threads",
        "DCI decoder threads for this cell. Too few and subframes are dropped in live "
        "capture, or replay falls behind real time.",
        min=1, max=MAX_NOF_DCI_DECODER,
    ),
    _f(
        "nof_rx_ant", "int", 1, "RX antennas",
        "Receive channels to open on this SDR. Two are required to decode transmission modes "
        "3 and 4 with two spatial layers -- with one antenna those grants cannot be separated "
        "and always fail. Needs an SDR with two coherent RX channels (B210, or an X310 with "
        "two daughterboards). No help on a 4-port cell, where srsRAN cannot predecode spatial "
        "multiplexing at all.",
        min=1, max=4,
    ),
    _f(
        "mode", "mode", MODE_NORMAL, "Mode",
        "Normal decodes live. Record captures IQ to disk alongside the run. Replay reads "
        "IQ back from a file.",
    ),
    _f(
        "replay_fname", "path", "", "Replay file",
        "Source IQ file for Replay mode. Ignored otherwise: recording always writes to "
        "<out_dir>/<timestamp>/recorded-samples.bin.",
    ),
    _f(
        "decode_pdcch", "bool", True, "Decode PDCCH",
        "Decode the control channel. Off synchronises and records without decoding, "
        "which is what you want for a pure IQ capture.",
    ),
    _f("log_dl", "bool", True, "Log downlink", "Write the downlink .dciLog file."),
    _f("log_ul", "bool", True, "Log uplink", "Write the uplink .dciLog file."),
    _f("log_phich", "bool", False, "Log PHICH", "Write the PHICH .dciLog file."),
    _f(
        "disable_plot", "bool", True, "Disable plot",
        "Disable the GUI plot for this cell. Only meaningful in builds with ENABLE_GUI.",
    ),
    _f(
        "debug", "bool", False, "Debug tracing",
        "Verbose per-subframe tracing. Thousands of lines per second.",
    ),
    _f(
        "silent", "bool", False, "Silent",
        "Suppress the per-subframe summary lines.",
    ),
]

# --------------------------------------------------------------------------- dci_log_config

LOG = [
    _f(
        "log_interval", "int", -1, "Log rotation (s)",
        "Seconds between log file rotations; each rotation opens a new timestamped file. "
        "-1 or 0 disables rotation.",
        min=-1,
    ),
]


def defaults_for(fields):
    return {f["key"]: f["default"] for f in fields}


# GUI-only per-cell state, never written to the config: ngscope has no EARFCN key, only
# rf_freq. These record which of the two the user is editing, and the EARFCN they typed,
# so reopening the app returns to the same view. config_io only emits schema keys, so
# these are dropped on the way out by construction.
GUI_CELL_EXTRAS = {
    "gui_freq_mode": "hz",   # "hz" | "earfcn"
    "gui_earfcn": "",
}


def default_cell():
    cell = defaults_for(RF_DEV)
    cell.update(GUI_CELL_EXTRAS)
    return cell


def default_config():
    """A complete, valid-shaped config model. Matches what the C defaults would produce."""
    return {
        "schema_version": STATE_VERSION,
        "top": defaults_for(TOP_LEVEL),
        "log": defaults_for(LOG),
        "cells": [default_cell()],
    }


def bootstrap():
    """Everything the frontend needs to render the form."""
    return {
        "top_level": TOP_LEVEL,
        "rf_dev": RF_DEV,
        "log": LOG,
        "limits": {
            "max_cells": MAX_NOF_RF_DEV,
            "max_threads": MAX_NOF_DCI_DECODER,
            "rf_args_maxlen": RF_ARGS_MAX_LEN,
        },
        "modes": [
            {"value": MODE_NORMAL, "label": "Normal"},
            {"value": MODE_RECORD, "label": "Record"},
            {"value": MODE_REPLAY, "label": "Replay"},
        ],
    }
