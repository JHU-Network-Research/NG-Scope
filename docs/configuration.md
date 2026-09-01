# NG-Scope Configuration Reference

NG-Scope is configured by a file passed with `-c`. Everything except the output directory
lives in that file; there are no environment variables and no other command-line switches
that affect decoding.

```
ngscope -c <config file> [-o <output folder>] [-h]
```

**Two formats are accepted, chosen by file extension:**

| extension | format | example |
|---|---|---|
| `.toml` | [TOML](https://toml.io) | [`ngscope/config.toml`](../ngscope/config.toml) |
| anything else | [libconfig](https://hyperrealm.github.io/libconfig/) | [`ngscope/config.cfg`](../ngscope/config.cfg) |

They accept exactly the same settings and are interchangeable — both backends are generated
from one schema, so neither can drift. The startup banner says which one is in use:

```
config: reading ngscope/config.toml (TOML)
```

TOML is the newer option and the better-supported format in editors; libconfig remains the
default so existing `.cfg` files keep working untouched.

`-h` also lists `-s <sib output>` and `-b <cell cfg output>`. Neither changes where anything
is written: both directories are derived from `-o`, `-b` is parsed and then unused, and `-s`
is only echoed back. Use `-o`.

Every setting is echoed at startup, so the fastest way to confirm one took effect is to
`grep '^config:'` the console output. A value that came from a default rather than the file
is marked, which makes a typo'd key obvious:

```
config: nof_rf_dev = 1
config: rnti = 9185
config: decode_RAR = true
config: rach_filter_only = false (default)
config: rf_config0.rf_freq = 2680000000
config: rf_config0.rf_args = "type=x300"
config: dci_log_config.log_interval = 5
```

### Where settings are defined

The accepted keys, their types, defaults and whether they are required live in one place —
the schema tables at the bottom of
[`ngscope/hdr/dciLib/load_config.h`](../ngscope/hdr/dciLib/load_config.h). Both the
libconfig and TOML backends generate their lookups from these tables, which is why the two
formats cannot drift apart:

```c
#define NGSCOPE_TOP_LEVEL_KEYS(X)                              \
    X(INT,   "nof_rf_dev",      nof_rf_dev,      1,     false) \
    X(INT,   "rnti",            rnti,            0,     true)  \
    X(BOOL,  "decode_RAR",      decode_RAR,      false, false) \
    ...
```

**Adding a setting is one row plus a struct field** — no parsing code to touch in either
[`load_config.c`](../ngscope/src/dciLib/load_config.c) (libconfig) or
[`load_config_toml.c`](../ngscope/src/dciLib/load_config_toml.c) (TOML), and it appears in
both formats at once.

Two rules the tables enforce:

- **Required keys have no default.** `rnti` and `rf_config<N>.rf_freq` are required: if
  either is missing NG-Scope reports it and exits, rather than running on a fabricated
  value. (`rnti = 0` in particular is not inert — `srsran_ngscope_tree_copy_rnti()` matches
  zeroed tree slots, so it would flood the output.)
- **Every optional key has an explicit default.** `ngscope_config_t` is a stack local in
  `main()`, so a key with neither a value nor a default previously left the field holding
  garbage — not zero.

---

## File structure

The two formats differ only in how repeated RF-device sections are written.

**libconfig (`.cfg`)** — numbered blocks, counted by `nof_rf_dev`:

```
nof_rf_dev = 1;          // top-level scalars
rnti = 9185;

rf_config0 = { ... };    // one block per RF device, numbered from 0
rf_config1 = { ... };

dci_log_config = { ... };
```

Blocks beyond `nof_rf_dev` are ignored, so the count and the blocks must be kept in sync.

**TOML (`.toml`)** — an array of tables, which needs no count:

```toml
rnti = 9185              # top-level scalars

[[rf_config]]            # one table per RF device
rf_freq = 2680000000

[[rf_config]]
rf_freq = 1955000000

[dci_log_config]
log_interval = 5
```

`nof_rf_dev` is derived from the number of `[[rf_config]]` tables and is not written in TOML
files — the startup banner reports it as `nof_rf_dev = 2 (from 2 [[rf_config]] tables)`.
Note also that `rf_freq` takes no `L` suffix in TOML, since its integers are already 64-bit.

---

## Top-level parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `nof_rf_dev` | int | `1` | **libconfig only.** Number of RF devices (cells) to decode simultaneously. Must be 1–4 (`MAX_NOF_RF_DEV`); outside that range NG-Scope exits. Each needs its own `rf_configN` block. In TOML it is derived from the `[[rf_config]]` array and must not be set. |
| `rnti` | int | **required** | Target RNTI. Used as the single-UE target when `decode_single_ue = true`, for PHICH tracking, and as a preferred RNTI in the blind decoder's candidate selection. |
| `remote_enable` | bool | `false` | Start the DCI sink server, which streams decoded DCIs to remote subscribers over the network. |
| `decode_single_ue` | bool | `false` | Decode only `rnti` instead of running the multi-UE blind search. Much cheaper, but reports one UE. |
| `decode_SIB` | bool | `false` | Decode SIB1/SIB2 and write cell identity (MCC/MNC/TAC/cell ID) and reference signal power to `cellcfg.json`. |
| `decode_RAR` | bool | `false` | Decode Random Access Responses. See [RACH decoding](#rach-decoding) below. |
| `rar_seed_tracker` | bool | `false` | Prime the UE tracker with RACH-assigned RNTIs. See [RACH decoding](#rach-decoding). |
| `rach_filter_only` | bool | `false` | Report only RNTIs observed completing RACH. See [RACH decoding](#rach-decoding). |
| `pcap_mac` | bool | `false` | Write decoded downlink MAC PDUs to `mac-<rf_idx>.pcapng` in MAC-LTE encapsulation. See [docs/pcap.md](pcap.md) for the Wireshark setup, which is not optional — DLT 147 is `DLT_USER0` and dissects as nothing until configured. |
| `pcap_max_mb` | int | `0` | Per-file cap in MB, `0` for unlimited. |
| `enable_256qam` | bool | `true` | Use the 256QAM MCS→TBS table for C-RNTI Format1/2 grants. Only correct when the cell configures `altCQI-Table-r12`, which a downlink sniffer cannot observe, so it is a guess either way. It selects the MCS→TBS mapping, so it sets the `tbs` values in the `.dciLog` files — a wrong guess gives wrong throughput figures. srsRAN forces it off for Format1A and non-user RNTIs, so SIB, RAR and paging are unaffected. |

A missing optional key is not fatal: it falls back to the default above and says so. A
missing **required** key is fatal — NG-Scope lists what is missing and exits.

---

## Per-device parameters (`rf_configN` / `[[rf_config]]`)

| Key | Type | Default | Description |
|---|---|---|---|
| `rf_freq` | int64 | **required** | Downlink centre frequency in Hz. In libconfig it needs the int64 suffix (`2680000000L`); in TOML it does not. Two devices may not share a frequency — NG-Scope exits if they do, because log files are named by frequency. |
| `N_id_2` | int | `-1` | Force the PSS sequence (0–2). `-1` searches all three. |
| `rf_args` | string | `""` | Passed to the SDR driver, e.g. `"type=b200"`, `"type=x300,clock_source=external"`. Max 100 chars. |
| `nof_rx_ant` | int | `1` | Receive channels to open on this SDR. **Two are required for transmission modes 3 and 4 with two spatial layers** — `srsran_predecoding_ccd_zf()` needs `nof_ports == 2 && nof_rxant == 2`, so with one antenna every such grant fails. Needs two coherent RX channels (B210; X310 with two daughterboards). Useless on a 4-port cell, where srsRAN has no spatial-multiplexing predecoder at any antenna count. Recording only stores channel 0, so a two-antenna capture cannot yet be replayed as two antennas. |
| `nof_thread` | int | `4` | DCI decoder threads for this cell. Max 8 (`MAX_NOF_DCI_DECODER`). Too few and subframes are skipped in live capture, or the replay falls behind real time. |
| `disable_plot` | bool | `true` | Disable the GUI for this cell. Only effective in builds with `ENABLE_GUI`. |
| `log_dl` | bool | `true` | Write the downlink `.dciLog` file. **This is the flag that controls DL logging**, not `dci_log_config.log_dl`. |
| `log_ul` | bool | `true` | Write the uplink `.dciLog` file. |
| `log_phich` | bool | `false` | Write the PHICH `.dciLog` file. |
| `mode` | int | `0` | `0` normal, `1` record IQ to disk, `2` replay IQ from disk. |
| `replay_fname` | string | none | Source file for `mode = 2`. Required only in replay mode; NG-Scope exits if it is missing. Recording always writes to `<out_dir>/<timestamp>/recorded-samples.bin` and ignores this key. |
| `debug` | bool | `false` | Verbose per-subframe tracing. Extremely noisy — thousands of lines per second. |
| `silent` | bool | `false` | Suppress the per-subframe summary lines. |
| `decode_pdcch` | bool | `true` | Decode the control channel. Setting it `false` synchronises and records without decoding, which is what you want for a pure IQ capture. |

### Record and replay

`mode = 1` writes raw IQ plus a per-frame header to
`<out_dir>/<timestamp>/recorded-samples.bin`. `mode = 2` reads such a file back, pacing
playback to the recorded timestamps so it runs at roughly real time — a 60-second capture
takes about 60 seconds to replay.

Replay is a faithful re-run of the decode path, which makes it the right way to A/B a
configuration change: run twice on the same file, changing one flag.

---

## Logging parameters (`dci_log_config`)

| Key | Type | Description |
|---|---|---|
| `log_interval` | int (default `-1`) | Seconds between log file rotations. Each rotation opens a new timestamped file. `-1` or `0` disables rotation. |

This block used to also accept `log_dl` and `log_ul`. They were parsed and stored but never
read, so setting them had no effect; they have been removed. Which `.dciLog` files get
written is controlled per cell by `rf_configN.log_dl` / `log_ul` / `log_phich`. Older configs
that still set them keep working — libconfig ignores keys the program does not ask for.

---

## RACH decoding

Three independent flags. All default to `false`; the first two never change DCI output, the
third changes it substantially.

### `decode_RAR`

Decodes Random Access Responses (Msg2) and writes one row per RAR to
`<out_dir>/<timestamp>/rar_log-<rf_idx>.csv`:

```
timestamp,collection_time,tti,rf_idx,ra_rnti,rapid,temp_crnti,ta_cmd,grant_rba,grant_mcs,ul_grant,tbs,crc
1786685439584262,3893822,1755,0,8,56,15098,25,293,1,0x24a2c,56,1
```

`security_log-<rf_idx>.csv` carries both clocks for each boundary: `rar_timestamp` /
`smc_timestamp` are host wall-clock at decode, while `rar_collection_time` /
`smc_collection_time` are the radio domain. `rar_to_smc_ms` is derived from the latter, so
it is the real over-the-air delay whether the run was live or a replay decoding at some
other speed. Prefer the collection times for anything plotted against time: on a replay the
wall clock advances at decode speed, which inflated the same delay by 26 ms at the median
and up to a second at the tail on the capture measured here.

`temp_crnti` is the RNTI the network just assigned to a UE, and `tti` joins against the `tti`
column in `dci-decode-debug-<n>.csv` and the `"tti"` field in the `.dciLog` files. This is
how you tell when an RNTI came into existence, rather than inferring it from traffic.

Each subframe is searched for RA-RNTI 1–10 in the common search space; a hit is PDSCH-decoded
and the MAC RAR PDU parsed. Both the PDCCH and PDSCH CRCs are checked against a known
RA-RNTI, so false positives are very unlikely. Costs roughly **+25%** decode time per
subframe. Does not affect DCI output.

RA-RNTI 11–60 (TDD with more than one PRACH frequency resource) is not supported; srsRAN's
`SRSRAN_CRNTI_START` is `0x000B`, so those values are misclassified as UE RNTIs during DCI
unpacking. FDD is fully covered.

### `rar_seed_tracker`

Primes the UE tracker with each RACH-assigned RNTI so its next genuine PDCCH sighting
promotes it to "active" instead of requiring two. It deliberately never marks an RNTI active
on RAR evidence alone.

Measured on a 21-second capture: promotion happens a median of 10 TTIs earlier, in 44 of 46
cases. Measured effect on DCI yield: **none** (+1 record, inside run-to-run noise). Left in
because it is free and safe, but do not expect it to help.

### Choosing an operating mode

`rach_filter_only` is not merely a noise filter — it selects between two fundamentally
different decoders, and which one is right depends on the question being asked.

**`false` (blind).** The search recovers each RNTI from the descrambled PDCCH CRC, so it sees
every UE on the cell including those already connected when the capture began. It also
manufactures RNTIs: a false alarm yields a uniformly distributed 16-bit value. Measured on a
60 s band-12 capture: 53,953 DCIs across 6,369 distinct RNTIs, of which only a few hundred
are real UEs. Right for cell-level load and bandwidth measurement, where the aggregate
matters and per-UE attribution does not.

**`true` (RACH-gated).** Only RNTIs observed being handed out in a Random Access Response are
reported. Same capture: 25,760 DCIs across 188 RNTIs. This is the model LTESniffer uses --
it searches each known UE's search space with `srsran_ue_dl_find_dl_dci()`, so the PDCCH CRC
is checked against a known RNTI rather than recovered from it, and a hit cannot be
manufactured. The cost is that a UE which connected before the capture started is invisible.

**For per-UE analysis -- connection tracking, security-context state, IMSI-catcher detection
-- use `true`.** Every UE relevant to those questions performs RACH within the capture by
definition, and per-UE conclusions drawn over blind-mode RNTIs are unsound.

One deliberate difference from LTESniffer: NG-Scope admits an RNTI on the RAR alone, whereas
LTESniffer waits for an `RRCConnectionSetup` to confirm it. NG-Scope's rule is looser but
keeps UEs that attempted to attach and never got further -- which is precisely the population
that distinguishes a fake base station from a real one.

Note also that the re-encode correlation gate in the blind search (`ue_dl.c`, `JH
CORR_FILTER`) is currently commented out, so with `rach_filter_only = false` there is no
false-positive gate at all.

### `rach_filter_only`

Restricts reported RNTIs to those observed completing RACH, plus SI-RNTI, P-RNTI and RA-RNTI
— which never RACH by definition, so filtering them would silently discard all system
information and paging DCIs.

Implies `decode_RAR`; enabling it alone would leave the RNTI set empty and drop every UE DCI,
so `load_config` warns and turns `decode_RAR` on.

Measured on a 60-second commercial capture:

| | off | on |
|---|---|---|
| distinct RNTIs reported | 6,244 | **95** |
| DCI records | 60,445 | 9,532 |

**This is a precision/recall trade, and the recall cost is large.** The blind decoder recovers
RNTIs from the descrambled PDCCH CRC rather than checking them against a known value, so a
false alarm produces a uniformly distributed 16-bit RNTI and survives a ~96-entry whitelist
with probability ≈ 96/65536. But ~84% of what it drops is real traffic from UEs that
completed RACH before the capture started and therefore can never enter the set.

Applies to the `.dciLog` files, `cell_status` and the remote sink. It does **not** apply to
`dci-decode-debug-<n>.csv`, which is always written unfiltered with a trailing `rach_ok`
column marking what the filter would drop. That column is populated whether or not the flag
is set, so you can measure the trade-off from a single unfiltered run:

```bash
awk -F, '$24==1' dci-decode-debug-*.csv | wc -l   # would survive
awk -F, '$24==0' dci-decode-debug-*.csv | wc -l   # would be dropped
```

A summary is printed at shutdown:

```
RACH filter (cell 0): 96 RNTIs admitted, 11952 DCIs kept, 63292 dropped (84.1%)
```

---

## Output layout

`-o` sets the root (default `ngscope_out`); a timestamped run directory is created inside it.

```
<out_dir>/<YYYY_MM_DD_HH_MM_SS>/
├── dci_output/
│   ├── dci_raw_log_dl_freq_<rf_freq>_<timestamp>.dciLog     JSON, one record per TTI
│   ├── dci_raw_log_ul_freq_<rf_freq>_<timestamp>.dciLog
│   └── phich_log_ul_freq_<rf_freq>_<timestamp>.dciLog
├── decoded_sibs/
├── dci-decode-debug.csv          header row only
├── dci-decode-debug-<n>.csv      one file per decoder thread, no header
├── rar_log-<rf_idx>.csv          decode_RAR only
├── mac-<rf_idx>.pcapng           pcap_mac only -- see docs/pcap.md
├── rsrp.txt, cell_type.json, cellcfg.json
├── decoder_<n>.txt, task_scheduler.txt, collection_times.csv, file_reads.txt
└── recorded-samples.bin          mode = 1 only
```

Per-decoder CSVs are split by thread and carry no header — concatenate them and prepend the
header from `dci-decode-debug.csv`. Within one file rows are in TTI order, but the threads
interleave, so sort the concatenation by `tti` if you need sequence. Note that `tti` wraps at
10240 (`MAX_TTI`), roughly every 10 seconds, so it is not a monotonic timeline on its own —
use `timestamp` or `collection_time` for that.

---

## Known quirks

These are surprising but current behaviour, listed so you do not lose time to them.

- **Unknown keys are silently ignored.** Nothing warns about a typo'd or obsolete key — the
  only symptom is the setting you meant reporting `(default)` at startup. Top-level
  `disable_plot` is a live example: it is never parsed (only `rf_configN.disable_plot` is)
  yet still appears in three of the four shipped configs, where it does nothing.
- **A phich-only configuration never starts the logger.** The check that decides whether to
  spawn the logging thread tests only `log_dl` and `log_ul`, so `log_phich = true` with both
  others `false` produces no output at all.
- **`.dciLog` files contain a zero-filled placeholder record for every TTI with no DCIs**, so
  the record count is not the DCI count. Filter on `"rnti"` ≠ 0.
- **Long `-o` paths are silently truncated** at 128 characters.
- **Duplicate `rf_freq` across devices is fatal**, because log files are named by frequency.
