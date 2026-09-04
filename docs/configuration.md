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
    X(BOOL,  "decode_RAR",      decode_RAR,      false, false) \
    ...
```

**Adding a setting is one row plus a struct field** — no parsing code to touch in either
[`load_config.c`](../ngscope/src/dciLib/load_config.c) (libconfig) or
[`load_config_toml.c`](../ngscope/src/dciLib/load_config_toml.c) (TOML), and it appears in
both formats at once.

Two rules the tables enforce:

- **Required keys have no default.** A key marked required in the last column has no usable
  default: if it is missing NG-Scope reports it and exits, rather than running on a
  fabricated value. **No key is currently marked required** — `rnti` was the last one and it
  is gone (see below), and `rf_config<N>.rf_freq` is enforced by
  `ngscope_config_finalize()` for the modes that actually tune rather than by the table,
  because replay learns it from the recording. The mechanism is still wired through every
  backend, so a future required key is one column away.
- **Every optional key has an explicit default.** `ngscope_config_t` is a stack local in
  `main()`, so a key with neither a value nor a default previously left the field holding
  garbage — not zero.

---

## File structure

The two formats differ only in how repeated RF-device sections are written.

**libconfig (`.cfg`)** — numbered blocks, counted by `nof_rf_dev`:

```
nof_rf_dev = 1;          // top-level scalars
decode_RAR = true;

rf_config0 = { ... };    // one block per RF device, numbered from 0
rf_config1 = { ... };

dci_log_config = { ... };
```

Blocks beyond `nof_rf_dev` are ignored, so the count and the blocks must be kept in sync.

**TOML (`.toml`)** — an array of tables, which needs no count:

```toml
decode_RAR = true        # top-level scalars

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
| `remote_enable` | bool | `false` | Start the DCI sink server, which streams decoded DCIs to remote subscribers over the network. |
| `decode_SIB` | bool | `false` | Decode SIB1/SIB2 and write cell identity (MCC/MNC/TAC/cell ID) and reference signal power to `cellcfg.json`. |
| `decode_RAR` | bool | `false` | Decode Random Access Responses. See [RACH decoding](#rach-decoding) below. |
| `rar_seed_tracker` | bool | `false` | Prime the UE tracker with RACH-assigned RNTIs. See [RACH decoding](#rach-decoding). |
| `rach_filter_only` | bool | `false` | Report only RNTIs observed completing RACH. See [RACH decoding](#rach-decoding). |
| `mark_security_phase` | bool | `false` | **Replay only** — refused at config time for live or record, and implies both `decode_RAR` (which anchors each UE) and `pcap_mac` (which is where the result goes). Decodes each RACH-anchored UE's downlink transport blocks into `mac-<rf>.pcapng`. ngscope makes no claim about their contents: `tools/security_scan.py` dissects that capture with Wireshark and writes `security_events`/`security_sessions`/`security_summary`. The name is historical — nothing is marked in-process any more, and the `.dciLog` `security_phase` field stays `unknown` until the join runs. See [docs/security-measurement.md](security-measurement.md). |
| `pcap_mac` | bool | `false` | Write decoded downlink MAC PDUs to `mac-<rf_idx>.pcapng` in MAC-LTE encapsulation. See [docs/pcap.md](pcap.md) for the Wireshark setup, which is not optional — DLT 147 is `DLT_USER0` and dissects as nothing until configured. |
| `pcap_max_mb` | int | `0` | Per-file cap in MB, `0` for unlimited. |
| `qam_retry` | bool | `true` | **Replay only.** When a transport block fails its CRC, rebuild the grant on the other MCS→TBS table and decode again, keeping whichever passes. The CRC is ground truth, so this measures the table rather than trusting `enable_256qam`, per grant — the only way to be right, since `altCQI-Table-r12` is per-UE state. Costs a second PDSCH decode per failure, which is affordable exactly where the scheduler blocks instead of dropping subframes. On one capture it recovered 37 `SecurityModeCommand`s (33.8% → 39.2%) for 1 second in 65. |
| `probe_blind_dci` | bool | `false` | **Replay only** — refused at config time otherwise. A measurement instrument, not part of a capture run: it decodes a transport block for every distinct RNTI the blind search reports and records whether the DL-SCH CRC passes, split by whether that RNTI was RACH-confirmed. Writes `blind_probe-<rf>.csv` and a teardown summary. Pair with `rach_filter_only = false`, or the unconfirmed column is empty by construction. See [Is a blind DCI real?](#is-a-blind-dci-real) below. |
| `enable_256qam` | bool | `true` | Use the 256QAM MCS→TBS table for C-RNTI Format1/2 grants. Only correct when the cell configures `altCQI-Table-r12`, which is **per-UE** RRC state a downlink sniffer cannot observe — so it is a guess, and on a mixed cell no single value is right for every UE. It selects the MCS→TBS mapping, so it sets the transport block size: a wrong guess gives wrong `tbs` values in the `.dciLog` files *and* a transport block CRC that can never pass. srsRAN forces it off for Format1A and non-user RNTIs, so SIB, RAR and paging are unaffected. Every run prints a verdict at teardown; with `mark_security_phase` in replay, a failed block is retried on the other table, so the setting matters much less there. |

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
| `nof_thread` | int | `4` | DCI decoder threads for this cell. Must be 1–8 (`MAX_NOF_DCI_DECODER`); a value outside that range is now refused at config time, having previously segfaulted inside `srsran_ue_dl_init()`. Too few and subframes are skipped in live capture, or the replay falls behind real time. |
| `disable_plot` | bool | `true` | Disable the GUI for this cell. Only effective in builds with `ENABLE_GUI`. |
| `log_dl` | bool | `true` | Write the downlink `.dciLog` file. **This is the flag that controls DL logging**, not `dci_log_config.log_dl`. |
| `log_ul` | bool | `true` | Write the uplink `.dciLog` file. |
| `log_phich` | bool | `false` | **No longer supported — forced off with a warning.** It wrote the PHICH `.dciLog`, whose only real content was the synthetic `rv = 4` record PHICH decoding injected for the configured target RNTI. Both are gone; see [Removed settings](#removed-settings). |
| `mode` | int | `0` | `0` normal, `1` record IQ to disk, `2` replay IQ from disk. |
| `replay_fname` | string | none | Source file for `mode = 2`. Required only in replay mode; NG-Scope exits if it is missing **or unreadable** — checked at config time, before the radio and decoders are set up. May be compressed: a `.bz2`, `.gz` or `.xz` suffix is decompressed on the fly. Recording always writes to `<out_dir>/<timestamp>/recorded-samples.bin` and ignores this key. |
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

#### Compressed recordings

`replay_fname` may point at a compressed recording. The suffix selects the decompressor, a
parallel one preferred and the serial one used if that is absent:

| suffix | preferred | fallback |
|---|---|---|
| `.bz2` | `lbzip2` | `bzip2` |
| `.gz` | `pigz` | `gzip` |
| `.xz` | `xz` | — |

It runs as a subprocess on a pipe, concurrently with the decoder, so it costs wall time only
when the decoder is left waiting on it. In-process decompression via `libbz2` was rejected on
measurement: it is the same single-threaded algorithm as `bzip2 -dc` (and as `bzcat`, which is
a symlink to the same binary), so it buys nothing over the subprocess and gives up the
concurrency.

**It never changes the result, only the wall time.** The replay reads strictly forward, and
the one place it seeks — skipping a payload it has rejected — reads and discards on a pipe
instead. Verified on a 3.14 GB capture: uncompressed, `lbzip2` and `bzip2` all produced
17,072 frames read and the same 3,167 downlink DCIs, with identical RAR sets. The pcap
differed by one packet, which is **baseline nondeterminism** — two identical uncompressed runs
differ by the same one packet, because which tracked UEs a subframe's decoder gets to scan
depends on thread timing.

**Whether decompression limits the run depends on the cell, so it is measured, not
predicted.** Every replay prints a `REPLAY SOURCE` line at teardown giving the fraction of
wall time spent blocked reading the recording and the resulting source throughput. On that
capture — 100 PRB, 5 decoder threads, so about 115 MB/s consumed:

| source | wall | blocked | source rate | verdict |
|---|---|---|---|---|
| plain file | 27.2 s | 1% | 9,499 MB/s (page cache) | — |
| `lbzip2` | 36.8 s | 13% | 642 MB/s | decompression kept up |
| `bzip2` | 115.2 s | 79% | 34 MB/s | the decompressor was the limiter |

So on a wide cell serial `bzip2` costs roughly 4× the wall time, while on a narrower one — or
with heavier decode settings such as `probe_blind_dci`, which slow the consumer — it has room
to keep up. Read the teardown line rather than assuming either way.

Compression buys less than it costs on IQ: `bzip2` gets a recording to about 46% of its
original size. Worth it for an archive, rarely for a capture being iterated on.

---

## Logging parameters (`dci_log_config`)

| Key | Type | Description |
|---|---|---|
| `log_interval` | int (default `-1`) | Seconds between log file rotations. Each rotation opens a new timestamped file. `-1` or `0` disables rotation. |

This block used to also accept `log_dl` and `log_ul`. They were parsed and stored but never
read, so setting them had no effect; they have been removed. Which `.dciLog` files get
written is controlled per cell by `rf_configN.log_dl` / `log_ul`. Older configs that still
set them keep working — libconfig ignores keys the program does not ask for.

---

## Is a blind DCI real?

With `rach_filter_only = false` the blind decoder reports far more RNTIs than exist — 6,369
in 60 s against 188 real, on one capture. They come out of the PDCCH blind search, which
*descrambles* the DCI CRC to recover an RNTI rather than checking it against a known one, so
the CRC cannot reject anything: whatever 16 bits fall out become an RNTI.

`probe_blind_dci = true` answers the question the DCI CRC cannot, using the **transport-block
CRC** as the oracle:

- PDSCH descrambling is seeded with the RNTI — `(rnti << 14) + (q << 13) + ((nslot/2) << 9) +
  cell_id`, `lib/src/phy/phch/sequences.c`.
- The DL-SCH CRC is an unmasked CRC24A that the RNTI never touches, `lib/src/phy/phch/sch.c`.

So a transport block that passes CRC was descrambled with the right RNTI *and* rate-matched
to the right size. The `(RNTI, grant)` pair is real, with a false-pass probability around
2⁻²⁴. That is a much stronger test than asking whether the payload parses — and a real block
often will *not* parse, because it is ciphered, or a DRB carrying IP, or an RLC segment.

**The test is one-sided, and the output keeps that visible.** Every probe lands in one of
three buckets, never collapsed into real-versus-spurious:

| bucket | meaning |
|---|---|
| `no_dci` | a targeted search for that RNTI found no DCI at all |
| `crc_fail` | DCI found, transport block did not decode — **inconclusive** |
| `crc_pass` | decoded: the DCI is real |

`crc_fail` proves nothing on its own. srsRAN cannot predecode spatial multiplexing on a
4-port cell, the MCS→TBS table is per-UE state a sniffer cannot see (which is why the probe
honours `qam_retry`), the signal may be weak, and an `rv > 0` retransmission needs HARQ
combining across TTIs that this does not do.

**What to read from it.** Not a per-DCI verdict but the *difference in pass rate* between the
two populations. The RACH-confirmed column is the baseline for known-real UEs on that
capture, which is well below 100% for the reasons above. The unconfirmed column is then a
**lower bound** on real UEs the RAR anchor missed — UEs already connected before capture
started, and handover-in, which
[docs/security-measurement.md](security-measurement.md) records as invisible from the target
cell alone. Those are missing from every denominator the security measurement reports.

Results are **not** written to the MAC pcapng, deliberately: those frames would be attributed
to RAR-anchored sessions by `tools/security_scan.py` and would change `n_pdus` and possibly an
outcome, contaminating the measurement this is meant to inform.

### Measured: `att_850_office`, 30 s, `rach_filter_only = false`

| | RACH-confirmed | not confirmed |
|---|---|---|
| distinct RNTIs probed | 47 | 5,114 |
| RNTIs with ≥1 CRC-passing block | **45 (95.7%)** | **54 (1.1%)** |
| RNTIs with ≥3 passing blocks | 43 | 43 |
| passing blocks | 331 | 446 |
| passing-block TBS, median / mean | 88 / 278 | 144 / 603 |
| appear in `rar_log` | 45 | **0** |

Read per **RNTI**, not per block: the block-level pass rates (24.3% vs 1.5%) are depressed on
both sides by `rv > 0`, MIMO and weak signal, and are not the interesting quantity.

**Blind mode is overwhelmingly noise — and not entirely.** 5,060 of 5,114 unconfirmed RNTIs
produced no decodable block at all, which is what `rach_filter_only` exists to remove. But 54
did, and 43 of those produced three or more. Three independent CRC24A passes under one RNTI is
a 2⁻⁷² coincidence, so those are real UEs, and **none of them appears in `rar_log`**.

They are real UEs the RAR anchor structurally cannot see — already connected when the capture
started, or handed over in. Their traffic profile says the same thing: larger transport blocks
than the RACH-confirmed population, which is what an established session in data transfer looks
like next to a UE still doing signalling. The clearest case on this capture is RNTI 10649, with
81 passing blocks spanning 17.8 s — the same RNTI ngscope's own teardown names as the busiest
downlink UE on the cell, and it is absent from every denominator the security measurement
reports.

### These UEs are positive evidence, not missing failures

A first reading is that they are unobservable — no RAR, so no anchor, so nothing to measure.
That is wrong, and the `ch` column shows why. The probe walks the DL-SCH subheaders of every
passing block (36.321 6.1.2) and classifies the logical channel:

| passing blocks by channel | RACH-confirmed | not confirmed |
|---|---|---|
| `ccch` | 44 | 17 |
| `srb` | 152 | 158 |
| **`drb`** | **23** | **168** |
| `other` (MAC CE, padding) | 112 | 103 |
| **RNTIs with ≥1 DRB block** | **11** | **15** |

**A DRB cannot exist without AS security.** It is configured by an
`RRCConnectionReconfiguration`, which the eNB may only send after a completed
`SecurityModeCommand` — including the unauthenticated-emergency case, which still runs
security mode establishment, just with the null algorithms. So a CRC-passing DRB block is
itself proof that that UE established an AS security context *with this cell*. The boundary
happened before the capture started; the consequence of it is still on the air.

So on this capture 15 UEs have **demonstrated** AS security with the cell and appear in no
denominator the security measurement reports. The published figure was 22/68 = 32.4%. Counting
what is actually observable gives 37 UEs with demonstrated security, against 83 seen at all.

This is the same error as counting `outcome=reused` as a failure, which
[security-measurement.md](security-measurement.md) already warns is backwards:
`SecurityModeCommand` is *one* observation of security establishment, not the only one.
Reestablishment and resume are a second. DRB traffic is a third.

The remaining honest caveat is the one-sidedness above: absence of a DRB block is not absence
of security, so 15 is a floor on this population, not a count.

Cost on the same capture: 40.6 s → 42.6 s of replay, about **+5%**. Lower than the ~8×
decode-attempt figure suggests, because two thirds of probes end at the targeted PDCCH search
without ever reaching a PDSCH decode.

---

## Removed settings

**Old configs keep working.** Both backends look up only the keys in the schema, so a key
the program no longer asks for is ignored rather than rejected. Nothing has to be edited out
of an existing `.cfg` or `.toml`.

### `rnti` and `decode_single_ue`

`rnti` named one UE — the "target RNTI" — and `decode_single_ue` decoded only that UE. Both
are gone, along with everything that treated the named UE differently from any other. It was
the last key marked required, so no key is required today.

Three decode paths gave the target RNTI preferential treatment, and all three are now
disabled by passing 0 rather than deleted, so a future per-UE feature can reuse them:

| site | what it did |
|---|---|
| `match_two_dci_vec()` (`ngscope_tree.c`) | accepted a candidate on an RNTI match alone, skipping the child-parent agreement check every other candidate has to pass |
| `srsran_ngscope_tree_prune_node()` | short-circuited format selection for that RNTI |
| `srsran_ngscope_tree_copy_rnti()` | lifted its DCIs straight into the output, bypassing pruning entirely |

Each is now guarded on `targetRNTI > 0`, which is **required rather than defensive**: an
unfilled tree slot has `rnti == 0`, so an unguarded zero target would match every empty node.
That is the hazard the old "`rnti = 0` is not inert" warning described.

`srsran_ngscope_decode_dci_singleUE_yx()` (`lib/src/phy/ue/ngscope.c`) is likewise kept and
uncalled; `srsran_ue_decode_dci_yx()` beneath it already returns 0 for a zero RNTI.

**What it changed, measured.** Same 20 s prefix of the Verizon reference capture
(`verizon_66636/…/2026_08_13_15_31_42`, PCI 56, 100 PRB), same config, one build before the
removal and one after:

| | before | after |
|---|---|---|
| DL records, non-zero RNTI | 25,214 | 25,205 |
| UL records, non-zero RNTI | 5,815 | 5,815 |
| records for `rnti = 9185` | 12 | 0 |
| replay wall time | 23.66 s | 23.66 s |

Diffed on `(tti, rnti)`, the *only* records the old build had and the new one does not are
those 12 — nothing else was lost, and the uplink is identical. The new build gained three
records, for RNTIs 12379, 26160 and 38195. That is the shortcut's real cost: at TTI 1716 the
old build reported 9185 on 60 PRB where the new one reports 12379 on 100 PRB, so the
preference was not merely adding a phantom UE, it was displacing a candidate that passed the
child-parent check.

9185 appears in **none** of that run's 30 RARs — it is a stale value carried in every shipped
config from a T-Mobile capture, and the cell it was being reported on had never assigned it.

Two consumers of the target elsewhere are guarded the same way and stay in place:
`push_dci_to_remote()`, which fed one named UE to the DCI sink, and the `ue_dl_prb` /
`ue_ul_prb` fields in the ring buffer, which nothing read.

### `log_phich`

Still accepted, but `ngscope_config_finalize()` forces it off with a warning.

PHICH carries the eNB's HARQ feedback for a UE's PUSCH, and it is the only way a downlink
sniffer can observe a *non-adaptive* uplink retransmission — on a NACK the UE retransmits on
the same resources with no new grant, so nothing appears on the PDCCH. Adaptive
retransmissions do carry a fresh grant and are still logged for every UE via `TB1_rv` /
`TB1_ndi`; none of that changed.

It went with the target RNTI because it could only ever follow that one UE, and because of
what it wrote:

- `pend_ack_list` (`phich_decoder.h`) holds exactly one `(I_lowest, n_dmrs)` per TTI, so it
  is structurally single-UE.
- On a NACK the caller **synthesised** a UL DCI — `rnti = target, rv = 4, prb = 0, tbs = 0,
  decode_prob = 100` — and pushed it into `dci_per_sub`, so it reached the `.dciLog`
  indistinguishable from a real grant except by that signature. In one recorded capture 34
  of the 63 UL records for the target RNTI were synthetic.
- ACKs were decoded and discarded. Only NACKs produced output.
- `ack_list` is a single global shared by every decoder thread and every RF device, and the
  read and reset in `decode_phich()` do not hold `ack_mutex` — a live race at
  `nof_thread > 1`.

`dci_decoder_phich_decode()` and `phich_decoder.c` are kept intact and uncalled, with
`targetRNTI` now a parameter rather than a config read so the function still compiles. A
useful revival needs all four fixed: a per-RNTI pending-ack list, a separate PHICH log
instead of injection into the DCI stream, ACKs recorded as well as NACKs, and per-device
state. Since nothing writes an `rv == 4` record any more, and that is the only thing
`log_phich_subframe()` reports, leaving the key enabled would produce a log of empty filler
records — which is why it is forced off rather than left as a silent no-op.

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

`security_sessions-<rf_idx>.csv` carries the radio clock throughout: `rar_ct` /
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

> For the measurement this setting exists to support, and how to read its output, see
> [security-measurement.md](security-measurement.md).


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
- **`.dciLog` files contain a zero-filled placeholder record for every TTI with no DCIs**, so
  the record count is not the DCI count. Filter on `"rnti"` ≠ 0.
- **Long `-o` paths are silently truncated** at 128 characters.
- **Duplicate `rf_freq` across devices is fatal**, because log files are named by frequency.
