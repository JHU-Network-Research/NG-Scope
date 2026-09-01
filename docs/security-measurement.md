# Measuring AS security establishment

NG-Scope can report, for each UE that attempts to attach to a cell, how far it got —
in particular whether it reached **AS security establishment**. This document explains what
is measured, how to read the numbers, and what limits their accuracy.

The motivating use is **IMSI-catcher detection**. A legitimate UE cannot complete AS security
with a fake base station, because the fake eNB cannot derive `K_eNB` or produce a valid
`SecurityModeCommand`. A cell where UEs attach but never reach security is the signature.
The same measurement is useful for ordinary network characterisation.

---

## What is observable, and why

`SecurityModeCommand` travels **downlink** and is integrity-protected but **not ciphered**, so
a downlink-only sniffer can read it. That single fact is what makes this measurable without
an uplink receiver.

The boundary is observed, never inferred. Nothing is deduced from elapsed time or grant
counts, and a UE that cannot be placed is reported as `unknown` rather than assumed. That
matters because the RAR-to-SecurityModeCommand delay is not a constant — measured on a band
12 cell it ranged from **45 ms to 1855 ms** (median 68 ms), so no fixed window would work.

---

## The funnel

Each stage is evidence of a different thing, and the gaps between them mean different things.

| stage | evidence | 300 s band 12 capture |
|---|---|---|
| attempted attach | a RAR handed out a Temporary C-RNTI | **1318** |
| got scheduled | any DCI for that RNTI | 1085 |
| RRC connected | `RRCConnectionSetup` decoded | 302 |
| **reached AS security** | `SecurityModeCommand` decoded | **424\*** |

\* More SecurityModeCommands than RRCConnectionSetups, because Msg4 and the SMC are separate
decode opportunities and either can be missed independently. Do not read the rows as nested
subsets; each is an independent observation of the same population.

**The headline ratio is 424/1318 = 32.2%.**

### Which denominator to use

`424/1318` mixes two very different things: UEs that genuinely never reached security, and
UEs we simply failed to observe. For deciding whether a *cell* is behaving normally, the
conditional ratio is better conditioned — of the connections we could actually follow, what
fraction completed security. Against a catcher that ratio collapses toward zero, whereas the
raw 32.2% would also fall if the receiver were merely having a bad day.

Report both, and never quote either without the coverage counters below.

---

## Reading the numbers

A run prints three lines at teardown. All three matter.

```
SECURITY (cell 0): 1318 RNTIs anchored by a RAR, 424 with a SecurityModeCommand (32.2%).
                   PDSCH attempts 8122, decoded 4780 (58.9%), RRC unpacked 1622 (20.0%).
SECURITY (cell 0): tracking high-water 57 of 512 slots, no UE dropped for want of a slot
SECURITY (cell 0): tracking exits -- 0 on SecurityModeCommand, 872 on the 10 s window;
                   948 drops averted where a decoder thread was behind the RAR
```

- **Line 1** is the result. `PDSCH decoded` is the receiver's hit rate; `RRC unpacked` is how
  often a decoded transport block actually contained readable RRC.
- **Line 2 is a validity condition, not decoration.** A UE dropped for want of a tracking slot
  is indistinguishable in the output from a UE that never reached security. The detection rate
  can only be read as a property of the cell while this line says *no UE dropped*. If it
  reports evictions or a tracked-but-unscanned count, the rate is an undercount of unknown
  size.
- **Line 3** breaks down why UEs left the tracked set. `on the 10 s window` is the honest
  timeout. `drops averted` counts a bug class that used to discard UEs silently.

### Per-packet phases

The pcap and the `.dciLog` files label each record `pre`, `post`, `unknown` or `n/a`:

| value | meaning |
|---|---|
| `pre` | before this UE's SecurityModeCommand |
| `post` | after it |
| `unknown` | a UE whose boundary was never observed — **not** evidence of anything |
| `n/a` | not a UE identity (SI-RNTI, P-RNTI, RA-RNTI), so no security context exists |

`unknown` and `n/a` are deliberately distinct. `unknown` is the number that bounds how much of
the capture is unaccounted for; folding broadcast traffic into it overstates that by more than
half.

**Most records are `unknown` when written.** The boundary is the SecurityModeCommand, which
arrives *after* the packets it bounds, so the live label can only ever be a partial
approximation. Run the join afterwards — it placed 2,310 packets against 124 in-stream on the
capture above.

---

## Two clocks, and which to trust

Every artefact carries both:

- **`timestamp` / `timestamp_us`** — host wall clock, taken when a decoder thread picked the
  subframe up.
- **`collection_time`** — the radio domain, from the SDR or the recording.

**Use `collection_time` for anything plotted against time.** In replay the wall clock advances
at *decode* speed, not capture speed. The 300 s capture above decodes in 434 s, so bucketing
by wall clock stretches a five-minute capture into eight and misallocates UEs between buckets.

The distortion is not small. On 104 boundaries, the wall-clock RAR-to-SMC delay overstated the
true figure by **26.5 ms at the median and up to 1046 ms**. Measured in the radio domain the
delta matches the TTI difference exactly in 104 of 104 cases, as it must, since one TTI is one
millisecond.

`rar_to_smc_ms` in `security_log-<rf_idx>.csv` is computed from collection times and is
therefore the real over-the-air delay.

### Worked example: the same capture, bucketed both ways

| min | RARs | SMCs | rate | | RARs | SMCs | rate |
|---|---|---|---|---|---|---|---|
| | *capture time* | | | | *decode time* | | |
| 0 | 315 | 107 | 34.0% | | 238 | 76 | 31.9% |
| 1 | 215 | 92 | 42.8% | | 163 | 74 | 45.4% |
| 2 | 288 | 80 | 27.8% | | 159 | 64 | 40.3% |
| 3 | 305 | 68 | 22.3% | | 193 | 46 | 23.8% |
| 4 | 195 | 77 | 39.5% | | 200 | 41 | 20.5% |
| 5–7 | — | — | — | | 365 | 123 | 26–43% |
| **total** | 1318 | 424 | **32.2%** | | 1318 | 424 | 32.2% |

Only the total is unaffected. The decode-time view invents three minutes that do not exist and
puts minute 4 at 20.5% instead of 39.5%.

**Implication for detection:** on this cell the rate varies between 22% and 43% minute to
minute with no trend. That variance is the noise floor. A single minute below ~22% means
nothing; a five-minute aggregate is far tighter.

---

## Operating mode

`rach_filter_only` selects between two different decoders, and for this measurement only one
of them is sound.

| | `false` (blind) | `true` (RACH-gated) |
|---|---|---|
| RNTI source | recovered from the descrambled PDCCH CRC | observed in a RAR |
| 60 s capture | 53,953 DCIs, 6,369 RNTIs | 25,760 DCIs, 188 RNTIs |
| false RNTIs | many | essentially none |

Blind mode manufactures RNTIs: a false alarm yields a uniformly distributed 16-bit value. It is
right for cell-level load measurement, where the aggregate matters and per-UE attribution does
not. **For anything per-UE, use `rach_filter_only = true`.** Every UE relevant to attach
behaviour performs RACH within the capture by definition.

This is also the model LTESniffer uses — it searches each known UE's search space rather than
sweeping blind. One deliberate difference: NG-Scope admits an RNTI on the RAR alone, whereas
LTESniffer waits for `RRCConnectionSetup` to confirm it. NG-Scope's looser rule keeps UEs that
attempted and never got further, which is precisely the population that distinguishes a fake
base station from a real one.

---

## What limits accuracy

**No uplink.** AS security actually activates at `SecurityModeComplete`, which is uplink and
invisible. The observed boundary is the SecurityModeCommand a few milliseconds earlier, so it
is early by construction.

**Absence of evidence is what the detector runs on, and it is not free.** A missed subframe and
a UE that never received an SMC produce identical output. Under live capture the scheduler
discards subframes when every decoder is busy, leaving holes with no marker. **Replay blocks
instead of dropping, so only replay yields a coverage figure that means anything.** Cross-check
`task_scheduler.txt` on live runs.

**Cell antenna configuration sets a hard ceiling.** srsRAN cannot predecode spatial
multiplexing on a 4-port cell at any receive-antenna count — the same gap exists in LTESniffer,
which builds on a byte-identical `precoding.c`. On the cell measured here (4-port), 91.3% of
grants are single transport block and decodable with one antenna; the remaining 8.7% are
unreachable. `cell_type.json` records `nof_ports` for exactly this reason. On a **2-port** cell
a second receive antenna is transformative, unlocking two-layer traffic entirely; on a 4-port
cell it only improves SNR on grants already being attempted.

**No HARQ soft combining.** Retransmissions with `rv != 0` are decoded standalone or not at
all.

**The 256QAM table is a guess.** 36.213 permits it only when the cell configures
`altCQI-Table-r12`, which is per-UE RRC state a sniffer cannot see. It sets the `tbs` values in
the `.dciLog` files, so a wrong guess corrupts throughput figures *and* guarantees transport
block CRC failure. NG-Scope now checks the guess against physics — an effective code rate above
1 is impossible — and reports a verdict at teardown. On the cell measured here the 64QAM table
is **7.8× cleaner**, meaning `enable_256qam = true` is wrong for it.

**Null ciphering (EEA0).** Post-security traffic stays readable, so a `sec=post` packet that
still parses is not a contradiction.

---

## Running a measurement

```toml
rach_filter_only    = true     # per-UE analysis requires this
mark_security_phase = true     # implies decode_RAR
pcap_mac            = true     # optional: the evidence trail

[[rf_config]]
mode          = 2              # replay: lossless, so coverage figures mean something
replay_fname  = "capture.bin"
nof_thread    = 8
```

Then:

```bash
ngscope -c config.toml -o out/
cd out/<timestamp>/
tools/security_phase_join.py . -f all
```

Outputs:

| file | contents |
|---|---|
| `security_log-<rf>.csv` | one row per observed boundary, both clocks, `rar_to_smc_ms` |
| `security_phase.csv` | every DCI with its joined phase and derived deltas |
| `dci_output_joined/` | the `.dciLog` files with corrected phases |
| `mac-<rf>.pcapng` | decoded MAC PDUs — see [pcap.md](pcap.md) |
| `pcap_joined/` | the same, with corrected phases |
| `rar_log-<rf>.csv` | one row per RAR — the funnel's denominator |
| `cell_type.json` | `nof_ports`, `nof_prb`, `nof_rx_ant` — what was decodable in principle |

Run `reordercap` on the pcap before any RLC/PDCP-level analysis; records are written in
decode-completion order, not TTI order.
