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

### A second cell, for scale

An 80 s AT&T capture (PCI 405, 100 PRB, 2 ports) gives **234 / 692 = 33.8%** — close to the band
12 figure from a different network, bandwidth and antenna configuration. Its PDSCH decode rate
is higher (61.7% against 58.9%), which is the 2-port/4-port difference rather than a better
receiver. Two cells is not a baseline, but it is a second point: `docs/security-implementation.md`
§9 has the full breakdown.

---

## Reading the numbers

A run prints four lines at teardown. All four matter.

```
SECURITY (cell 0): 1318 RNTIs anchored by a RAR, 424 with a SecurityModeCommand (32.2%).
                   PDSCH attempts 8122, decoded 4780 (58.9%), RRC unpacked 1622 (20.0%).
SECURITY (cell 0): tracking high-water 57 of 512 slots, no UE dropped for want of a slot
SECURITY (cell 0): tracking exits -- 0 on SecurityModeCommand, 872 on the 10 s window;
                   948 drops averted where a decoder thread was behind the RAR
SECURITY (cell 0): DCCH SDUs -- 467 unpacked (2 of them reassembled), 556 RLC control;
                   unread: 0 segmented, 2 unsupported, 0 short, 26 ciphered/unparseable;
                   1 partial SDU(s) LOST before completing
```

Lines 1-3 are the 300 s band 12 reference capture; line 4 is from the 80 s AT&T capture, since
the DCCH accounting postdates the reference run.

- **Line 1** is the result. `PDSCH decoded` is the receiver's hit rate; `RRC unpacked` is how
  often a decoded transport block actually contained readable RRC.
- **Line 2 is a validity condition, not decoration.** A UE dropped for want of a tracking slot
  is indistinguishable in the output from a UE that never reached security. The detection rate
  can only be read as a property of the cell while this line says *no UE dropped*. If it
  reports evictions or a tracked-but-unscanned count, the rate is an undercount of unknown
  size.
- **Line 3** breaks down why UEs left the tracked set. `on the 10 s window` is the honest
  timeout. `drops averted` counts a bug class that used to discard UEs silently.
- **Line 4 is the other validity condition.** It accounts for every DL-DCCH SDU the decoder saw.
  `RLC control` is a STATUS PDU, which carries no SDU and is not a loss;
  `ciphered/unparseable` is overwhelmingly post-security traffic and is expected. Everything
  else after `unread:` is an RRC message that existed and was not read, and **any of them could
  have been a SecurityModeCommand** — so they bound how much boundary evidence went missing.
  `segmented` should be 0 on a replay, where reassembly is on; `unsupported` is now only
  re-segmented PDUs and should be near zero. A `partial SDU(s) LOST` clause means reassembly
  held pieces whose partners were never decoded — you cannot rejoin what you never received.

The cheapest external check on all of this: run `reordercap` on the pcap and count distinct
RNTIs carrying a SecurityModeCommand. It should equal the SMC count on line 1.

```bash
reordercap mac-0.pcapng sorted.pcapng
tshark -r sorted.pcapng -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""' \
  -Y 'lte-rrc.securityModeCommand_element' -T fields -e frame.comment \
  | grep -o 'rnti=0x[0-9a-f]*' | sort -u | wc -l
```

Two traps in that one command. Reorder first, because Wireshark cannot reassemble RLC from
records written in decode-completion order. And filter on the field, never on the Info column:
`_ws.col.Info` carries one summary per frame and the last SDU in a MAC PDU overwrites the
others, which is enough to hide half the SecurityModeCommands in a capture.

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
`task_scheduler.txt` on live runs. This is also why RLC reassembly is enabled for replay only:
holding a partial SDU is sound where nothing goes missing, but a discarded middle segment leaves
a partial that never completes, which looks exactly like a UE that never reached security.

**Cell antenna configuration sets a hard ceiling.** srsRAN cannot predecode spatial
multiplexing on a 4-port cell at any receive-antenna count — the same gap exists in LTESniffer,
which builds on a byte-identical `precoding.c`. On the cell measured here (4-port), 91.3% of
grants are single transport block and decodable with one antenna; the remaining 8.7% are
unreachable. `cell_type.json` records `nof_ports` for exactly this reason. On a **2-port** cell
a second receive antenna is transformative, unlocking two-layer traffic entirely; on a 4-port
cell it only improves SNR on grants already being attempted.

**No HARQ soft combining.** Retransmissions with `rv != 0` are decoded standalone or not at
all.

**The 256QAM table is a guess — but replay no longer has to guess.** 36.213 permits it only
when the cell configures `altCQI-Table-r12`, which is **per-UE** RRC state a sniffer cannot see,
so no single `enable_256qam` value can be right for every UE on a cell. It sets the `tbs` values
in the `.dciLog` files, so a wrong guess corrupts throughput figures *and* guarantees transport
block CRC failure.

Two mechanisms address this, and they answer different questions:

- **The TBS probe** checks the guess against physics — an effective code rate above 1 is
  impossible — and prints a verdict at teardown. It works off DCI alone, so it runs live too,
  but it is an inference about the cell as a whole.
- **In replay, the decoder tests the table per grant.** When a transport block fails its CRC the
  grant is rebuilt on the other table and decoded again, keeping whichever passes. The CRC is
  ground truth, so this measures rather than infers, and it is per grant, which is the only way
  to be right when the setting is per-UE. Replay-only: it costs a second PDSCH decode per
  failure, affordable exactly where the scheduler blocks instead of dropping subframes.

The teardown line reports what the traffic actually needed:

```
SECURITY (cell 0): MCS->TBS table -- 2199 transport blocks decoded, 101 of them (4.6%)
                   only after falling back to the other table
```

Measured with `enable_256qam = true` (the default) against the same captures decoded with each
table pinned:

| capture | pinned 256QAM | pinned 64QAM | 256QAM + retry | blocks retried |
|---|---|---|---|---|
| `att_trolley` | 234 / 692 = 33.8% | 271 / 692 = 39.2% | **271 / 692 = 39.2%** | 4.6% |
| `mt_airy02/5110` | 12 / 26 = 46.2% | 13 / 26 = 50.0% | **13 / 26 = 50.0%** | 45.2% |
| `verizon_66636` | 52 / 96 = 54.2% | 52 / 96 = 54.2% | **52 / 96 = 54.2%** | 0.0% |

The retry matches the better pinned setting on every capture without being told which it is, and
`verizon_66636` is the control: the probe called it inconclusive there, and the retry confirms
that by rescuing nothing at all. Note how little the retried *fraction* predicts the effect —
4.6% of blocks on the trolley capture is worth 37 extra SecurityModeCommands, because the
affected grants are where the boundary evidence lives.

**Not every DL-DCCH SDU can be read, and the ones that cannot are counted.** An SDU split
across grants is rejoined on replay only; behind a length-indicator list it is not read at all;
re-segmented PDUs are not handled. Line 4 of the teardown report is the size of that blind spot.
What remains unread is `unsupported` (re-segmented PDUs, whose segment-offset header is not
parsed) and fragments whose other pieces were never decoded. Both are counted.

How much this matters is entirely cell-dependent, so read the line rather than carrying a figure
over from another capture. Segmentation and concatenation were rare on one AT&T capture — 9 of
428 AM data PDUs were segments — and constant on another, 48 of 100. Reading the
length-indicator chain changed nothing at all on the first cell and doubled the measured rate on
the second, from 23.1% to 46.2%.

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

The join is not optional bookkeeping — it is the authoritative labelling, because the
in-stream `security_phase` can only mark a fraction of the pre-security DCIs. Forgetting it
does not fail loudly, it just under-reports. In the GUI, **Security context → Join after the
run** does it automatically when ngscope exits, streaming the output into the same console.
It is skipped, with a reason in the console, if `mark_security_phase` was off or no run
directory was seen, and it does not run between sweep channels, where it would compete for
CPU with the next channel's capture.

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

The join sorts `pcap_joined/` through `reordercap` by default (`--no-reorder` opts out and
keeps the byte-identical patch, which is what the regression gate checks). A raw
`mac-<rf>.pcapng` that has not been joined is still in decode-completion order.
