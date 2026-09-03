# Measuring AS security establishment

NG-Scope can report, for each UE that attempts to attach to a cell, how far it got —
in particular whether it reached **AS security establishment**. This document explains what
is measured, how to read the numbers, and what limits their accuracy.

The motivating use is **IMSI-catcher detection**. A legitimate UE cannot complete AS security
with a fake base station, because the fake eNB cannot derive `K_eNB` or produce a valid
`SecurityModeCommand`. A cell where UEs attach but never reach security is the signature.
The same measurement is useful for ordinary network characterisation.

**Before the first run**, check that tshark is set up: detection is offline, so every number
below comes from Wireshark dissecting `mac-<rf>.pcapng`. Only two things are needed — tshark
with `reordercap`, and, on Ubuntu, an AppArmor allowance for capture files under `$HOME`. The
DLT mapping is passed by the tool and the LTE dissector defaults are already correct.
[docs/pcap.md § What tshark needs](pcap.md#what-tshark-needs) has the one-command check and
the recipe.

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

### UEs that could never have shown a boundary

Not every UE in the denominator was ever going to produce a SecurityModeCommand. Two RRC
procedures restore a stored `K_eNB` instead of deriving a fresh one, and neither is followed by
an SMC:

| procedure | channel | why no SMC |
|---|---|---|
| `RRCConnectionReestablishment` | DL-CCCH (SRB0) | the UE presented a `shortMAC-I` derived from its stored `K_RRCint` and the network accepted it |
| `RRCConnectionResume-r13` | DL-DCCH | the context was stored at suspend and restored |

Counting these as failures is not just imprecise, it is backwards: reaching either point is
*positive* evidence that the UE held a real AS context with this network, which a fake base
station cannot manufacture. NG-Scope records them and reports the corrected ratio:

```
SECURITY (cell 0): context reuse -- 2 re-establishment, 2 resume. 3 of those 4 never showed
                   a boundary and cannot; excluding them, 271 of 689 (39.3%)
```

Reported rather than silently subtracted, because the raw ratio is what earlier captures were
quoted with and the correction has to be auditable. On the trolley capture it moves the figure
by 0.1 points — but on a cell with heavy radio-link failure, or a Rel-13 suspend/resume
deployment, the same correction could be large, and without it you would read a healthy cell as
a suspicious one.

Handover-in is the third such case and is **not** detected: the target cell reuses via NH/NCC,
but the command saying so is sent by the *source* cell, so from here it is indistinguishable
from a failed attach.

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

Two tools report, and they answer different questions.

**ngscope, at teardown: coverage only.** It no longer knows anything about security, so it
reports how well it decoded and nothing about what it decoded:

```
SECURITY (cell 0): 692 RNTIs anchored by a RAR. PDSCH attempts 11953, decoded 8068 (67.5%)
                   -- written to the MAC pcap; run tools/security_scan.py over it for the
                   detection rate.
SECURITY (cell 0): tracking high-water 93 of 512 slots, no UE dropped for want of a slot
SECURITY (cell 0): tracking exits -- 656 on the 10 s window; 283 drops averted where a
                   decoder thread was behind the RAR
SECURITY (cell 0): MCS->TBS table -- 8068 transport blocks decoded, 284 of them (3.5%) only
                   after falling back to the other table
```

**Lines 2 and 3 are validity conditions, not decoration.** A UE dropped for want of a tracking
slot is indistinguishable *in the pcap* from a UE that never reached security, so whatever the
scan concludes can only be read as a property of the cell while these say *no UE dropped*.

**`security_scan.py`: the result.**

```
### mac-0.pcapng  (rf 0)
  frames            : 8,760   8760 frames, 1370 out of order
  RAR cross-check   : rar_log 692 vs wireshark 692  identical=True
  comment vs dissect: 0 mismatches
  sessions          : established=271, in_progress=33, no_traffic=367, none=1, released=17, reused=3
  rate              : 271/692 = 39.2% of all RACHing UEs
                      271/325 = 83.4% of those we decoded any traffic for
  events            : securityModeCommand=297, rrcConnectionSetup=333, nasTauReject=65, ...
```

**Both rates, always.** `no_traffic` counts UEs for which not one transport block was decoded;
dropping them says something about the receiver, but it also drops UEs that RACHed and
genuinely did nothing, so the second figure is an upper bound rather than a correction.
Quoting only one of them moves the headline by 40 points.

**The first two lines are the cross-checks.** `RAR cross-check` compares srsRAN's RAR parse
against Wireshark's on the same bytes — the only place two independent parsers still meet, and
it validates the denominator, where an error silently changes the rate. `comment vs dissect`
compares the RNTI ngscope wrote into every packet comment against the one Wireshark dissected,
on 100% of records, which catches pcap framing drift.

### Per-packet phases

The pcap and the `.dciLog` files carry the same seven values, written by the join. The pcap's
`sec=` field is padded to exactly 7 characters, which is what makes patching it a byte splice,
so nothing longer can ever be added:

| value | meaning |
|---|---|
| `pre` | before this UE's SecurityModeCommand (inclusive — the SMC is the last cleartext message) |
| `post` | after it |
| `reused` | the UE resumed a context it already held (re-establishment or resume), so no boundary was ever going to exist here |
| `noctx` | the network refused the connection, so no context was created |
| `none` | the UE was watched, traffic was decoded, and no security evidence appeared |
| `unknown` | could not be placed: no traffic decoded, or still in progress when the window closed |
| `n/a` | not a UE identity (SI-RNTI, P-RNTI, RA-RNTI), so no security context exists |

**`none` and `unknown` are the pair that matters.** `none` is a measurement — the thing an
IMSI-catcher would produce — and `unknown` is the absence of one. Collapsing them hides the
detection behind the coverage gap.

**Zero boundaries is a result, not a missing file.** `tools/security_scan.py` writes its three
files with headers before anything that can fail, so "nobody on this cell reached security" is
an empty table rather than an absence. That distinction is the whole point for IMSI-catcher detection, and it is now better
supported than it used to be: `security_sessions` carries `n_pdus` per session, so the claim
becomes "8,068 transport blocks decoded across 692 UEs and not one carried a
SecurityModeCommand" rather than just an empty file. Read it alongside the RAR count and the
coverage lines before concluding anything — zero boundaries with zero RARs means nothing was
seen at all.

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

`ms_rar_to_outcome` in `security_sessions-<rf_idx>.csv` is computed from collection times and
is therefore the real over-the-air delay. The join keys on `collection_time` throughout for the
same reason.

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

**RLC coverage is now Wireshark's problem, and it reports on itself.** ngscope used to do its
own reassembly and length-indicator walking, and the SDUs it could not read were the blind spot.
That whole path is gone: Wireshark reassembles across grants and walks LI chains natively, so
the only DL-DCCH left unread is a re-segmented PDU (`RF = 1`, whose segment-offset header is not
parsed — 2 across the trolley capture, 0 elsewhere) and fragments whose other pieces were never
decoded at all.

`security_events-<rf>.csv` carries `rlc_segments` and `rlc_skipped` per row, from
`rlc-lte.reassembly-info.number-of-segments` and `rlc-lte.sequence-analysis.skipped-frames`.
That is a strict upgrade on the old accounting, because it is computed by a different
reassembler than the one that produced the bytes.

How much this matters is entirely cell-dependent. Segmentation and concatenation were rare on
one AT&T capture — 9 of 428 AM data PDUs were segments — and constant on another, 48 of 100. The
retired parser scored 23.1% on the second where Wireshark reads 50.0% from the same bytes.

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
| `security_events-<rf>.csv` | one row per indicator occurrence found by `security_scan.py` — RRC and NAS, with the tshark field that fired and the frame number in `pcap_joined/` |
| `security_sessions-<rf>.csv` | one row per RAR-anchored session: the funnel and the denominator. Seeded from `rar_log`, so a UE with no evidence still has a row |
| `security_summary.json` | provenance (tshark version, fields queried), the validity checks, per-cell counts and both rates |
| ~~`security_reuse-<rf>.csv`~~ | *retired* — reuse is now an `outcome` value in `security_sessions`. Was: one row per UE seen resuming an AS context it already held — `RRCConnectionReestablishment` or `RRCConnectionResume-r13`. These never send a SecurityModeCommand, so they do not belong in the denominator |
| ~~`security_log-<rf>.csv`~~ | *retired*, replaced by `security_sessions-<rf>.csv`. The zero-boundary rule carries over: `security_scan.py` writes its three files with headers before anything that can fail, so a header-only file means "scanned, found nothing" — the result of interest here — and an absent file means the run was never scanned |
| `security_phase.csv` | every DCI with its joined phase and derived deltas |
| `dci_output_joined/` | the `.dciLog` files with corrected phases |
| `mac-<rf>.pcapng` | decoded MAC PDUs — see [pcap.md](pcap.md) |
| `pcap_joined/` | the same, with corrected phases |
| `rar_log-<rf>.csv` | one row per RAR — the funnel's denominator |
| `cell_type.json` | `nof_ports`, `nof_prb`, `nof_rx_ant` — what was decodable in principle |

The join sorts `pcap_joined/` through `reordercap` by default (`--no-reorder` opts out and
keeps the byte-identical patch, which is what the regression gate checks). A raw
`mac-<rf>.pcapng` that has not been joined is still in decode-completion order.
