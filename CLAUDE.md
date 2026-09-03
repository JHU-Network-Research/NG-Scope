# NG-Scope — working context

srsRAN_4G 23.04 with an LTE control-channel sniffer (`ngscope/`) grafted on. Current work adds
downlink MAC payload decoding, pcapng output, and per-UE AS-security-state tracking, for
**IMSI-catcher detection**: a legitimate UE cannot establish an AS security context with a fake
base station, so "did this UE reach security?" is the signal.

Read these before changing anything in that area — they are current and detailed:

| document | for |
|---|---|
| `docs/security-implementation.md` | what was changed and why, bugs found, decisions **not** to re-litigate, known gaps |
| `docs/security-measurement.md` | how to take a measurement and read the numbers |
| `docs/pcap.md` | pcap format and the Wireshark setup it needs |
| `docs/configuration.md` | every setting; schema lives in `ngscope/hdr/dciLib/load_config.h` |

---

## Build and test

**Builds natively on the host** — UHD 4.9, FFTW 3.3.10, libconfig++ and mbedtls are installed,
and `build/` is already CMake-configured. Do not use Docker here.

```bash
cd build && make -j"$(nproc)" ngscope    # binary lands at build/ngscope/src/ngscope
```

`build/` is gitignored; re-run `cmake ..` only after adding a source file outside the `dciLib`
glob.

*Historical note, because it still shows in the tooling:* this work started on a Mac with
neither UHD nor FFTW, where every build went through the `amarder89/ng-scope:gui` container
(amd64 under emulation) against a `build-docker/` tree. `Dockerfile` is that image's provenance,
and `measurements/run.sh` still hard-codes the container's `/src/...` paths. The container
remains the fallback on a host that genuinely cannot build — it is not the path here.

`tshark` and `capinfos` are on the host too, so validating a pcap is a straight local step with
no write-inside/inspect-outside split. `tshark` needs the DLT mapping every time:

```bash
tshark -r mac-0.pcapng -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
```

**`tshark` is confined by AppArmor and cannot read `$HOME` out of the box** -- the profile at
`/etc/apparmor.d/tshark` allows `/tmp` and `/usr/share/wireshark` only, so a run directory
under `~/ngscope-data/` fails with a *permission* error while `ls -l` looks fine and `cat`
works. Widened here via `/etc/apparmor.d/local/tshark`; `docs/pcap.md` has the recipe. Only
`tshark` is confined -- `reordercap`, `capinfos` and `sharkd` are not, which is why a failing
run still produces `pcap_joined/`.

**Do not switch to `sharkd` to get around it.** Measured: with a pristine `HOME` it loads the
capture, reports `status: OK`, and dissects *nothing*, with no error -- it has no `-o`, so the
DLT mapping can only come from on-disk config. Zero events across a populated capture is this
project's positive result, so that is a phantom detection. `assert_dissected()` in
`security_scan.py` now makes it a hard error whichever tool is used.

## Measuring

**Replay, not live.** The scheduler blocks on a busy decoder in replay but *discards* subframes
live, so only replay gives a comparable yield figure. `measurements/` has the harness; its
README explains the scripts.

**The harness is not yet host-native.** `measurements/run.sh` hard-codes `/src/measurements/…`
and `/src/build-docker/ngscope/src/ngscope`, and the `*.toml` files are templates carrying
container-absolute `replay_fname` (plus `rf_freq` for whichever capture). Rewrite those to host
paths — `build/ngscope/src/ngscope` and a real capture path — before a run here.

**Captures live outside the repo.** `recordings/` is gitignored and on this machine does not
exist; the data is under `~/ngscope-data/` (`att_trolley`, `shriver`, `mt_airy02`,
`verizon_66636`, and smaller T-Mobile/Verizon sets). The reference capture below,
`tmobile_5035_poconos.bin` (13.7 GB, 300 s) with its 10 s and 60 s prefixes, is **not present
here** — the figures that follow are recorded results, not something reproducible on this box as
it stands. **Cut prefixes on frame boundaries** — `nof_samples` varies per frame, so the chain
must be walked, not strided (`rx_frame_header_t` in `ngscope/hdr/dciLib/ngscope_rx.h`).

Reference cell: band 12, EARFCN 5035, cell 44, FDD, **25 PRB, 4 ports**. The 4-port part
matters — srsRAN cannot predecode spatial multiplexing there at any antenna count, capping
what is decodable at ~91% of grants. Current result: **424 of 1318 RACHing UEs reached AS
security (32.2%)**.

Four more captures, all on this machine and all replayed clean.
`docs/security-implementation.md` §9 has the full table and the per-capture notes.

| capture | cell | rate | note |
|---|---|---|---|
| `att_trolley` | PCI 405, 100 PRB, 2 ports | 234/692 = 33.8% | no metadata sidecar; `rf_freq` can be 0 |
| `mt_airy02/earfcn-5110` | PCI 358, 50 PRB, 2 ports | 12/26 = 46.2% | segments heavily — the capture that exercises the RLC work |
| `mt_airy02/earfcn-5330` | PCI 206, 50 PRB, 4 ports | 10/97 = 10.3% | weak; read as a floor. Needs `decode_SIB = false` |
| `verizon_66636` | PCI 56, 100 PRB, 4 ports | 52/96 = 54.2% | cleanest run; TBS probe **inconclusive** here |

The two `mt_airy02` captures carry their live run's `rar_log-0.csv`, and the replay reproduces
each exactly, per-UE on `(temp C-RNTI, RAR tti)`. That is the strongest check available that the
replay path is faithful.

**Do not read the spread as cell behaviour.** Port count does not predict it — the 4-port cells
sit at both ends — and the `PDSCH decoded` figure is confounded by tracking exit, since a UE
stops being scanned once its SecurityModeCommand is seen. Signal strength dominates.

**`decode_SIB = true` segfaults on the 5330 capture** inside `srsran_ue_dl_find_and_decode_sib1`,
about two minutes in. Pre-existing: it reproduces on a stock build with the security changes
stashed, at the identical site. `docs/security-implementation.md` §7 has the trace.

### Regression gates that caught real mistakes

Detection is offline now: ngscope writes `mac-<rf>.pcapng` and claims nothing about it;
`tools/security_scan.py` dissects it with Wireshark and writes `security_events` /
`security_sessions` / `security_summary`; `tools/security_phase_join.py` labels the `.dciLog`
files from that. The gates changed shape with it.

- **`tools/fixtures/retired_parser_baseline.json` is the superset gate.** It froze the retired
  in-process parser's per-`(rnti, rar_tti)` verdicts on all five reference captures while both
  parsers still existed — the last time two independent parsers ran on the same bytes. A scan
  must never lose an RNTI in `retired_established`. Verified: 271/52/22/13/10, MISSING 0.
- **The RAR cross-check replaces the old SMC cross-check**, which went vacuous with one parser
  left. srsRAN's RAR parse (`rar_log-<rf>.csv`) vs Wireshark's dissection of the same bytes;
  `security_scan.py` runs it every time and puts it in the summary. It is better placed than
  what it replaced, because the anchor set is the denominator of everything.
- **Comment vs dissection, on every packet.** The RNTI ngscope wrote into the comment must
  equal the one Wireshark dissected. Free, 100% coverage, catches pcap framing drift.
- **The `sec=` splice must preserve file size exactly** and leave the dissection identical
  apart from the comment line itself. Filter with `grep -v "^ *sec="` — in `tshark -V` the
  comment is a bare indented line, not a `Comment:` line, so the obvious filter misses it.
  The fixed 7-character field is what makes the splice possible; don't remove the padding.
- **Compare per-UE on `(temp C-RNTI, RAR tti)`**, not on timestamps. Except the first RAR of a
  run, whose TTI is unstable.

## Traps

**Two clocks.** `timestamp_us` is host wall clock at *decode*; `collection_time` is the radio
domain. In replay the wall clock runs at decode speed (1.45× here), so bucketing by it invents
time that does not exist. Use `collection_time` for anything against time.

**Silent drops are the enemy.** A UE dropped by a cap, a filter or an overloaded scheduler is
indistinguishable in the output from a UE that never reached security — which is exactly what
the detector is trying to measure. Every such path is counted and reported at teardown. **If you
add a path that can drop a tracked UE, add a counter with it.**

**Some UEs can never show a boundary.** `RRCConnectionReestablishment` and
`RRCConnectionResume-r13` restore a stored `K_eNB`, so no SecurityModeCommand follows; they
land as `outcome=reused` in `security_sessions`. Reaching either is *positive* evidence of a
real prior context, so counting them as failures is backwards. Handover-in is the same case but
is not detectable from the target cell alone. **NAS is a separate context** — a ciphered NAS
message proves the UE completed NAS security with the MME, not AS security with this eNB, so
`nas_outcome` is its own column and never feeds `outcome`. Collapsing them once cost a phantom
detection.

**Zero boundaries must look like a measurement, not a missing file.** `security_scan.py`
writes its three files with headers before anything that can fail, so header-only means
"scanned, found nothing" — the positive result for catcher detection — and absent means "never
scanned". `security_sessions` also carries `n_pdus`, so the claim can be "8,068 blocks decoded
across 692 UEs, none carried an SMC" rather than just an empty file.

**Report both denominators.** `established/all RARs` is comparable with the historical figures;
`established/(RARs with decoded traffic)` drops UEs the receiver never saw — but it also drops
UEs that RACHed and did nothing, so it is an upper bound, not a correction. On the trolley
capture the two are 39.2% and 83.4%. Quoting one alone moves the headline by 40 points.

**Never guess a phase.** The domain is now seven values, and two pairs must not be collapsed:
`unknown` (could not watch) vs `none` (watched, saw nothing — the detection signal), and
`unknown` vs `n/a` (not a UE identity). The `sec=` field is padded to exactly 7 characters so
the join can splice it in place, so nothing longer than `unknown` can ever be added. Both
weak-symbol defaults in `mac_pcap.c` answer `unknown`/`dlsch` deliberately, and the sec_phase
one is now the only implementation.

**`rach_filter_only = true` for any per-UE work.** Blind mode manufactures RNTIs from
descrambled CRCs — 6,369 of them in 60 s against 188 real. Fine for aggregate load, unsound
per-UE.

**But the RAR anchor misses roughly half the UEs on a cell**, and `probe_blind_dci = true`
measures how many. It decodes a transport block for every blind DCI and uses the DL-SCH CRC as
the oracle — PDSCH descrambling is RNTI-seeded, the CRC24A is not, so a pass proves the
`(RNTI, grant)` pair real at ~2⁻²⁴. On att_850_office/30 s: 5,114 unconfirmed RNTIs, 5,060 gave
nothing (blind mode is noise, as expected), but **54 decoded and 43 gave ≥3 blocks each** —
real UEs, none in `rar_log`. RNTI 10649 alone had 81 blocks over 17.8 s and is the cell's
busiest downlink UE. **15 of them carry DRB traffic**, and a DRB is
configured only by an `RRCConnectionReconfiguration` that follows a completed
`SecurityModeCommand` — so those UEs *demonstrably* established AS security with this cell,
before the capture began. They are positive evidence, not unobservable: the published 22/68 =
32.4% omits 15 UEs with proven security. Cost +5% replay. `docs/configuration.md` §*Is a blind
DCI real?* has the tables.

**Known defect this exposes, not yet fixed.** `security_scan.py` computes
`established / sum(all outcomes)`, so `reused` sits in the denominator and never the
numerator — UEs that reached `RRCConnectionReestablishment`/`Resume` are counted as failures,
which `docs/security-measurement.md` explicitly calls backwards. Live instance: the poconos
capture reports 339/1318 = 25.7% with `reused = 26`; treating those as the positive evidence
they are gives 365/1318 = 27.7%. `SecurityModeCommand` is one observation of establishment,
not the only one.

**There is no target RNTI any more.** The `rnti` and `decode_single_ue` config keys are gone,
with everything that treated one UE differently. `docs/configuration.md` § *Removed settings*
has the full account. Three things follow that are easy to trip over:

- **`targetRNTI > 0` guards in `ngscope_tree.c` are load-bearing, not defensive.** An
  unfilled `dci_array` slot has `rnti == 0`, so an unguarded zero target matches every empty
  node — `srsran_ngscope_tree_copy_rnti()` would copy the whole empty tree into the output.
  Anything that reintroduces a preferred-RNTI parameter must keep them.
- **PHICH is kept but has no caller.** `dci_decoder_phich_decode()` and `phich_decoder.c` are
  intact and documented in place; `log_phich` is still an accepted key but
  `ngscope_config_finalize()` forces it off, because nothing writes the `rv == 4` record the
  phich log reports. Measured: on a 20 s replay the old build's phich log held 15,884 records
  and **zero** with a non-zero RNTI — entirely filler.
- **`rnti` was the last required key**, so the `required` column of the X-macro tables is now
  unexercised. The machinery is still wired through every backend.

**Config keys live in five places** and the schema comment says so: `load_config.h`,
`gui/ngscope_gui/schema.py`, `ngscope/config.toml`, `ngscope/config.cfg`, and the table in
`docs/configuration.md`. A top-level key also needs a field in `parse_args.h` and a line in
`ngscope_main.c` to reach `prog_args`. Verify with the script in `docs/configuration.md`'s
sibling check — parsing the X-macros and grepping the other four caught `mark_security_phase`
missing from the docs table.

**`mark_security_phase` is replay-only and refused at config time** for live or record: with
no in-process parsing a UE never leaves the tracked set early, and the extra decode work is
paid for in dropped subframes live. It also forces `pcap_mac` on, because the pcap is now the
only output that matters. **`qam_retry` is replay-only too**, enforced in `task_scheduler.c` by
ANDing with `mode == REPLAY`; its flag in `security_rrc.cpp` is **per rf_idx** — `mode` is per
device, so a global flag would let a replaying device switch on behaviour unsound for a live
neighbour. The GUI disables it unless a cell is replaying; that is guidance, the AND is the
guarantee.

---

## State

Branch `pcap`, 20 commits ahead of `13a0b95`, `origin/security` merged in. Pushed and level with
`origin/pcap`.

`Dockerfile` is now tracked (`2aaa4d7`), which settles the question of where the
`amarder89/ng-scope:gui` image came from. `measurements/README.md` and `measurements/run.sh`
still assume the container and its `/src/...` paths.

**Uncommitted work in the tree.** RRC/NAS detection has moved out of ngscope entirely:
`security_rrc.cpp` went from 858 lines to ~247, the whole RLC reassembly / length-indicator /
ASN.1 path is gone, and `security_ctx.c` keeps only the tracked set and the coverage counters.
ngscope writes `mac-<rf>.pcapng` and claims nothing; `tools/security_scan.py` dissects it with
Wireshark. Verified on all five reference captures: identical detections, RAR cross-check
identical, zero comment/dissection mismatches, the `sec=` splice byte-exact.
`mark_security_phase` is replay-only and forces `pcap_mac` on. Also fixed on the way: PHICH
`.dciLog` records were invalid JSON (`dci_log.c`, missing separator plus a trailing comma) --
latent only because every config sets `log_phich = false`. (That log is no longer written at
all; see the target-RNTI note above.)

Cost measured on the trolley capture: replay 119 s -> 142 s (+19%), PDSCH attempts 3,315 ->
11,953, tracking high-water 64 -> 93 of 512, no evictions and nothing unscanned. The extra
work is because a UE no longer leaves the tracked set when its SMC is found -- nothing in the
process knows what an SMC is any more.

**`enable_256qam` still defaults to `true`, and in replay it no longer matters much.** The
decoder now retries a failed transport block on the other MCS->TBS table and keeps whichever
passes CRC, per grant — which is the only correct model, since `altCQI-Table-r12` is per-UE state.
That recovers the whole gap: the trolley capture goes 33.8% -> 39.2% on the default setting,
matching what pinning 64QAM achieves. The teardown reports what the traffic needed (4.6% of
blocks retried there, 45.2% on `mt_airy02/5110`, 0.0% on `verizon_66636`).

The flag still sets the `tbs` values written to every `.dciLog`, and **live capture has no
retry**, so the default is not cosmetic. Left as `true` at the user's explicit request, because
flipping it changes `tbs` in existing output. Do not change it unprompted.

## Next

The offline handover is done and verified; what is left is finishing the seams.

- **`docs/security-implementation.md` §9** still describes the pre-handover verification
  recipe and the old per-capture tables. The numbers are unchanged (39.2 / 54.2 / 32.4 / 50.0
  / 10.3) but the commands are not.
- **`ch=` could come from the dissection.** `mac-lte.dlsch.lcid` is already in the scan's
  tshark pass, so `ccch`/`srb`/`drb` is a few lines in `security_scan.py` plus a second field
  in the comment — not the shared C classifier the old note called for.
- **`security_scan.py` has no `--verify` pass yet.** The plan's step 6 — re-dissect the patched
  file and assert the indicator sets are unchanged — is not implemented. The equivalent check
  was run by hand and passed (identical dissection outside the comment line, size preserved).
- **Ordering integrity is not yet counted.** TTI inversions after reorder would tell you when
  Wireshark's order-dependent RLC reassembly might be losing SDUs; nothing measures it today.

`docs/security-implementation.md` §7 lists the other gaps and §6 records what was deliberately
*not* built, with reasons — including two inferences (opacity, payload entropy) rejected on
measurement, which look compelling until you check them.
