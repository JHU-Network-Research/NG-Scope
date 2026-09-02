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

- **Security figures must not move** when only the pcap path changes. The tee is meant to be inert.
- **The pcapng join must preserve file size exactly** and give an identical `tshark` dissection
  by md5. The fixed-width `sec=` field is what makes that possible — don't remove the padding.
  **Run the join with `--no-reorder` for this check**: by default it now passes the output
  through `reordercap`, which legitimately changes the bytes.
- **`rar_to_smc_ms` must equal the TTI delta** of the same two subframes (1 TTI = 1 ms).
- **Compare per-UE on `(temp C-RNTI, RAR tti)`**, not on timestamps — both come from the capture
  and are stable across runs. Except the first RAR of a run, whose TTI is unstable (below).
- **The SMC count must equal the distinct RNTIs with a SecurityModeCommand in the pcap**, after
  `reordercap`. The only external check on the tracker; it caught both the segmentation and the
  length-indicator losses. Count with `-Y lte-rrc.securityModeCommand_element`, **never by
  grepping `_ws.col.Info`** — that is one summary per frame, last writer wins, so a MAC PDU
  holding several SDUs reports only the last. It hid half the SMCs on mt_airy02.

---

## Traps

**Two clocks.** `timestamp_us` is host wall clock at *decode*; `collection_time` is the radio
domain. In replay the wall clock runs at decode speed (1.45× here), so bucketing by it invents
time that does not exist. Use `collection_time` for anything against time.

**Silent drops are the enemy.** A UE dropped by a cap, a filter or an overloaded scheduler is
indistinguishable in the output from a UE that never reached security — which is exactly what
the detector is trying to measure. Every such path is counted and reported at teardown. **If you
add a path that can drop a tracked UE, add a counter with it.**

**Zero boundaries must look like a measurement, not a missing file.** `security_log-<rf>.csv`
is created with its header at startup (`ngscope_sec_log_init`), so empty means "measured, none
found" — the positive result for catcher detection — and absent means "never measured". It used
to be written lazily by the first boundary, which conflated the two and made the join blame the
config.

**Never guess a phase.** `unknown` means "not observed" and must stay distinct from `post`. Both
weak-symbol defaults in `mac_pcap.c` answer `unknown`/`dlsch` deliberately.

**`rach_filter_only = true` for any per-UE work.** Blind mode manufactures RNTIs from
descrambled CRCs — 6,369 of them in 60 s against 188 real. Fine for aggregate load, unsound
per-UE.

**Config keys live in five places** and the schema comment says so: `load_config.h`,
`gui/ngscope_gui/schema.py`, `ngscope/config.toml`, `ngscope/config.cfg`, and the table in
`docs/configuration.md`. A top-level key also needs a field in `parse_args.h` and a line in
`ngscope_main.c` to reach `prog_args`. Verify with the script in `docs/configuration.md`'s
sibling check — parsing the X-macros and grepping the other four caught `mark_security_phase`
missing from the docs table.

**`rlc_reassembly` and `qam_retry` are replay-only**, enforced in `task_scheduler.c` by ANDing
each with `mode == REPLAY`, and their flags in `security_rrc.cpp` are **per rf_idx** — `mode` is
per device, so a global flag would let a replaying device switch on behaviour that is unsound
for a live neighbour. The GUI disables them unless a cell is replaying; that is guidance, the
AND is the guarantee.

---

## State

Branch `pcap`, 20 commits ahead of `13a0b95`, `origin/security` merged in. Pushed and level with
`origin/pcap`.

`Dockerfile` is now tracked (`2aaa4d7`), which settles the question of where the
`amarder89/ng-scope:gui` image came from. `measurements/README.md` and `measurements/run.sh`
still assume the container and its `/src/...` paths.

**Uncommitted work in the tree**, validated across five captures and documented in
`docs/security-implementation.md` §3.6, §3.7, §4 and §7:

- `nof_thread > 8` is now refused at config time instead of segfaulting.
- Every DL-DCCH SDU is accounted for in a fourth teardown line.
- RLC reassembly of split SDUs, **replay only** — recovered a SecurityModeCommand that was
  otherwise silently lost.
- `unpack_dcch()` read the RLC framing-info and extension bits from the wrong octet.
- `rlc_reassembly` and `qam_retry` are real config keys now, replay-gated in C and disabled
  in the GUI unless a cell replays. GUI-side **Join after the run** runs
  `tools/security_phase_join.py` when ngscope exits (not between sweep channels).
- The RLC length-indicator chain is walked, so several SDUs in one PDU are all read. Worth
  **6 extra SecurityModeCommands on mt_airy02 (23.1% → 46.2%)** and nothing on the trolley
  capture, where it only adds 144 already-known messages.

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

Most worthwhile: **`ngscope_mac_pcap_classify()` has no strong override**, so the pcap comment
reports `ch=dlsch` for every C-RNTI instead of `ccch`/`srb`/`drb`. The MAC PDU walk already
exists in `scan_mac_pdu()` (`security_rrc.cpp`) and needs lifting into a shared classifier.

`docs/security-implementation.md` §7 lists the other gaps and §6 records what was deliberately
*not* built, with reasons — check it before proposing work, several plausible ideas were
considered and rejected on measurement.
