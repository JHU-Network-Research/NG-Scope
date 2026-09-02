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

**The host cannot build this.** No UHD or FFTW on the Mac. Everything goes through the
container, which is amd64 under emulation — slower, but a full build is a few minutes:

```bash
docker run --rm -v "$PWD":/src -w /src/build-docker amarder89/ng-scope:gui \
  bash -lc 'make -j18 ngscope'
```

`build-docker/` is gitignored and already configured; re-run `cmake ..` only after adding a
source file outside the `dciLib` glob.

**Wireshark tooling is the other way round: `tshark` and `capinfos` are on the host, not in the
container.** Validating a pcap means writing it inside and inspecting it outside. `tshark` needs
the DLT mapping every time:

```bash
tshark -r mac-0.pcapng -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
```

## Measuring

**Replay, not live.** The scheduler blocks on a busy decoder in replay but *discards* subframes
live, so only replay gives a comparable yield figure. `measurements/` has the harness; its
README explains the scripts and that the configs are templates (container-absolute
`replay_fname`, `rf_freq` for the reference capture).

```bash
docker run --rm -v "$PWD":/src -w /src amarder89/ng-scope:gui \
  bash -lc 'measurements/run.sh /src/measurements/sec_60s.toml mylabel'
```

`recordings/` is gitignored and holds `tmobile_5035_poconos.bin` (13.7 GB, 300 s) plus 10 s and
60 s prefixes. **Cut prefixes on frame boundaries** — `nof_samples` varies per frame, so the
chain must be walked, not strided (`rx_frame_header_t` in `ngscope/hdr/dciLib/ngscope_rx.h`).

Reference cell: band 12, EARFCN 5035, cell 44, FDD, **25 PRB, 4 ports**. The 4-port part
matters — srsRAN cannot predecode spatial multiplexing there at any antenna count, capping
what is decodable at ~91% of grants. Current result: **424 of 1318 RACHing UEs reached AS
security (32.2%)**.

### Regression gates that caught real mistakes

- **Security figures must not move** when only the pcap path changes. The tee is meant to be inert.
- **The pcapng join must preserve file size exactly** and give an identical `tshark` dissection
  by md5. The fixed-width `sec=` field is what makes that possible — don't remove the padding.
- **`rar_to_smc_ms` must equal the TTI delta** of the same two subframes (1 TTI = 1 ms).
- **Compare per-UE on `(temp C-RNTI, RAR tti)`**, not on timestamps — both come from the capture
  and are stable across runs.

---

## Traps

**Two clocks.** `timestamp_us` is host wall clock at *decode*; `collection_time` is the radio
domain. In replay the wall clock runs at decode speed (1.45× here), so bucketing by it invents
time that does not exist. Use `collection_time` for anything against time.

**Silent drops are the enemy.** A UE dropped by a cap, a filter or an overloaded scheduler is
indistinguishable in the output from a UE that never reached security — which is exactly what
the detector is trying to measure. Every such path is counted and reported at teardown. **If you
add a path that can drop a tracked UE, add a counter with it.**

**Never guess a phase.** `unknown` means "not observed" and must stay distinct from `post`. Both
weak-symbol defaults in `mac_pcap.c` answer `unknown`/`dlsch` deliberately.

**`rach_filter_only = true` for any per-UE work.** Blind mode manufactures RNTIs from
descrambled CRCs — 6,369 of them in 60 s against 188 real. Fine for aggregate load, unsound
per-UE.

**Config keys live in four places** and the schema comment says so: `load_config.h`,
`gui/ngscope_gui/schema.py`, `ngscope/config.toml`, `ngscope/config.cfg` (plus the docs table).

---

## State

Branch `pcap`, 16 commits ahead of `13a0b95`, `origin/security` merged in. **Nothing pushed** —
`origin/pcap` does not exist yet.

`Dockerfile` is untracked and predates this work. It is probably the provenance of
`amarder89/ng-scope:gui`, which both docs now name as the build environment, so it likely
belongs in the repo — but it is the user's file and they have not asked for it to be committed.

**`enable_256qam` defaults to `true`, and the evidence says it is wrong for this cell.** The
built-in probe reports the 64QAM table is 7.8× cleaner by an impossible-code-rate test. Left as
is at the user's explicit request, because flipping it changes the `tbs` values in every
existing `.dciLog`. Do not change it unprompted.

## Next

Most worthwhile: **`ngscope_mac_pcap_classify()` has no strong override**, so the pcap comment
reports `ch=dlsch` for every C-RNTI instead of `ccch`/`srb`/`drb`. The MAC PDU walk already
exists in `scan_mac_pdu()` (`security_rrc.cpp`) and needs lifting into a shared classifier.

`docs/security-implementation.md` §7 lists the other gaps and §6 records what was deliberately
*not* built, with reasons — check it before proposing work, several plausible ideas were
considered and rejected on measurement.
