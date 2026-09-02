# Implementation notes: MAC pcap output and security-phase measurement

A record of what was changed, why, and what was learned doing it. Written for whoever picks
this up next — human or agent. For how to *use* the result, see
[security-measurement.md](security-measurement.md); for the pcap format, [pcap.md](pcap.md).

Fourteen commits on the `pcap` branch, ~3,000 lines. `origin/security` was merged partway
through and contributes roughly a third of that.

---

## 1. What the work set out to do

Write the contents of decoded PRBs to a pcap file, LTESniffer-style, distinguishing messages
sent before and after AS security establishment — for IMSI-catcher detection.

Two things reshaped that goal on contact with the code.

**NG-Scope decoded almost no UE transport blocks.** It is a control-channel sniffer: it
recovers DCI, and the only paths that produced payload bytes were SIB1/SIB2 and RAR. A prior
attempt at security tracking on `origin/security` measured SecurityModeCommand detection for
just 18.5% of RACHing UEs. Most of the work became finding out why.

**LTESniffer is not a different decoder, it is a different trade.** It never blind-searches
for RNTIs; it maintains a UE list bootstrapped from RACH and searches each known UE's search
space with `srsran_ue_dl_find_dl_dci()`, so the PDCCH CRC is *checked against* a known RNTI
rather than recovered from it. High precision, no visibility of pre-existing UEs. NG-Scope's
`rach_filter_only = true` is the same trade. Its PHY is a fork of srsRAN whose `precoding.c`
is byte-identical to this tree's apart from the copyright year, so it inherits exactly the
same MIMO limitations.

---

## 2. Architecture

```
task_scheduler_thread (one per RF device)
  └─ N × dci_decoder_thread
       dci_decoder_decode()                    ngscope/src/dciLib/dci_decoder.c
         1. SIB1/SIB2 decode                   decode_sib.cpp    ─┐
         2. RAR decode                         decode_rar.cpp    ─┤ produce
         3. blind DCI search                   lib/.../ngscope.c  │ transport
         4. ngscope_sec_scan_subframe()        security_rrc.cpp  ─┘ blocks
         5. sec_phase stamping                 security_ctx.c
         6. RACH filter
                                                    │
                        ngscope_mac_pcap_write()  ←──┘   mac_pcap.c
                                 │
                        ngscope_pcapng_write()          pcapng.c
```

Steps 1, 2 and 4 each decode transport blocks and now tee them to the pcap writer. Step 3
does not — see §6.

Two weak symbols decouple the writer from the security tracker, so `mac_pcap.c` builds and
works without it:

| symbol | weak default (`mac_pcap.c`) | strong override |
|---|---|---|
| `ngscope_mac_pcap_sec_phase()` | always `"unknown"` | `security_ctx.c` |
| `ngscope_mac_pcap_classify()` | RNTI class only | *(not yet — see §7)* |

Both defaults **never guess**. That is deliberate: the whole detector rests on distinguishing
"we did not see it" from "it did not happen".

---

## 3. Bugs found

These account for most of the improvement. Each was found by instrumenting, not by reading.

### 3.1 The RACH filter ran unconditionally at rf_idx 0 — `ue_dl.c:691`

```c
if (!ngscope_rach_filter_pass(0, dci_msg[nof_dci].rnti)) continue;
```

Introduced by `73db5f8`. Hardcoded device index, and applied regardless of
`rach_filter_only`. Consequences: on multi-cell runs cells 1–3 were filtered against cell 0's
RNTI set; with `decode_RAR` off the set is empty and *every* unicast DCI was dropped inside the
search. It also disabled the instrument that would have shown this — with the filter inside the
search, everything reaching `dci-decode-debug-<n>.csv` had already passed it, so the `rach_ok`
column was always 1.

**Fix:** the function has no `rf_idx` and no config in scope and its signature is public, so
bind the device to the thread. A decoder thread serves one RF device for its whole life, which
makes `__thread` the right lifetime; unbound means no filtering, which is what `cellscanner`,
`cellinspector` and the tests want.

**Measured (60 s, blind mode):** 25,760 → 53,953 DCIs (2.1×); 188 → 6,369 distinct RNTIs (34×).

### 3.2 Tracked UEs dropped when a decoder thread ran behind — `security_ctx.c`

The worst one, and invisible without a counter.

```c
bool expired = ... || now_us < r->rar_us || (now_us - r->rar_us) > SEC_TRACK_WINDOW_US;
```

`now_us` is the timestamp of whatever subframe the *calling* thread is working on, and threads
run subframes out of order. So `now_us` routinely sits behind a RAR anchored moments earlier by
a thread that was ahead — and the entry was expired and swap-removed from `active[]`,
permanently until the next RAR.

The condition existed to prevent unsigned underflow in the subtraction. It was written as an
expiry when it should have been a guard: an entry newer than the current subframe cannot have
exceeded its window.

`security_ctx.c` already warns about this exact hazard in `ngscope_sec_phase()`, where an
earlier author hit it and documented it. The same trap was open one function away.

**Measured (60 s):** 117 of 221 tracking exits were this, against 104 genuine timeouts. Fixing
it took detections from 64 to 86 (21.2% → 28.5%).

### 3.3 Both tracking caps were below real concurrency

`SEC_MAX_ACTIVE` (64) and `SEC_MAX_SCAN_RNTI` (32). Neither was binding while 3.2 masked real
concurrency; with it fixed the tracked set peaks around 70.

`SEC_MAX_SCAN_RNTI` was the tighter and more damaging one. `ngscope_sec_tracked()` fills its
output in array order and stops at the cap, so it does not *sample* the tracked set — it
starves the same UEs every subframe.

**Fix:** 512 and 128. The scan cap is now mode-dependent (§5). 28.5% → 34.4%.

### 3.4 `.format` was never set on the dominant path

`srsran_ngscope_dci_into_array_dl()` filled every field except `.format`, which was stamped
later in `srsran_ngscope_tree_copy_dci_fromArray2PerSub()`. But `prune_based_on_topN()` and
`prune_based_on_activeUE()` reach `dci_per_sub` through `ngscope_push_dci_to_per_sub()`, a plain
memcpy — so most downlink DCIs arrived as `SRSRAN_DCI_FORMAT0`.

Cosmetic until something keys on it; a prerequisite for any per-format work.

### 3.5 Stale `nof_allocated_locations` — no measurable effect

The reset before the blind search was commented out, so with `decode_RAR` on the RA-RNTI sweep
could leave locations claimed and suppress overlapping candidates.

**Real but negligible.** Only srsRAN's own `dci_blind_search()` populates the array, and both
entry points reset on entry, so the leak needs the RAR search to have hit — 302 subframes out of
58,000. Yield was identical either way. Kept because it is free and correct. Recorded here
because "plausible bug with no measured effect" is worth knowing.

### 3.6 RLC framing info and the extension bit were read from the wrong octet — `security_rrc.cpp`

`unpack_dcch()` took FI and E from octet 1 of the AMD PDU header. Per 36.322 §6.2.1.4 both live
in octet 0 — `D/C | RF | P | FI(2) | E | SN(9:8)` — and octet 1 is the low byte of the sequence
number. The code was therefore testing sequence-number bits: it rejected any PDU whose SN had
bits 2-4 set, three of every four, and would have passed a genuinely segmented PDU through as
though it were whole.

**Latent, not harmless.** Tracking stops at the SecurityModeCommand, so only a connection's
first few RLC PDUs are ever offered to this function, and their sequence numbers are small: SNs
0-2 on a 20 s slice of the AT&T capture, 0-5 over the full 80 s. Twelve PDUs across that capture
would have been wrongly rejected. On any path that looked further into a connection it would
have thrown away most of the DCCH.

### 3.7 `nof_thread` above 8 segfaulted with no diagnostic — `load_config.c`

`nof_thread` indexes `sf_buffer[][]`, `dci_decoder[]` and `dci_thd[]` in `task_scheduler.c`, all
of which are `MAX_NOF_DCI_DECODER` (8) wide, and nothing validated it. A larger value started
eight decoder threads and then walked off the end of each array, crashing inside
`srsran_ue_dl_init()` with a backtrace pointing nowhere near the cause. `nof_rx_ant` had had a
bounds check since the beginning; this one was simply missing. Now refused at config time, like
every other out-of-range setting.

---

## 4. New components

### `pcapng.{c,h}` — generic pcapng writer

Classic pcap has nowhere to put a per-packet comment, and srsRAN's `LTE_PCAP_MAC_WritePDU()`
stamps `gettimeofday()` at write time rather than the subframe's timestamp. So: SHB + IDB +
one EPB per record, `if_tsresol = 6` matching `timestamp_us()`.

Design points worth preserving:

- **Blocks are serialised on the caller's stack, then written under the lock.** Only the
  `fwrite` is inside the critical section. Same split `srsran::mac_pcap_base` makes, and it
  means a queue could be dropped in later without touching callers.
- **A single mutex, not a writer thread.** Worst case is ~10 records/ms into a 64 KB buffered
  `FILE*`, against decoder threads spending 1–30 ms per subframe. Contention is not measurable.
- **No malloc in the hot path.** Oversized records increment a counter and are dropped.
- Both block-length fields are written from one value — a reader walks the file backwards using
  the trailer, and Wireshark rejects a block whose two lengths disagree.

### `mac_pcap.{c,h}` — LTE mapping

Reuses `LTE_PCAP_PACK_MAC_CONTEXT_TO_BUFFER()` from `lib/src/common/pcap.c`, so the
pseudo-header is byte-identical to srsRAN's and a capture is interchangeable with one from
srsUE. One file per RF device: RNTIs are unique only within a cell.

The comment format is documented in [pcap.md](pcap.md). **`sec=` is padded to a fixed 7
characters on purpose** — it makes the join's rewrite an in-place byte patch rather than a
structural re-serialisation. Do not remove that padding without changing
`security_phase_join.py`.

### `tbs_table_probe.{c,h}` — which MCS→TBS table is the cell using?

`enable_256qam` is unknowable from the downlink, and getting it wrong corrupts every `tbs` in
the `.dciLog` files. But an effective code rate above 1 is physically impossible, and
`nof_bits` is already computed next to `tbs` in `srsran_ra_dl_compute_nof_re()`. So evaluate
every grant under both tables and count impossible rates; the table that produces them is ruled
out.

Two populations are kept, all candidates and those with re-encode correlation ≥ 0.8, because
the hook point sees candidates that are later pruned as false alarms and those produce
impossible rates under *both* tables. The verdict reads the confident population.

Built as its own static library, like `rach_filter`, because it is called from `srsran_phy` and
so cannot live in `ngscope_dci`, which links against `srsran_phy`.

**Result on the measured cell:** 64QAM is 7.8× cleaner. `enable_256qam = true` is wrong for it.
The default was left `true` at the operator's request — flipping it changes existing `.dciLog`
throughput figures.

### `security_rrc.cpp` — DCCH accounting and RLC reassembly

Every DL-DCCH SDU now lands in exactly one `ngscope_dcch_result_t` bucket, reported at teardown.
RLC control PDUs are counted separately from failures because a STATUS PDU carries no SDU and is
not a message we failed to read; everything else in the "unread" half is an RRC message that
existed and was not decoded, and any of those could have been a SecurityModeCommand. Without
this the loss was invisible, which is the one thing §5 says the measurement cannot tolerate.

Reassembly rejoins SDUs the eNB split across grants, and is **enabled only for replay**
(`ngscope_sec_rrc_set_reassembly()`, called from `task_scheduler.c` under `mode == REPLAY`,
before any decoder thread starts). Holding a partial SDU until the rest arrives is sound exactly
where nothing goes missing: replay blocks on a busy decoder and sees every subframe, whereas
live capture discards them, and a discarded middle segment leaves a partial that never completes
— indistinguishable, in the output, from a UE that never reached security.

A PDU may also hold several SDUs at once, delimited by a **length-indicator chain**: a run of
`[E(1), LI(11)]` pairs after the two fixed octets, padded with 4 bits when the count is odd.
`unpack_dcch()` walks it, hands every whole piece straight to the unpacker, and sends only the
leading and trailing pieces into reassembly. That matters because FI constrains just the outer
pieces — a PDU can carry a complete message *and* the start of the next one, which is exactly
the shape that hid a SecurityModeCommand on the mt_airy02 cell.

Because a PDU can be both the end of one SDU and the start of another, the fragment store keeps
a **head** and a **tail** per sequence number rather than a single buffer, and a completed SDU
removes only the segments it consumed — clearing the whole slot would silently discard a second
SDU still being assembled.

Two details that are not obvious:

- **Segments are matched by sequence number, not arrival order.** Decoder threads run in
  parallel, so a later subframe routinely finishes first. On the AT&T capture the last segment
  was already held when the first arrived.
- **A reassembled message is attributed to its FI=LAST segment**, not to whichever piece
  completed the reassembly. Those differ for the same reason, and using the completing subframe
  put the boundary at an arbitrary TTI — 1839 for a message that finished on air at 1840,
  breaking the `rar_to_smc_ms == TTI delta` gate.

Partial SDUs still held at teardown are flushed and counted as lost rather than forgotten.

### `security_rrc.cpp` — letting the CRC pick the MCS→TBS table

`enable_256qam` selects `use_tbs_index_alt`, which sets the transport block size, which sets the
rate matching — so a wrong guess cannot pass CRC. It is also **per-UE** state (`altCQI-Table-r12`
in 36.213), so no single config value is right for every UE on a cell.

In replay, `ngscope_sec_scan_subframe()` therefore stops guessing: when a transport block fails
its CRC the grant is rebuilt on the other table and decoded again, keeping whichever passes
(`ngscope_sec_rrc_set_qam_retry()`, enabled from `task_scheduler.c` under `mode == REPLAY`). The
CRC is ground truth, so this measures the table instead of inferring it, and it does so per grant.

`decode_grant_with_table()` returns three states, not two: CRC passed, attempted and failed, or
*no buildable grant*. The third has to stay distinct — it is not an attempt, and folding it in
would understate the decode rate that line 1 of the report is built from.

Measured with the default `enable_256qam = true`, against the same captures with each table
pinned:

| capture | pinned 256QAM | pinned 64QAM | 256QAM + retry | blocks retried |
|---|---|---|---|---|
| `att_trolley` | 234 / 692 = 33.8% | 271 / 692 = 39.2% | **271 / 692 = 39.2%** | 4.6% |
| `mt_airy02/5110` | 12 / 26 = 46.2% | 13 / 26 = 50.0% | **13 / 26 = 50.0%** | 45.2% |
| `verizon_66636` | 52 / 96 = 54.2% | 52 / 96 = 54.2% | **52 / 96 = 54.2%** | 0.0% |

It reaches the better pinned setting on every capture without being told which it is, and all
three still pass the pcap cross-check, so the extra detections are real. `verizon_66636` is the
control: the TBS probe called it inconclusive, and the retry independently confirms that by
rescuing nothing. Cost is negligible — 66 s against a 65 s baseline — because the retry fires
only on failures and PDSCH decoding is a small part of a replay's work.

---

## 5. Design decisions worth not re-litigating

**Two clocks, and which is authoritative.** `timestamp_us` is host wall clock at decode;
`collection_time` is the radio domain. In replay the wall clock advances at *decode* speed, so
anything derived from it is wrong — measured, it overstated RAR-to-SMC delay by 26.5 ms at the
median and 1046 ms at the tail. `security_log` now carries both, and `rar_to_smc_ms` comes from
the collection times. Validation: the capture-time delta matches the TTI delta of the same two
subframes in 104 of 104 cases, as it must, since one TTI is one millisecond.

The join still *matches* on wall clock, because that is what `.dciLog` and pcapng records
carry. Switching the match key to capture time would probably be an improvement — the wall
clock has thread jitter — but it is a behavioural change and should be measured, not assumed.

**Mode-dependent scan cap.** Live capture discards a subframe when every decoder is busy, so
overspending on the security scan loses whole subframes invisibly. Replay *blocks* instead, so
it stays lossless however slow it runs and the only cost is wall time. Hence
`NGSCOPE_SEC_SCAN_CAP_LIVE` (128) and `NGSCOPE_SEC_SCAN_CAP_REPLAY` (512).

**Counters are load-bearing, not diagnostics.** Every silent drop is a UE that looks exactly
like one that never reached security. The teardown lines exist so the detection rate can be
read as a property of the cell rather than of the receiver. Do not remove them, and add one
whenever a new path can drop a tracked UE.

**Coverage is asymmetric, and in the flattering direction.** The targeted security scan covers
the pre-security window with verified RNTIs; post-security traffic reaches the pcap only via
weaker paths. A raw pre-vs-post packet count measures the two mechanisms, not the cell.

**Recording refuses `nof_rx_ant > 1`.** The IQ recorder writes `ptr[0]` only and
`rx_frame_header_t` has no channel count, so such a recording would be silently truncated to
one channel and look valid. Refusing beats losing a field capture.

---

## 6. Things deliberately not done

**A sweep decoding every DL DCI.** Originally planned. Under RACH-gated operation — the only
sound mode for per-UE analysis — the targeted scan already covers the tracked set, and a blind
sweep would add false-positive RNTIs for traffic the detector does not need. The `src=blind`
provenance field exists in the pcap comment for it, currently unused.

**A `mac_tee` indirection layer.** With one consumer it would be a layer for its own sake. Its
one substantive job, de-duplicating between targeted and blind passes, belongs inside
`mac_pcap` and should be added there if a second producer appears.

**Raising `SEC_MAX_ACTIVE` to 4096.** Nearly free — 8 KB against a 2.6 MB per-device context,
and `ngscope_sec_tracked()` walks `nof_active`, not the array size. But high-water is 57 against
512, and at 4096 the scan cap would bind first and lose the same information *without* the
eviction counter firing. Raising the outer cap alone converts a loud failure into a quiet one.

**Multi-channel IQ recording.** Needs a format version bump so old files are not misparsed.
Currently refused rather than silently wrong.

**Implementing 4-port MIMO predecoding.** `srsran_predecoding_multiplex()` is *"not implemented
for 4 Tx ports"* and `srsran_predecoding_ccd_zf()` is *"Only 2 ports supported"*. Real DSP work,
and it would need 2+ RX antennas to be usable once written. Worth knowing this is a software
gap, not a physical limit — 4-port spatial multiplexing is decodable in principle.

---

## 7. Known gaps

- **`ngscope_mac_pcap_classify()` has no strong override**, so `ch=` reports `dlsch` for every
  C-RNTI instead of `ccch`/`srb`/`drb`. The MAC PDU walk to implement it already exists in
  `scan_mac_pdu()` in `security_rrc.cpp`; it needs lifting into a shared classifier. This is
  the most obviously worthwhile next task.
- **`scan_mac_pdu()` does not check `pdu.nof_subh()`.** `sch_pdu::parse_packet()` returns `void`
  and swallows the base class's error (`lib/src/mac/pdu.cc:218`), so `nof_subh() == 0` is the
  only observable failure signal for a corrupt PDU.
- **RLC reassembly is replay-only**, by design (see §4). A live run still bails on a segmented
  SDU and counts it `segmented`, so a SecurityModeCommand split across grants is missed there.
  The alternative — holding partial SDUs while the scheduler is discarding subframes — turns a
  missed middle segment into a stall indistinguishable from a UE that never reached security.
- **`decode_SIB = true` segfaults on some cells.** Confirmed on
  `mt_airy02/earfcn-5330`: a SIGSEGV inside `srsran_ue_dl_find_and_decode_sib1`
  (`decode_sib.cpp:140`), reached from `dci_decoder_decode` → `dci_decoder_thread`, roughly two
  minutes into the replay. **Pre-existing**, not from the security work — the same crash
  reproduces on a stock build with the security changes stashed, at the identical site. The
  other captures here decode SIBs without complaint, and that cell is weak (PSR 4.03, power
  -2.5 dBm), so the likely trigger is a false-positive SI-RNTI DCI yielding a nonsense grant:
  `pdsch_res[]` in that function is left uninitialised and only the enabled transport blocks get
  a payload pointer. `decode_SIB = false` avoids it, at the cost of `cellcfg.json`. Not
  diagnosed further.
- **Re-segmented PDUs (`RF = 1`) are not handled.** Their header carries a segment offset that
  is not parsed; they are counted `unsupported`. Rare: 2 across the trolley capture, 0 on
  mt_airy02, and both were retransmissions of the same 1-byte tail.
- **The first RAR of a run gets a TTI up to 60 ms too large.** On the AT&T capture
  `tti - collection_time` is a constant 405.111 ms for 130 of 131 RARs and 345.111 for the
  first, so the two clocks disagree on exactly one record while the SFN settles. It breaks the
  `rar_to_smc_ms == TTI delta` gate for that one UE — the collection-time figure is the correct
  one — and it makes the `(temp C-RNTI, RAR tti)` comparison key unstable for the first UE of a
  run. Not diagnosed further; it is one record per run.
- **No HARQ soft combining anywhere in the tree**, including in the deleted LTESniffer port.
  Per-(RNTI, HARQ) buffers would cost ~483 KB each, ≈7.7 MB per tracked UE.
- **The correlation gate is still commented out** (`ue_dl.c`, `JH CORR_FILTER`). `73db5f8`
  replaced it with the RACH filter; now that the filter is optional, blind mode has no
  false-positive gate at all.

---

## 8. Historical note: the deleted LTESniffer port

`ngscope/hdr/` contains ten headers with LTESniffer's class names — `SFDecoder.h`, `sfworker.h`,
`ueDatabase.h`, `ulSch.h`, `common_type_define.h` and others — declaring functions with no
definitions anywhere in the tree. They are not an incomplete port. Commit `e5ee089` deleted the
implementations in one go: 14 files, 4,783 lines, headers left behind. Recover with
`git show 5bc706b:ngscope/src/SFDecoder.cc`.

Worth reading rather than restoring. It is a parallel architecture — its own thread pool,
buffer pool and `main` — and adopting it would mean losing the DCI tree, UE tracker, RACH
filter, sink and GUI. It also had **no HARQ combining**, so it would not fix retransmissions.

The one technique worth extracting is at `SFDecoder.cc:1156`: it reads each UE's transmission
mode out of `RRCConnectionSetup`, which is sent on CCCH in the clear, instead of guessing from
the DCI format. `unpack_ccch()` in `security_rrc.cpp` already decodes that exact message and
discards the contents. `alt_cqi_table_r12` — the 256QAM answer — sits in the same
`physicalConfigDedicated` at `phy_ded.h:2733`.

Caveat on both: the reconfiguration that usually enables TM3/TM4 and 256QAM arrives *after*
security activation and is ciphered, so Msg4 gives the initial config, not necessarily the
operating one. LTESniffer has the same blind spot.

---

## 9. Verifying a change

Replay is the instrument: the scheduler blocks rather than dropping, so two runs over the same
file see identical input.

```bash
cd build && make -j"$(nproc)" ngscope    # binary at build/ngscope/src/ngscope
ngscope -c <config>.toml -o out/
```

On a host without UHD and FFTW the build goes through the `amarder89/ng-scope:gui` container
against a `build-docker/` tree instead; `Dockerfile` is that image's provenance.
`measurements/run.sh` still hard-codes the container's `/src/...` paths and needs rewriting for
a host-native run.

`measurements/run.sh` extracts DCI counts, distinct RNTIs, the `rach_ok` split, the format
distribution and all teardown reports. `measurements/analyse_pcap.sh` cross-tabulates RRC
message type against joined phase.

Regression gates that caught real mistakes here:

- **Security figures must not move** when only the pcap path changes. The tee is supposed to be
  inert; if the numbers shift, it is not.
- **The pcapng rewrite must preserve file size exactly** and produce an identical `tshark`
  dissection by md5. The fixed-width `sec=` field is what makes that true. Use `--no-reorder`:
  the join now sorts its output through `reordercap` by default, which changes the bytes for
  a good reason and would otherwise look like a regression.
- **`rar_to_smc_ms` must equal the TTI delta** of the same two subframes, since one TTI is one
  millisecond. This is how the two-clocks bug was confirmed.
- **Compare per-UE, not in aggregate.** Key on `(temp C-RNTI, RAR tti)` — both come from the
  capture and are stable across runs, unlike wall-clock timestamps. One caveat: the first RAR of
  a run has an unstable TTI (§7).
- **The SMC count must equal the number of distinct RNTIs carrying a SecurityModeCommand in the
  pcap**, after `reordercap`. This is the only external check on the tracker, and it is what
  exposed both the segmentation loss and the length-indicator loss. Reorder first — Wireshark
  cannot reassemble RLC from records in decode-completion order.

  **Count it with the field filter, never by grepping the Info column:**

  ```bash
  reordercap mac-0.pcapng sorted.pcapng
  tshark -r sorted.pcapng -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""' \
    -Y 'lte-rrc.securityModeCommand_element' -T fields -e frame.comment \
    | grep -o 'rnti=0x[0-9a-f]*' | sort -u | wc -l
  ```

  `_ws.col.Info` holds one summary per *frame*, last writer wins, so a MAC PDU carrying several
  SDUs reports only the last of them. Grepping it undercounted mt_airy02 at 7 SMCs where the
  capture holds 12, and made a real loss look like a rounding error. Use
  `lte-rrc.securityModeCommand_element`, not `..._r8_element`: the inner element is absent when
  the critical-extensions body does not dissect, which drops one genuine SMC per capture here.

### Progression on the reference capture

Band 12, EARFCN 5035, cell 44, FDD, 25 PRB, 4 ports. 300 s, `rach_filter_only = true`.

| state | SMC detections | rate |
|---|---|---|
| `origin/security` as merged | 183 / 1318 | 13.9% |
| + out-of-order expiry fix | — | — |
| + cap sizing | 424 / 1318 | **32.2%** |

On the 60 s prefix the three steps are separable: 21.2% → 28.5% → 34.4%.

### Other cells

Five captures replayed so far, all with `rach_filter_only = true`. Every gate in the list above
passes on every one of them except where noted.

| capture | cell | RARs / SMCs | rate | PDSCH | replay |
|---|---|---|---|---|---|
| `tmobile_5035_poconos` (reference) | 25 PRB, 4 ports, band 12 | 1318 / 424 | 32.2% | 58.9% | 1.45× |
| `att_trolley` | PCI 405, 100 PRB, 2 ports, AT&T | 692 / 234 | 33.8% | 61.7% | 1.48× |
| `mt_airy02/earfcn-5110` | PCI 358, 50 PRB, 2 ports, AT&T | 26 / 12 | 46.2% | 35.5% | 1.06× |
| `mt_airy02/earfcn-5330` | PCI 206, 50 PRB, 4 ports, band 14 | 97 / 10 | 10.3% | 43.6% | 1.04× |
| `verizon_66636` | PCI 56, 100 PRB, 4 ports, Verizon | 96 / 52 | **54.2%** | 61.6% | 1.08× |

**The PDSCH column is not a receiver-quality ranking.** A UE stops being scanned once its
SecurityModeCommand is seen, so a cell with a high detection rate spends its remaining attempts
on the UEs that never yield one — which are the weak ones. That is why 5110 shows the lowest
PDSCH rate and nearly the highest detection rate.

**Nor does port count predict much.** The 4-port cells sit at both ends of the table: 10.3% on
5330 and 54.2% on Verizon. Signal strength dominates. What 4 ports costs is a hard ceiling on
spatial multiplexing, which shows up as a decode-rate ceiling rather than a detection-rate one.

Two of these carry the `rar_log-0.csv` from the live run that made the recording, which gives the
one check nothing else can: **the replay reproduces the live run's RAR set exactly**, per-UE on
`(temp C-RNTI, RAR tti)` — 26 of 26 on 5110, 97 of 97 on 5330.

#### `att_trolley` — 12.86 GB, 80 s

No metadata sidecar: the frame chain gives the sample rate (23.04 Msps → 100 PRB) and the cell
announces the rest. Reassembly moved a 20 s slice from 56 to 57 SMCs. The length-indicator walk
changes the detection count not at all, exactly as the pcap predicted — all 72 LI PDUs here hold
an `rrcConnectionRelease` and a `dlInformationTransfer`, no SecurityModeCommand — but it does
read them, so `DCCH SDUs unpacked` rises 323 → 467 (the two SDUs behind each of the 72) and
`unsupported` falls 74 → 2. The TBS probe finds 64QAM 13.0× cleaner.

#### `mt_airy02/earfcn-5110` — 22.9 GB, 249 s

The capture that pays for both pieces of RLC work. It segments and concatenates constantly — 48
of 100 AM data PDUs are segments, against 9 of 428 on the trolley — and the length-indicator walk
doubles the measured rate:

| | before the LI walk | after |
|---|---|---|
| SMCs | 6 / 26 (23.1%) | **12 / 26 (46.2%)** |
| DCCH `unsupported` | 9 | 0 |

The reordered pcap holds 12 distinct RNTIs with a SecurityModeCommand either way, so the second
row is the correct one and the first was a 50% undercount.

#### `mt_airy02/earfcn-5330` — 27.4 GB, 300 s

**Read 10.3% as a floor, not as a property of the cell.** It is weak (PSR 4.03, power -2.5 dBm)
as well as 4-port, and the teardown reports **6 partial SDUs lost against 15 unpacked** — the
worst ratio of the five. Many segments' partners were never decoded, and a UE whose
SecurityModeCommand fell in that gap is indistinguishable from one that never received a
SecurityModeCommand.

Must be replayed with `decode_SIB = false`; see §7.

#### `verizon_66636` — 10.37 GB, 60 s

MCC 311 / MNC 480, band 66 at 2130 MHz from the capture's own `config.cfg`. The cleanest run of
the five: 52 / 52 on `rar_to_smc_ms == TTI delta`, and 52 SMC RNTIs in `security_log` against the
same 52 in the reordered pcap. Light RLC framing, like the trolley — 6 first-segments and 3 LI
PDUs across the capture.

**The first cell where the TBS probe cannot separate the tables.** Impossible-code-rate counts
come out at 0.03% for 64QAM against 0.04% for 256QAM — too close to call, and the probe says so.
Its "confident" verdict falls back to the lower mean code rate, which picks 64QAM but on much
weaker evidence than the 7.8× and 13.0× separations elsewhere. Do not quote this one as
independent support for `enable_256qam = false`.
