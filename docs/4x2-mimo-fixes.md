# 4x2 MIMO decoding fixes

Four ports at the eNB, two receive antennas at the sniffer. This document explains what stopped
ngscope from processing 4x2 captures from commercial cells, what was changed, and how the
changes were checked. It is written for someone who knows the code base and LTE at the level of
"transmission modes, codebooks, codewords", but not the details of this change.

Reference capture: `~/ngscope-data/4x2/tmobile-5035-studentcenter-20261002.bz2`, a T-Mobile
cell (EARFCN 5035, PCI 272, 25 PRB, 4 ports), recorded with 2 RX channels, about 78 s long.

---

## Summary

| # | Problem | Effect | Fix |
|---|---|---|---|
| 1 | SIB payloads parsed even when the CRC failed | Replay crashed after ~29 s | Skip failed blocks and unexpected message types |
| 2 | 4-port precoding codebook was wrong | Spatial multiplexing decoded at 13% | Generate the codebook from the 3GPP formula |
| 3 | DCI precoding field misread on 4 ports | Rank-1 grants used the wrong precoder | Map the field per 36.212 |
| 4 | Only the first codeword of a grant was used | Good second transport blocks discarded | Check and write every codeword |

Net result on the reference capture:

| | Before | After |
|---|---|---|
| Spatial-multiplexing CRC pass rate | 13.4% | 65.0% |
| Transport blocks decoded | 2,324 | 5,830 |
| SecurityModeCommands found | 70 | 76 |
| UEs reaching AS security | 55 / 81 (67.9%) | 58 / 81 (71.6%) |

No UE moved to a worse outcome. The 2-port reference capture (`att_trolley`) gives the same
result as before.

---

## Background: what a 4-port cell sends

A downlink grant (DCI) says how its data is transmitted. Three schemes matter here:

- **Transmit diversity.** The same data is spread over all four ports for robustness. srsRAN
  already handled this on 4 ports, and it decoded well (86%).
- **Closed-loop spatial multiplexing** (TM4, DCI Format2). The eNB multiplies the data by a
  *precoder*, a 4×1 or 4×2 matrix chosen from a fixed codebook of 16 entries. The DCI carries
  the codebook index (TPMI). To decode, the receiver has to apply the same matrix to its
  channel estimate. *Rank* is the number of parallel data streams (layers): rank 1 is one
  stream, rank 2 is two.
- **Open-loop spatial multiplexing / large-delay CDD** (TM3, DCI Format2A). Similar, but the
  precoder cycles through a fixed sequence instead of being signalled.

A grant can carry one or two *codewords* (transport blocks), each with its own CRC.

With two receive antennas the sniffer can separate at most two layers, so rank 1 and rank 2
are the decodable cases. Upstream srsRAN implements spatial multiplexing and CDD only for 2
ports.

---

## Fix 1: SIB decoding crash

**Symptom.** The replay died after about 29 seconds with `std::bad_alloc`, after a flood of
ASN.1 decode errors. The backtrace pointed at `srsran_ue_dl_find_and_decode_sib1`.

**Cause.** The PDSCH decoder writes its output buffer whether or not the CRC passes. The SIB1
and SIB2 functions in `ngscope/src/dciLib/decode_sib.cpp` never checked the CRC; they handed
the buffer straight to the ASN.1 parser. Sooner or later, random bits decoded as an enormous
length field and the allocation failed.

A second, smaller problem was in the same place. The code read the message as SIB1 (or as
SystemInformation) without checking which type it actually was. The ASN.1 library only logs a
type mismatch and then reinterprets the memory anyway.

**Fix.** Both functions now return early unless the CRC passed and the message is the expected
type.

**Note.** This is the same crash that was previously blamed on the `mt_airy02/5330` capture,
which is also a 4-port cell. `decode_SIB = false` may no longer be needed there; that has not
been tested.

---

## Fix 2: the 4-port codebook

**Symptom.** Only 13.4% of spatial-multiplexing grants passed CRC, against 86% for transmit
diversity on the same capture. A 2-port cell decodes about 87% of the same grant type, so the
radio channel was not the explanation.

**Cause.** The 4-port rank-2 precoder table in `lib/src/phy/mimo/precoding.c` had been typed in
by hand and had wrong signs on most entries. For example, entry 0 should be proportional to
`[[1,1],[1,−1],[1,−1],[1,1]]` but was `[[1,1],[−1,1],[−1,1],[−1,1]]`. Applying the wrong
matrix gives a wrong effective channel, and the data cannot be recovered. The same function
also ran a SIMD loop with a third, different mapping, whose output a scalar loop then
overwrote.

**Fix.** A single new predecoder, `srsran_predecoding_multiplex_4port`, replaces the separate
4x1/4x2 variants. It does not store the 16 matrices. It generates each one from the formula in
36.211 Table 6.3.4.2.3-2:

```
W_n = I − 2·u_n·u_nᴴ / (u_nᴴ·u_n)
```

Here `u_n` is a 4-element vector listed in the spec. A rank-1 precoder is the first column of
`W_n`; a rank-2 precoder is a specified pair of columns scaled by 1/√2. Only the 16 short
vectors and the column choices need to be typed in, so there is far less room for sign errors.

For each resource element the decoder combines the 4-port channel estimate with the precoder
to get an effective channel per receive antenna and layer, then equalizes:

- rank 1: maximum-ratio combining across the receive antennas;
- rank 2: a 2×2 MMSE solve (srsRAN's existing `srsran_mat_2x2_mmse_csi_gen`).

Output scaling and the per-symbol channel quality values follow the existing 2-port code, so
the demodulator and turbo decoder downstream see what they expect.

**CDD.** `srsran_predecoding_ccd_4port` applies the same approach to large-delay CDD. The
precoder cycles through codebook entries 12–15 and alternates a phase term every symbol, as
defined in 36.211 §6.3.4.3. This is implemented but **not validated**: the reference cell does
not appear to schedule CDD (see Limitations).

The old 4x1/4x2 functions are still in `precoding.c` but are no longer called.

---

## Fix 3: reading the precoding field on 4 ports

**Cause.** On a 4-port cell, Format2 carries a 6-bit precoding field (pinfo). The code took the
low four bits as the codebook index and set the layer count equal to the number of codewords.
The standard (36.212 Table 5.3.3.1.5-5) says otherwise:

| Codewords | pinfo | Meaning |
|---|---|---|
| 1 | 0 | transmit diversity |
| 1 | 1–16 | rank 1, TPMI = pinfo − 1 |
| 1 | 17 | rank 1, precoder from the UE's last uplink report |
| 1 | 18–33 | rank 2 on one codeword, TPMI = pinfo − 18 |
| 2 | 0–15 | rank 2, TPMI = pinfo |
| 2 | 16 and up | "last report" entries, rank 3/4, or reserved |

So every rank-1 grant was decoded with the precoder next to the right one in the codebook.

**Fix.** `config_mimo_pmi` in `lib/src/phy/phch/ra_dl.c` now follows the table. It builds rank 1
with one codeword and rank 2 with two codewords. Everything else is refused when the grant is
built:

- **Rank 3/4:** two antennas cannot separate three or four layers.
- **"Last uplink report":** that is UE state a sniffer does not see.
- **Rank 2 on one codeword:** needs a different transport-block-size rule (36.213 §7.1.7.2.2).
  It does not occur in the reference capture.

Refused grants appear in the teardown as *found but not built*, so they are counted rather than
silently dropped or mislabelled as CRC failures. Format2A (TM3) on 4 ports gets the equivalent
check: only pinfo 0 is built.

---

## Fix 4: second codeword discarded

**Cause.** In `ngscope/src/dciLib/security_rrc.cpp`, a grant counted as decoded only if
transport block 0 passed CRC, and only TB0 was written to the pcap. In a two-codeword grant,
TB1 is a separate MAC PDU with its own CRC. It was never written, even when it decoded. This
affected 2-port cells as well.

**Fix.**
- A grant counts as decoded if any of its transport blocks passes.
- The MCS-table retry (`qam_retry`) runs only when none passed, so a good TB1 is not
  overwritten by the retry attempt.
- Every passing block is written to `mac-<rf>.pcapng` with its own MCS, redundancy version and
  size.
- The teardown line now reports how many decoded blocks were second codewords: 304 on the
  reference capture.

---

## Finding: security traffic is not always transmit diversity

The docs used to say that everything before security is sent with transmit diversity. The
reasoning was that a UE stays in TM1/TM2 until an `RRCConnectionReconfiguration`, which only
follows the SecurityModeCommand. That is not true on this cell.

`RRCConnectionSetup` can already set the transmission mode. On the reference capture, 57 of the
76 SecurityModeCommands were sent with Format2, and 14 used spatial multiplexing. Those 14 were
undecodable before Fix 2, which is why fixing a "post-security" problem changed the detection
rate. **Any 4-port measurement taken before these fixes probably undercounts.**

The claim has been corrected in `docs/security-measurement.md`, `docs/configuration.md`,
`docs/security-implementation.md`, the `ngscope-measure` skill and the comments in
`security_rrc.cpp`.

---

## How the fixes were checked

**Codebook and mapping.** A temporary diagnostic retried each failed spatial-multiplexing grant
with all 16 codebook entries, on both MCS tables. If the mapping were still wrong, some other
entry would pass consistently in place of the signalled one. That did not happen: the signalled
entry is the overwhelming winner for every TPMI. The few "other entry passes" cases go in both
directions and cluster at low-MCS QPSK, where neighbouring precoders can pass by chance.

**Where the remaining failures are.**
- About 1,350 are high-MCS first transmissions where no precoder passes. This is a
  signal-quality limit: the eNB points the beam at the UE, not at the sniffer.
- 616 are retransmissions signalled with MCS 29–31. Those carry no transport block size (it
  comes from the original grant), so they cannot be decoded as things stand.

**Before/after on the same capture.** A baseline binary with only Fix 1 applied was run on the
same file for the comparison table in the Summary. 3 UEs moved from `in_progress` to
`established`, 1 to `released`, and none got worse.

**Regression gates** (see `CLAUDE.md`), all passing on both captures:
- RAR cross-check: srsRAN's and Wireshark's RAR parses are identical.
- Comment vs dissection: zero RNTI mismatches.
- `sec=` splice: re-dissects identically apart from the comment, file size preserved.

**2-port regression** on `att_trolley`:
- 271 / 692 = 39.2%, identical to the recorded reference;
- superset gate against `tools/fixtures/retired_parser_baseline.json`: MISSING 0.

---

## Limitations and possible next steps

- **MCS 29–31 retransmissions** (616 grants on the reference capture). Decoding them needs the
  transport block size from the original transmission. That means tracking per-UE, per-HARQ
  process state, which would also allow soft-combining retransmissions.
- **Rank 2 on one codeword.** Needs the two-layer transport block size rule. Not seen in the
  reference capture.
- **CDD on 4 ports.** Implemented, but this capture's Format2A hits look like false alarms:
  they spread evenly across precoding values, including a reserved one. A cell that really uses
  TM3 is needed to validate it.
- **Rank 3/4.** Needs more than two receive antennas.
- **Precoder fallback.** Retrying the other codebook entries on CRC failure recovers about 135
  extra blocks on this capture, but costs up to 32 extra decodes per failed grant. Not enabled.
- **Dead code.** The old 4x1/4x2 functions in `precoding.c` should be deleted; nothing calls
  them.
- **Unrelated recorder bug.** The recording header's `record_duration_ns` field holds the end
  timestamp, not a duration.

---

## Files changed

| File | Change |
|---|---|
| `ngscope/src/dciLib/decode_sib.cpp` | CRC and message-type checks before SIB parsing |
| `lib/src/phy/mimo/precoding.c` | New generated 4-port codebook, `srsran_predecoding_multiplex_4port`, `srsran_predecoding_ccd_4port`; dispatchers routed to them |
| `lib/src/phy/phch/ra_dl.c` | 4-port pinfo → rank/TPMI mapping per 36.212; unsupported cases refused |
| `ngscope/src/dciLib/security_rrc.cpp` | Decode and write every passing codeword; comments corrected |
| `ngscope/src/dciLib/security_ctx.c`, `ngscope/hdr/dciLib/security_ctx.h` | Second-codeword counter in the teardown |
| `docs/*.md`, `.claude/skills/ngscope-measure/SKILL.md` | Corrected 4-port and pre-security claims |
