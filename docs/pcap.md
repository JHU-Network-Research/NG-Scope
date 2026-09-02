# MAC pcap output

With `pcap_mac = true`, NG-Scope writes every decoded downlink MAC PDU to

```
<out_dir>/<YYYY_MM_DD_HH_MM_SS>/mac-<rf_idx>.pcapng
```

in the same MAC-LTE encapsulation srsRAN and LTESniffer use, so the file opens in Wireshark
and dissects up through RLC, PDCP and RRC wherever the contents are readable.

One file per RF device, deliberately: RNTIs are unique only within a cell, so merging two
cells' captures would silently misattribute them.

---

## Wireshark setup — required

DLT 147 is `DLT_USER0`. It has **no registered link type**, so a fresh Wireshark shows the
packets as opaque data until told what they are. This is a one-time setting.

**GUI:** Edit → Preferences → Protocols → DLT_USER → Encapsulations Table → **Edit** → **+**

| field | value |
|---|---|
| DLT | `User 0 (DLT=147)` |
| Payload protocol | `mac-lte-framed` |

**CLI**, no configuration needed:

```bash
tshark -r mac-0.pcapng \
  -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
```

The same `-o` works with `wireshark`.

### Getting RRC out of it

MAC alone is rarely what you want. Two dissector preferences do most of the work:

- **MAC-LTE** → *Attempt to decode BCCH, PCCH and CCCH data using LTE RRC dissector* — gives
  you SIBs, paging and Msg4.
- **MAC-LTE** → *Attempt to dissect LCID 1&2 as srb1&2* — hands SRB traffic to rlc-lte, which
  passes it to pdcp-lte and then the RRC dissector.

With both on, a readable `RRCConnectionSetup` or `SecurityModeCommand` shows up by name in the
packet list.

---

## Reorder before analysing

`tools/security_phase_join.py` now does this for you: the file it writes to `pcap_joined/`
is passed through `reordercap` unless you pass `--no-reorder`. For a raw `mac-<rf>.pcapng`
that has not been through the join, sort it yourself first:

```bash
reordercap mac-0.pcapng mac-0-sorted.pcapng
```

NG-Scope decodes subframes across several threads, so records are written in
decode-completion order, not TTI order. Typically 5–10% of records are out of order. pcapng
allows that and Wireshark will open the file either way — but the rlc-lte and pdcp-lte
dissectors do stateful, order-dependent reassembly, so out-of-order PDUs can produce spurious
reassembly failures and missed RRC messages.

**How much this costs in practice is unmeasured.** On the five captures here, sorting changed
nothing: an order-independent diff of all 2,891 dissected frames on a file with 267 records
out of order came back identical. The hazard is real in principle and the sort is cheap, so it
is on by default — but do not cite reordering as the explanation for a discrepancy without
checking, because on this data it explains none of them. The thing that *does* silently
undercount is reading `_ws.col.Info` instead of a field filter; see below.

Sorting is not done in-process on purpose. The reordering window is unbounded: under load the
scheduler parks subframes in a temporary buffer and replays them arbitrarily later, so no
fixed-size sort window would be correct. `reordercap` also already handles the pcapng block
bookkeeping, which is not worth reimplementing.

## Counting messages: use a field filter, not the Info column

`_ws.col.Info` holds one summary per *frame*, last writer wins, so a MAC PDU carrying several
SDUs reports only the last of them. Counting `SecurityModeCommand` that way found 7 on a
capture that holds 12 — a real 40% undercount that looked like a decoder bug. Filter on the
field instead, and use the outer element, not `..._r8_element`, which is absent when the
critical-extensions body does not dissect:

```bash
tshark -r sorted.pcapng -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""' \
  -Y 'lte-rrc.securityModeCommand_element' -T fields -e frame.comment \
  | grep -o 'rnti=0x[0-9a-f]*' | sort -u | wc -l
```

---

## The packet comment

Every record carries a comment, which is where NG-Scope puts what Wireshark has no field for:

```
sec=unknown ch=ccch mix=1 src=targeted rnti=0x1a2f tti=03051 rf=0 fmt=1A mcs=2 tbs=48
rv=0 prb=4 pid=0 tx=div evm=0.021 corr=0.940 dp=0.990 rach=1 ct=42424242 lcids=0,28,31
```

| key | meaning |
|---|---|
| `sec` | `unknown` / `pre` / `post` — where this PDU sits relative to its UE establishing AS security. Same three values as the `security_phase` field in the `.dciLog` files, so one grep spans both. |
| `ch` | logical channel: `bcch`, `pcch`, `rar`, `ccch`, `srb`, `drb`, `ce`, `pad`, or `dlsch` when the PDU was not parsed. |
| `mix=1` | present only when the PDU mixed several channel classes; `ch` then names the highest-precedence one and `lcids` lists everything. |
| `src` | how the RNTI was obtained — see below. |
| `rv`, `mcs`, `tbs`, `prb`, `pid` | grant parameters. `rv` is carried here because the mac-lte pseudo-header has no retransmission field. |
| `corr`, `dp` | PDCCH re-encode correlation and decode probability: how much to trust the DCI. |
| `ct` | the radio-domain collection time. The pcap timestamp is host wall-clock taken when the decoder picked the subframe up, which lags the air under load; `ct` is the precise instant but has a device-dependent epoch. `collection_times.csv` relates the two. |

### `src` is the field to read first

| value | meaning |
|---|---|
| `targeted`, `rar`, `sib` | the PDCCH CRC was checked **against a known RNTI**, so the RNTI is right. |
| `blind` | the RNTI was **recovered from the descrambled CRC** and may be fictional. |

The bytes are trustworthy either way — nothing reaches the file without passing the 24-bit
transport-block CRC, and since PDSCH scrambling is RNTI-dependent, a wrong RNTI yields noise
rather than a passing CRC. What `src=blind` qualifies is the *attribution*: any per-UE
conclusion, including the `sec` phase joined onto it, inherits that uncertainty.

---

## Useful filters

```
frame.comment contains "sec=post"      # traffic after AS security was established
frame.comment contains "src=targeted"  # verified-RNTI records only
frame.comment contains "ch=ccch"       # Msg4 / SRB0
mac-lte.rnti == 6703
mac-lte.rnti-type == 4                 # SI-RNTI
lte_rrc.securityModeCommand_element
```

---

## Known limitations

- **`sec` is almost always `unknown` in the raw file.** The boundary is the
  SecurityModeCommand, which arrives *after* the packets it bounds, so most records cannot be
  placed at the time they are written. Join against `security_log-<rf_idx>.csv` afterwards for
  the authoritative labelling.
- **A gap in the capture and a UE that never received a message look identical.** Under live
  capture the scheduler discards subframes when every decoder is busy, leaving holes with no
  marker in the file. Cross-reference `task_scheduler.txt`, and prefer replay mode when a
  coverage figure has to mean something.
- **Retransmissions appear as separate, near-identical packets.** Setting the MAC-LTE `isRetx`
  flag correctly needs per-HARQ-process state that NG-Scope does not keep; `rv` in the comment
  is a hint, not proof.
- **Uplink is not captured at all.** NG-Scope has no PUSCH receiver.
