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

## What tshark needs

Two audiences, and they need different things. `tools/security_scan.py` is **self-contained**
— it passes everything it depends on and reads no saved Wireshark configuration. Opening the
same file in the Wireshark GUI is not, because there is no command line to put the mapping on.

| | the automated scan | the GUI, by hand |
|---|---|---|
| `tshark` on `PATH` | required | — |
| `reordercap` on `PATH` | **recommended** — absence degrades, see below | only if sorting manually |
| DLT 147 → `mac-lte-framed` | passed with `-o`, nothing to configure | **must be set once**, below |
| LTE dissector preferences | Wireshark defaults are correct | same |
| AppArmor allowance for `$HOME` | **required on Ubuntu**, below | required |
| Python | 3, standard library only | — |

Verified against **tshark 4.6.4**. No minimum version has been established; every scan records
the version it ran under in `security_summary.json` (`tshark_version`), so a result can be
attributed after the fact.

`reordercap` is recommended rather than required: without it `security_scan.py` copies the
capture unsorted and says so in the `reorder` status, both on the console and in the summary
JSON. That is a real cost, not a cosmetic one — the rlc-lte and pdcp-lte dissectors reassemble
statefully and in order, so an unsorted file can lose RRC messages. It is reported rather than
fatal because the loss is silent otherwise, and on the captures here it measured as zero
(see [Reorder before analysing](#reorder-before-analysing)).

**Check the whole chain in one command.** If the protocol chain ends in `mac-lte`, everything
below is already in place:

```bash
tshark -r mac-0.pcapng -c 1 -T fields -e frame.protocols \
  -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
```

| output | meaning |
|---|---|
| `user_dlt:mac-lte-framed:mac-lte` | correct — dissecting as LTE MAC |
| `user_dlt:data` | the mapping did not take effect; frames read, nothing decoded |
| `You don't have permission to read the file` | AppArmor, not the filesystem — see below |

### DLT 147 — the one thing that is not a default

DLT 147 is `DLT_USER0`. It has **no registered link type**, so a fresh Wireshark shows the
packets as opaque data until told what they are.

**CLI** — no configuration needed, and this is what `security_scan.py` does:

```bash
tshark -r mac-0.pcapng \
  -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
```

**GUI** — a one-time setting, since there is no command line:
Edit → Preferences → Protocols → DLT_USER → Encapsulations Table → **Edit** → **+**

| field | value |
|---|---|
| DLT | `User 0 (DLT=147)` |
| Payload protocol | `mac-lte-framed` |

That writes `~/.config/wireshark/user_dlts`. The same `-o` works with `wireshark` too, if you
would rather not persist it.

### The LTE dissector preferences are already correct

`tshark -G defaultprefs` on 4.6.4 shows the whole MAC → RLC → PDCP → RRC chain enabled out of
the box, so **there is nothing to turn on**:

| preference | default | what it gives you |
|---|---|---|
| `mac-lte.attempt_rrc_decode` | `TRUE` | SIBs, paging and Msg4 from BCCH/PCCH/CCCH |
| `mac-lte.attempt_to_dissect_srb_sdus` | `TRUE` | LCID 1&2 handed to rlc-lte |
| `rlc-lte.call_pdcp_for_srb` | `TRUE` | SRB traffic reaches pdcp-lte |
| `rlc-lte.call_rrc_for_ccch` | `TRUE` | CCCH reaches the RRC dissector |
| `pdcp-lte.show_signalling_plane_as_rrc` | `TRUE` | `SecurityModeCommand` by name |
| `rlc-lte.do_sequence_analysis_am` | `Only-MAC-frames` | the reassembly and skipped-frame counts the scan reads back as a coverage check |

Worth stating because it is easy to assume otherwise and then to "fix" a scan by changing
preferences, which makes the result depend on one machine's saved config.

Measured, not assumed: the same capture scanned under the normal `HOME` and under a pristine
one with no Wireshark configuration at all gives **byte-identical** `security_events-0.csv`
and `security_sessions-0.csv`, and a `security_summary.json` identical apart from `run_dir`.

If a future Wireshark changes a default, `assert_dissected()` catches the MAC layer going away
but not a quieter change further up the chain — `fields_queried` and `tshark_version` in the
summary are what make that diagnosable after the fact.

### AppArmor: tshark may be refused files under `$HOME`

Ubuntu ships `/etc/apparmor.d/tshark`, a Canonical profile confining `/usr/bin/tshark`. It
grants read access to `/tmp` (via `abstractions/user-tmp`) and `/usr/share/wireshark`, and
nothing under `$HOME`. The profile does contain `file r /**.pcap{,ng}{,.gz}` — but inside the
nested `dumpcap` subprofile, which covers live capture, not `tshark -r`.

The symptom is misleading, because it is not a filesystem problem:

```
tshark: You don't have permission to read the file ".../pcap_joined/mac-0.pcapng"
tshark: Error loading table 'User DLTs Table': Permission denied
```

while `ls -l` shows the file owned by you and mode `rw-rw-r--`, and `cat` reads it fine. The
give-away is that the *same bytes* dissect when copied to `/tmp`.

The profile ends with `include if exists <local/tshark>`, which is the supported place to
widen it:

```bash
sudo tee /etc/apparmor.d/local/tshark >/dev/null <<'EOF'
file r @{HOME}/**.pcap{,ng}{,.gz},
file r @{HOME}/.config/wireshark/{,**},
EOF
sudo apparmor_parser -r /etc/apparmor.d/tshark
```

The second rule fixes the `User DLTs Table` denial, which otherwise appears on *every* run.
It is harmless only because `security_scan.py` passes the mapping with `-o` — but it means
the GUI-configured mapping is unavailable, so anything relying on saved preferences silently
gets no dissection.

Note the first rule matches by **extension**: a capture named anything other than
`.pcap`/`.pcapng`/`.gz` is still refused. `security_scan.py` detects a confinement denial,
distinguishes it from an ordinary POSIX one, and prints the existing override's contents when
there is one.

**Only `tshark` is confined.** `reordercap`, `editcap`, `capinfos`, `mergecap`, `rawshark` and
`sharkd` have no profile, which is why the reorder step succeeds and only the dissection
fails.

### Do not switch to `sharkd` to dodge this

It is a tempting fix — `sharkd` is the same libwireshark and reads `$HOME` fine — but it
trades a loud failure for a silent one. `sharkd` has **no `-o`**; its only preference control
is `-C <config profile>`, so the DLT 147 mapping can only come from config on disk. Measured
with a pristine `HOME`:

| | result |
|---|---|
| `sharkd`, no `user_dlts` | `{"status":"OK"}`, all frames loaded, protocol `Packet`, **no dissection and no error** |
| `tshark`, no `-o` | undissected too, but `-o` is passed on every invocation so it cannot happen |
| `tshark`, with `-o` | MAC-LTE / RLC-LTE / RRC |

A scan that dissects nothing finds no RRC events, and zero events across a populated capture
is this project's *positive* result. `sharkd` would report "no UE reached AS security" with
nothing distinguishing it from the real thing. `assert_dissected()` in `security_scan.py`
exists to make that impossible whichever tool is used: frames present and none dissecting as
`mac-lte` is a hard error.

### Getting RRC out of it

MAC alone is rarely what you want, but the two preferences that do the work —
*Attempt to decode BCCH, PCCH and CCCH data using LTE RRC dissector* and *Attempt to dissect
LCID 1&2 as srb1&2* — are both on by default (see the table above). A readable
`RRCConnectionSetup` or `SecurityModeCommand` shows up by name in the packet list as soon as
the DLT mapping is set. If it does not, check the mapping before touching anything else.

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

- **`sec` is always `unknown` in the raw file, by construction.** The boundary is the
  SecurityModeCommand, which arrives *after* the packets it bounds, so most records cannot be
  placed at the time they are written. Run `tools/security_scan.py` afterwards for
  the authoritative labelling.
- **A gap in the capture and a UE that never received a message look identical.** Under live
  capture the scheduler discards subframes when every decoder is busy, leaving holes with no
  marker in the file. Cross-reference `task_scheduler.txt`, and prefer replay mode when a
  coverage figure has to mean something.
- **Retransmissions appear as separate, near-identical packets.** Setting the MAC-LTE `isRetx`
  flag correctly needs per-HARQ-process state that NG-Scope does not keep; `rv` in the comment
  is a hint, not proof.
- **Uplink is not captured at all.** NG-Scope has no PUSCH receiver.
