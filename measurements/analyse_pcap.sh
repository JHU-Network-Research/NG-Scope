#!/bin/bash
# Cross-tabulate RRC/NAS message type against joined security phase.
# Usage: analyse_pcap.sh <mac-N.pcapng>
DLT='uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
F="$1"
echo "### $F"
capinfos "$F" 2>/dev/null | grep -E "Number of packets|Capture duration"
echo
echo "### phase distribution"
tshark -r "$F" -o "$DLT" -T fields -e frame.comment 2>/dev/null \
  | grep -o "sec=[a-z/]*" | sort | uniq -c

# A raw mac-<rf>.pcapng has sec=unknown on every packet by construction: ngscope parses
# nothing. Without this check the tables below are all zeros and look like a finding.
if ! tshark -r "$F" -o "$DLT" -T fields -e frame.comment 2>/dev/null \
     | grep -qE "sec=(pre|post|reused|noctx|none)"; then
    echo
    echo "ERROR: every packet is sec=unknown -- this pcap has not been scanned."
    echo "Run tools/security_scan.py over the run directory and use pcap_joined/ instead."
    exit 1
fi
echo
# Field filters, never _ws.col.Info: that holds one summary per frame, last writer wins, so
# a MAC PDU carrying several SDUs reports only the last of them. It undercounted
# SecurityModeCommand 7-vs-12 on a real capture.
echo "### message type x phase"
tshark -r "$F" -o "$DLT" -T fields -E occurrence=a -e frame.comment \
  -e lte-rrc.securityModeCommand_element -e lte-rrc.rrcConnectionSetup_element \
  -e lte-rrc.rrcConnectionRelease_element -e lte-rrc.rrcConnectionReject_element \
  -e lte-rrc.rrcConnectionReestablishment_element -e lte-rrc.rrcConnectionResume_r13_element \
  2>/dev/null \
| python3 -c "
import sys, re
from collections import Counter
NAMES = ['securityModeCommand','rrcConnectionSetup','rrcConnectionRelease',
         'rrcConnectionReject','rrcConnectionReestablishment','rrcConnectionResume']
c, tot = Counter(), Counter()
for line in sys.stdin:
    f = line.rstrip('\n').split('\t')
    if not f: continue
    m = re.search(r'sec=(\S+)', f[0])
    if not m: continue
    for i, name in enumerate(NAMES, start=1):
        if len(f) > i and f[i].strip():
            n = len([t for t in f[i].split(',') if t.strip()])
            c[(name, m.group(1))] += n; tot[name] += n
for k in sorted(tot, key=lambda x: -tot[x]):
    parts = ' '.join(f'{ph}={c[(k,ph)]}' for ph in
                     ('pre','post','reused','noctx','none','unknown','n/a') if c[(k,ph)])
    print(f'  {k:<32} {tot[k]:>6}   {parts}')
"

echo
echo "### NAS message types"
tshark -r "$F" -o "$DLT" -V 2>/dev/null \
  | grep -oE "NAS EPS Mobility Management Message Type: [A-Za-z ]+" \
  | sed 's/.*Type: //' | sort | uniq -c | sort -rn
