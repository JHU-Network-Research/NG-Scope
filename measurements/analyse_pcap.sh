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
echo
echo "### message type x phase"
tshark -r "$F" -o "$DLT" -T fields -e _ws.col.Info -e frame.comment 2>/dev/null \
| python3 -c "
import sys, re
from collections import Counter
KEYS = ('SecurityModeCommand','RRCConnectionSetup','RRCConnectionReconfiguration',
        'RRCConnectionRelease','RRCConnectionReject','DLInformationTransfer',
        'UECapabilityEnquiry','RAR','Paging')
c, tot = Counter(), Counter()
for line in sys.stdin:
    p = line.rstrip('\n').split('\t')
    if len(p) < 2: continue
    info, cmt = p[0], p[1]
    m = re.search(r'sec=(\S+)', cmt)
    if not m: continue
    for k in KEYS:
        if k in info:
            c[(k, m.group(1))] += 1; tot[k] += 1
            break
for k in sorted(tot, key=lambda x: -tot[x]):
    parts = ' '.join(f'{ph}={c[(k,ph)]}' for ph in ('pre','post','unknown','n/a') if c[(k,ph)])
    print(f'  {k:<32} {tot[k]:>6}   {parts}')
"
echo
echo "### NAS message types"
tshark -r "$F" -o "$DLT" -V 2>/dev/null \
  | grep -oE "NAS EPS Mobility Management Message Type: [A-Za-z ]+" \
  | sed 's/.*Type: //' | sort | uniq -c | sort -rn
