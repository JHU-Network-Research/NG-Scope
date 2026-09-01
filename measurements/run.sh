#!/bin/bash
# Usage: run.sh <config.toml> <label>
# Runs one replay and writes <label>.log plus a metrics summary to measurements/results/.
set -u
CFG="$1"; LABEL="$2"
RES=/src/measurements/results
mkdir -p "$RES"
OUT=/tmp/run_$LABEL
rm -rf "$OUT"; mkdir -p "$OUT"

start=$(date +%s)
timeout 3600 /src/build-docker/ngscope/src/ngscope -c "$CFG" -o "$OUT" > "$RES/$LABEL.log" 2>&1
rc=$?
end=$(date +%s)
wall=$((end-start))

D=$(ls -d $OUT/*/ 2>/dev/null | head -1)

{
echo "=============================================================="
echo "label            : $LABEL"
echo "config           : $CFG"
echo "exit / wall      : $rc / ${wall}s"
echo "--------------------------------------------------------------"
echo "cell             : $(grep -o 'Found Cell_id: *[0-9]*' "$RES/$LABEL.log" | tail -1)"
echo "cell_type.json   : $(tr -d '\n ' < $D/cell_type.json 2>/dev/null)"
echo "subframes        : $(grep -o 'assigned to decoder [0-9]* times' "$RES/$LABEL.log" | tail -1)"
echo "--------------------------------------------------------------"
TOTAL=$(cat $D/dci-decode-debug-*.csv 2>/dev/null | grep -c . )
echo "DCI rows         : $TOTAL"
echo "distinct RNTIs   : $(cat $D/dci-decode-debug-*.csv 2>/dev/null | awk -F, '{print $5}' | sort -u | grep -c .)"
echo "rach_ok == 0     : $(cat $D/dci-decode-debug-*.csv 2>/dev/null | awk -F, '$24==0' | grep -c .)"
echo "rach_ok == 1     : $(cat $D/dci-decode-debug-*.csv 2>/dev/null | awk -F, '$24==1' | grep -c .)"
echo "RAR rows         : $(( $(grep -c . $D/rar_log-0.csv 2>/dev/null || echo 1) - 1 ))"
echo "--- DCI format distribution (col 11) ---"
cat $D/dci-decode-debug-*.csv 2>/dev/null | awk -F, '{print $11}' | sort | uniq -c | sort -rn
echo "--- reports ---"
grep -E "^RACH filter|^TBS table probe|^SECURITY|^pcapng:" "$RES/$LABEL.log"
echo "=============================================================="
} > "$RES/$LABEL.metrics" 2>&1
cat "$RES/$LABEL.metrics"
