#!/bin/bash
# Fast benchmark for an in-meeting report. Skips the full sweep in
# tests/timing/run-timing.sh and runs one short workload (`ls -lR
# /usr/include`) under all four scenarios + a microbenchmark for
# capture-rate. Total runtime: ~30s.
#
# Usage: sudo bash tests/bpftrace/quickbench.sh

set -e

PROJ_ROOT="${PROJ_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT=/tmp/bpftrace-quickbench
mkdir -p "$OUT"
chmod 777 "$OUT"

# Make sure tools are findable under sudo.
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/bin:$PATH"

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "hyperfine not found — install with: sudo apt-get install -y hyperfine"
    exit 1
fi
if ! command -v trace_v3 >/dev/null 2>&1; then
    echo "trace_v3 not found in PATH"
    exit 1
fi

WORKLOAD='ls -lR /usr/include >/dev/null 2>&1'
RUNS_BASE=20
RUNS_TOOL=5
WARMUPS=2

echo "==============================================="
echo " quickbench: ${WORKLOAD}"
echo " (baseline ${RUNS_BASE} runs, tool ${RUNS_TOOL} runs, warmup ${WARMUPS})"
echo "==============================================="

trace_v3 install >/dev/null 2>&1 || true

hyperfine --warmup "$WARMUPS" --min-runs "$RUNS_BASE" --ignore-failure \
    --export-json "$OUT/baseline.json" \
    "sh -c \"$WORKLOAD\""

hyperfine --warmup "$WARMUPS" --min-runs "$RUNS_TOOL" --ignore-failure \
    --export-json "$OUT/strace.json" \
    "strace -q -y -f --seccomp-bpf -e %file,fork,clone,fcntl sh -c \"$WORKLOAD\""

hyperfine --warmup "$WARMUPS" --min-runs "$RUNS_TOOL" --ignore-failure \
    --export-json "$OUT/bpftrace.json" \
    "${PROJ_ROOT}/tests/bpftrace/run.sh --dep-file /dev/null --events-file /dev/null -- sh -c \"$WORKLOAD\""

hyperfine --warmup "$WARMUPS" --min-runs "$RUNS_TOOL" --ignore-failure \
    --export-json "$OUT/trace_v3.json" \
    "trace_v3 --dep-file /dev/null --trace-file /dev/null --missed-file /dev/null -- sh -c \"$WORKLOAD\""

echo
echo "==============================================="
echo " throughput microbench: 5M openats, 1 process"
echo "==============================================="

cc -O3 -o "$OUT/test-throughput" "${PROJ_ROOT}/tests/throughput/test-throughput.c"

# trace_v3: report missed-event count at default 4M ringbuf
T0=$(date +%s.%N)
trace_v3 --dep-file /dev/null --trace-file /dev/null --missed-file "$OUT/missed_v3.txt" \
    -- "$OUT/test-throughput" >/dev/null 2>&1
T1=$(date +%s.%N)
TRACE_V3_TIME=$(awk "BEGIN{print $T1 - $T0}")
TRACE_V3_MISSED=$(cat "$OUT/missed_v3.txt" 2>/dev/null | tr -dc 0-9)
: "${TRACE_V3_MISSED:=0}"

# bpftrace: parse "Lost N events" from stderr
T0=$(date +%s.%N)
"${PROJ_ROOT}/tests/bpftrace/run.sh" \
    --dep-file /dev/null \
    --events-file "$OUT/bt_throughput.events" \
    -- "$OUT/test-throughput" >/dev/null 2>&1 || true
T1=$(date +%s.%N)
BPFTRACE_TIME=$(awk "BEGIN{print $T1 - $T0}")
BPFTRACE_LOST=$(grep -oE "Lost [0-9]+ events" \
    "$OUT/bt_throughput.events.bpftrace.stderr" 2>/dev/null \
    | grep -oE "[0-9]+" | head -1)
: "${BPFTRACE_LOST:=0}"

# Use python to summarise hyperfine JSONs.
python3 - <<EOF
import json, os
out = "$OUT"
def load(name):
    p = os.path.join(out, name)
    if not os.path.exists(p): return None
    d = json.load(open(p)).get("results", [])
    return d[0] if d else None

names = ["baseline", "strace", "bpftrace", "trace_v3"]
data = {n: load(f"{n}.json") for n in names}
b = data["baseline"]["mean"] if data["baseline"] else None

print()
print("==============================================")
print(" Latency (ls -lR /usr/include)")
print("==============================================")
print(f"  {'tool':<12} {'mean(s)':>9}  {'stddev':>8}  {'overhead':>10}")
for n in names:
    r = data[n]
    if not r: continue
    oh = (r['mean']/b - 1)*100 if b and n != "baseline" else 0
    oh_str = "baseline" if n == "baseline" else f"+{oh:.1f}%"
    print(f"  {n:<12} {r['mean']:>9.4f}  {r['stddev']:>8.4f}  {oh_str:>10}")
print()
print("==============================================")
print(" Throughput (5M openats, 1 process, 4M ringbuf vs 1024-page perf-rb)")
print("==============================================")
print(f"  trace_v3 wall: ${TRACE_V3_TIME}s, missed events: ${TRACE_V3_MISSED}")
print(f"  bpftrace wall: ${BPFTRACE_TIME}s, lost events: ${BPFTRACE_LOST}")
EOF
