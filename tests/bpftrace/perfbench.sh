#!/bin/bash
# Perf comparison for the meeting. 4 scenarios × 3 workloads:
#
#   baseline       - no tracing
#   bpftrace_raw   - bpftrace prints TSV events to /dev/null. Captures
#                    kernel-probe cost + perf-buffer-printf transport
#                    but no post-processing (no dep set produced).
#   bpftrace+post  - bpftrace events piped through post_process.py to
#                    build the Read/Write set (the full apples-to-apples
#                    pipeline).
#   trace_v3       - native pipeline; --dep-file /dev/null so we measure
#                    end-to-end including the Rust dep tracer.
#
# Workloads pick the kind of syscall-bound file work the timing harness
# already uses (a subset of run-timing.sh, smaller so this finishes
# quickly): find, ls -lR, grep -r.
#
# Usage: sudo bash tests/bpftrace/perfbench.sh > /tmp/perfbench.log 2>&1

set -e

PROJ_ROOT="${PROJ_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BT_DIR="${PROJ_ROOT}/tests/bpftrace"
OUT=/tmp/perfbench
mkdir -p "$OUT"
chmod 777 "$OUT"
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/bin:$PATH"

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "hyperfine not found — install with: sudo apt-get install -y hyperfine"
    exit 1
fi
if ! command -v trace_v3 >/dev/null 2>&1; then
    echo "trace_v3 not in PATH"
    exit 1
fi

trace_v3 install >/dev/null 2>&1 || true

WARMUPS=2
RUNS=5

# Standard syscall-heavy workloads from the existing timing harness.
declare -a WORKLOADS=(
    "find:find /usr/include -type f > /dev/null 2>&1"
    "ls:ls -lR /usr/include > /dev/null 2>&1"
    "grep:grep -r typedef /usr/include > /dev/null 2>&1"
)

# Each scenario is a shell prefix that we drop in front of the workload
# string. hyperfine wraps the result in `sh -c`.
declare -a SCENARIOS=(
    "baseline:"
    "bpftrace_raw:bpftrace -B none -q -c \"/bin/sh -c %CMD%\" ${BT_DIR}/trace_deps.bt >/dev/null 2>&1; sh -c \"true\""
    "bpftrace_post:${BT_DIR}/run.sh --dep-file /dev/null --events-file /dev/null -- sh -c"
    "trace_v3:trace_v3 --dep-file /dev/null --trace-file /dev/null --missed-file /dev/null -- sh -c"
)

# bpftrace_raw is special-cased below because the bpftrace command needs
# to embed the workload string with shell quoting that hyperfine itself
# does, so the simple "prefix" model doesn't quite work for it.

for entry in "${WORKLOADS[@]}"; do
    NAME="${entry%%:*}"
    CMD="${entry#*:}"
    echo "==========================================="
    echo "  workload: ${NAME}  -- ${CMD}"
    echo "==========================================="

    # baseline
    hyperfine --warmup $WARMUPS --min-runs $RUNS --ignore-failure \
        --export-json "$OUT/${NAME}_baseline.json" \
        "sh -c \"${CMD}\""

    WRAPPER=$(mktemp /tmp/bt_raw_wrap.XXXXXX.sh)
    cat > "$WRAPPER" <<EOF
#!/bin/sh
exec sh -c '${CMD}'
EOF
    chmod +x "$WRAPPER"

    # bpftrace silent — probes attached, every body is just a counter
    # bump. Measures kernel-side BPF cost without the text printf
    # transport. Gap to bpftrace_raw == transport cost.
    hyperfine --warmup $WARMUPS --min-runs $RUNS --ignore-failure \
        --export-json "$OUT/${NAME}_bpftrace_silent.json" \
        "bpftrace -B none -q -c \"/bin/sh $WRAPPER\" ${BT_DIR}/trace_deps_silent.bt >/dev/null 2>&1"

    # bpftrace raw — events to /dev/null, no post-processing.
    hyperfine --warmup $WARMUPS --min-runs $RUNS --ignore-failure \
        --export-json "$OUT/${NAME}_bpftrace_raw.json" \
        "BPFTRACE_STRLEN=100 BPFTRACE_PERF_RB_PAGES=1024 bpftrace -B none -q -c \"/bin/sh $WRAPPER\" ${BT_DIR}/trace_deps.bt >/dev/null 2>&1"

    rm -f "$WRAPPER"

    # bpftrace + post
    hyperfine --warmup $WARMUPS --min-runs $RUNS --ignore-failure \
        --export-json "$OUT/${NAME}_bpftrace_post.json" \
        "${BT_DIR}/run.sh --dep-file /dev/null --events-file /dev/null -- sh -c \"${CMD}\""

    # trace_v3
    hyperfine --warmup $WARMUPS --min-runs $RUNS --ignore-failure \
        --export-json "$OUT/${NAME}_trace_v3.json" \
        "trace_v3 --dep-file /dev/null --trace-file /dev/null --missed-file /dev/null -- sh -c \"${CMD}\""
done

# Single summary table.
python3 - <<'PY'
import json, os, sys
out = "/tmp/perfbench"
scenarios = ["baseline", "bpftrace_silent", "bpftrace_raw", "bpftrace_post", "trace_v3"]
workloads = ["find", "ls", "grep"]

def load(w, s):
    p = os.path.join(out, f"{w}_{s}.json")
    if not os.path.exists(p): return None
    r = json.load(open(p)).get("results", [])
    return r[0] if r else None

print()
print("===============================================================")
print("  Mean wall-clock per scenario (s)")
print("===============================================================")
print(f"  {'workload':<8} " + " ".join(f"{s:>14}" for s in scenarios))
for w in workloads:
    row = [load(w, s) for s in scenarios]
    means = [r['mean'] if r else None for r in row]
    cells = []
    for m in means:
        cells.append(f"{m:>14.4f}" if m is not None else f"{'-':>14}")
    print(f"  {w:<8} " + " ".join(cells))

print()
print("===============================================================")
print("  Overhead vs baseline  (lower is better)")
print("===============================================================")
print(f"  {'workload':<8} " + " ".join(f"{s:>14}" for s in scenarios[1:]))
for w in workloads:
    base = load(w, "baseline")
    if not base or not base.get('mean'):
        continue
    bm = base['mean']
    cells = []
    for s in scenarios[1:]:
        r = load(w, s)
        if r and r.get('mean'):
            cells.append(f"{r['mean']/bm:>13.1f}x")
        else:
            cells.append(f"{'-':>14}")
    print(f"  {w:<8} " + " ".join(cells))
PY
