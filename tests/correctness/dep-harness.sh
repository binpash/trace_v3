#!/bin/sh
# Dependency-set correctness harness for the bpftrace contender.
#
# The strace-comparison harness in this directory diffs syscall sequences,
# which only makes sense between two tracers that emit a syscall log
# (trace_v3 and strace both do). bpftrace + post_process.py instead produces
# the same artifact that trace_v3's --dep-file produces: a sorted Read set
# and Write set with ancestor-directory closure.
#
# This harness runs both pipelines on the same test command and diffs the
# dependency summaries. A nonzero exit means the dep sets disagree —
# typically an unhandled syscall on the bpftrace side, or a path-resolution
# bug.
#
# Usage:
#   ./dep-harness.sh ./test-find.sh        # uses default output dir
#   TEST_OUTPUT=/tmp/foo ./dep-harness.sh ./test-find.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
BT_DIR="${PROJ_ROOT}/tests/bpftrace"

if [ $# -lt 1 ]; then
    echo "usage: $0 <test-script>" >&2
    exit 2
fi

TEST_SCRIPT="$1"
test_name=$(basename "${TEST_SCRIPT}" .sh)
export TEST_OUTPUT="${TEST_OUTPUT:-$(mktemp -d /tmp/trace_v3_XXXX)/correctness-deps}/${test_name}"
mkdir -p "${TEST_OUTPUT}"

cd "${SCRIPT_DIR}"

echo "=== dep-harness: ${test_name} ==="

# trace_v3 leg.
trace_v3 \
    --dep-file "${TEST_OUTPUT}/trace_v3.deps" \
    --trace-file /dev/null \
    --missed-file "${TEST_OUTPUT}/trace_v3.missed" \
    -- "${TEST_SCRIPT}" >"${TEST_OUTPUT}/trace_v3.stdout" 2>"${TEST_OUTPUT}/trace_v3.stderr"

# bpftrace+post leg.
"${BT_DIR}/run.sh" \
    --dep-file "${TEST_OUTPUT}/bpftrace.deps" \
    --events-file "${TEST_OUTPUT}/bpftrace.events" \
    -- "${TEST_SCRIPT}" >"${TEST_OUTPUT}/bpftrace.stdout" 2>"${TEST_OUTPUT}/bpftrace.stderr"

# The two pipelines emit identical formats so a unified diff is the report.
if diff -u "${TEST_OUTPUT}/trace_v3.deps" "${TEST_OUTPUT}/bpftrace.deps" >"${TEST_OUTPUT}/diff"; then
    echo "PASS: dep sets match (${TEST_OUTPUT})"
    exit 0
fi

# Decompose the diff so callers can see the asymmetry directly.
echo "FAIL: dep sets differ (${TEST_OUTPUT}/diff)"
echo "      summary:"
echo "        trace_v3 reads:  $(awk '/^Read set/{f=1;next} /^Write set/{f=0} f' "${TEST_OUTPUT}/trace_v3.deps" | wc -l) entries"
echo "        bpftrace reads:  $(awk '/^Read set/{f=1;next} /^Write set/{f=0} f' "${TEST_OUTPUT}/bpftrace.deps" | wc -l) entries"
echo "        trace_v3 writes: $(awk '/^Write set/{f=1;next} f' "${TEST_OUTPUT}/trace_v3.deps" | wc -l) entries"
echo "        bpftrace writes: $(awk '/^Write set/{f=1;next} f' "${TEST_OUTPUT}/bpftrace.deps" | wc -l) entries"
echo "      first 30 lines of diff:"
head -n 30 "${TEST_OUTPUT}/diff" | sed 's/^/        /'
exit 1
