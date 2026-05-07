#!/bin/sh
# Drive dep-harness.sh across every test-*.sh in this directory. Mirrors the
# structure of run-harness.sh but compares trace_v3 vs bpftrace dependency
# sets rather than trace_v3 vs strace syscall sequences.

set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/correctness"

export TEST_OUTPUT="${TEST_OUTPUT:-$(mktemp -d /tmp/trace_v3_XXXX)}/correctness-deps"
mkdir -p "${TEST_OUTPUT}"

failed=0
for f in ./test-*.sh; do
    ./dep-harness.sh "$f" || failed=1
done
exit $failed
