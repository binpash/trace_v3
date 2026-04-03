#!/bin/sh

set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/correctness"

export TEST_OUTPUT="${TEST_OUTPUT:-$(mktemp -d /tmp/trace_v3_XXXX)}/correctness"
mkdir -p "${TEST_OUTPUT}"

failed=0
for f in ./test-*
do
    ./harness.sh $f || failed=1
done
exit $failed
