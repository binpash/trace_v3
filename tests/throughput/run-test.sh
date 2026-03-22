#!/bin/sh

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 proc_count event_freq"
    exit 1
fi

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/throughput"

export TEST_OUTPUT="${TEST_OUTPUT:-$(mktemp -d /tmp/trace_v3_XXXX)}/throughput"
mkdir -p "${TEST_OUTPUT}"

par_num="$1"
shift 1

freq="$1"
shift 1

for i in $(seq 1 "$par_num")
do
    exec ./test-throughput $freq &
done

wait
