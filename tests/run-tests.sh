#!/bin/sh

export PROJ_ROOT="$(git rev-parse --show-toplevel)"

export TRACE=hs_trace

for test in "${PROJ_ROOT}"/tests/test-*.sh
do
    ${test} 1>"${test}.out" 2>"${test}.err"

    echo "==== STDOUT ===="
    cat "${test}.out"
    echo "==== STDERR ===="
    cat "${test}.err"
done
