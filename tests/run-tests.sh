#!/bin/sh

export PROJ_ROOT="$(git rev-parse --show-toplevel)"

export TRACE=$(which trace_v3)

for test in "${PROJ_ROOT}"/tests/correctness/test-*.sh
do
    echo "Running $(basename $test)"
    ${test} 1>"${test}.out" 2>"${test}.err"
    echo "==== STDOUT ===="
    cat "${test}.out"
    echo "==== STDERR ===="
    cat "${test}.err"
done

for test in "${PROJ_ROOT}"/tests/short/test-*.sh
do
    echo "Running $(basename $test)"
    ${test} 1>"${test}.out" 2>"${test}.err"
    echo "==== STDOUT ===="
    cat "${test}.out"
    echo "==== STDERR ===="
    cat "${test}.err"
done

for test in "${PROJ_ROOT}"/tests/long/test-*.sh
do
    echo "Running $(basename $test)"
    ${test} 1>"${test}.out" 2>"${test}.err"
    echo "==== STDOUT ===="
    cat "${test}.out"
    echo "==== STDERR ===="
    cat "${test}.err"
done
