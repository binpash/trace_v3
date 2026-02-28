#!/bin/sh

test_name=$(basename "${1}" .sh)
export TEST_OUTPUT="${TEST_OUTPUT:-$(mktemp -d /tmp/trace_v3_XXXX)/correctness}/${test_name}"
mkdir -p "${TEST_OUTPUT}"

echo Running correctness harness for ${test_name}
cat "./${test_name}.sh"

trace_v3 --dep-file /dev/null --trace-file "${TEST_OUTPUT}/trace_v3_log" -- "./${test_name}.sh" >/dev/null 2>&1

strace -y -f --seccomp-bpf -e %file,fork,clone,fcntl -o "${TEST_OUTPUT}/strace_log" -- "./${test_name}.sh" >/dev/null 2>&1

cat "${TEST_OUTPUT}/trace_v3_log" | cut -d'(' -f1 > "${TEST_OUTPUT}/trace_v3_calls"
cat "${TEST_OUTPUT}/strace_log" | cut -d' ' -f2 | cut -d'(' -f1 | grep -v "+++" > "${TEST_OUTPUT}/strace_calls"

diff "${TEST_OUTPUT}/trace_v3_calls" "${TEST_OUTPUT}/strace_calls" > "${TEST_OUTPUT}/diff"
diff_status=$?

echo Reported results for "$@" in "${TEST_OUTPUT}"
cat "${TEST_OUTPUT}/diff"
exit $diff_status
