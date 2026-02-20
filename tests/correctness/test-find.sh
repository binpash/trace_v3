#!/bin/sh

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

TRACE_V3_OUTPUT=$(mktemp)
STRACE_OUTPUT=$(mktemp)

echo trace_v3
"${TRACE}" --dep-file /dev/null --trace-file $TRACE_V3_OUTPUT -- find /

echo strace
strace -y -f --seccomp-bpf -e %file,fork,clone,fcntl -o $STRACE_OUTPUT -- find /

echo get syscalls
cat $TRACE_V3_OUTPUT | cut -d'(' -f1 > "${TRACE_V3_OUTPUT}calls"
cat $STRACE_OUTPUT | cut -d' ' -f2 | cut -d'(' -f1 > "${STRACE_OUTPUT}calls"

echo diff
diff "${TRACE_V3_OUTPUT}calls" "${STRACE_OUTPUT}calls"

echo done
