#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

mkdir "${TEST}"/hardlink
cd "${TEST}"/hardlink
cat >file1 <<EOF
Test file 1
EOF

ln file1 file2
cd -

"${TRACE}" cat "${TEST}"/hardlink/file1 "${TEST}"/hardlink/file2

rm "${TEST}"/hardlink/*
rmdir "${TEST}"/hardlink
