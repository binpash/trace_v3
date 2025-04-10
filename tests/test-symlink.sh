#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

mkdir "${TEST}"/symlink
cd "${TEST}"/symlink
cat >file1 <<EOF
Test file 1
EOF

ln -s file1 file2
cd -

"${TRACE}" cat "${TEST}"/symlink/file1 "${TEST}"/symlink/file2

rm "${TEST}"/symlink/*
rmdir "${TEST}"/symlink
