#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

mkdir "${TEST}"/bind1
mkdir "${TEST}"/bind2
cat >"${TEST}"/bind1/file <<EOF
Test file
EOF

sudo mount --bind "${TEST}"/bind1 "${TEST}"/bind2

"${TRACE}" cat "${TEST}"/bind1/file "${TEST}"/bind2/file

sudo umount "${TEST}"/bind2
rm "${TEST}"/bind1/*
rmdir "${TEST}"/bind1
