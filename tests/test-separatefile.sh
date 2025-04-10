#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

mkdir "${TEST}"/different
cd "${TEST}"/different
cat >file1 <<EOF
Test file 1
EOF

cat >file2 <<EOF
Test file 2
EOF
cd -

"${TRACE}" cat "${TEST}"/different/file1 "${TEST}"/different/file2

rm "${TEST}"/different/*
rmdir "${TEST}"/different
