#!/bin/sh
set -e

TRACE=$1

mkdir different
cat >different/file1 <<EOF
Test file 1
EOF

cat >different/file2 <<EOF
Test file 2
EOF

"${TRACE}" cat different/file1 different/file2

rm different/*
rmdir different
