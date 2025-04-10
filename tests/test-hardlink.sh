#!/bin/sh
set -e

TRACE=$1

mkdir hardlink
cd hardlink
cat >file1 <<EOF
Test file 1
EOF

ln file1 file2
cd ..

"${TRACE}" cat hardlink/file1 hardlink/file2

rm hardlink/*
rmdir hardlink
