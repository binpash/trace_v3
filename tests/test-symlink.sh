#!/bin/sh
set -e

TRACE=$1

mkdir symlink
cd symlink
cat >file1 <<EOF
Test file 1
EOF

ln -s file1 file2
cd ..

"${TRACE}" cat symlink/file1 symlink/file2

rm symlink/*
rmdir symlink
