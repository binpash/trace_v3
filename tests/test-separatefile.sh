#!/bin/sh
set -e

TRACE=$1

mkdir test1
cat >test1/file1 <<EOF
Test file 1
EOF

cat >test1/file2 <<EOF
Test file 2
EOF

"${TRACE}" cat test1/file1 test2/file2

rmdir test1
