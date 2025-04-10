#!/bin/sh
set -e

TRACE=$1

mkdir bind1
cat >bind1/file <<EOF
Test file
EOF

sudo mount --bind bind1 bind2

"${TRACE}" cat bind1/file bind2/file

sudo umount bind2
rm bind1/*
rmdir bind1
