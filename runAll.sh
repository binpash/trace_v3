#!/usr/bin/env bash
set -euo pipefail

TEST_FILE="ANYTHING"

# List of commands to test
CMDS=(
"ls | wc"
"tr -cs a-zA-Z '\n' < $TEST_FILE | uniq"
"bzip2 -c < $TEST_FILE | wc -c"
"gzip -c < $TEST_FILE | wc -c"
"awk '{count[\$1]++} END {for (i in count) print count[i], i}' < $TEST_FILE"
"sort -u < $TEST_FILE"
"sort -rn < $TEST_FILE | tee /dev/null"
"wc -lc < $TEST_FILE"
"find . -type f | wc -l"
"find . -type d | wc -l"
"head -n 5 $TEST_FILE"
"tail -n 5 $TEST_FILE"
"cut -d: -f1 $TEST_FILE | sort | uniq -c"
"cat $TEST_FILE | grep root"
)


i=0
for cmd in "${CMDS[@]}"; do
  i=$((i+1))
  echo "[$i] $cmd"

  # strace dump
  strace -y -f --seccomp-bpf -e %file,fork,clone -o "dump.txt" sh -c "$cmd"

  # analyze with trace_v2
  python3 trace_v2.py "dump.txt" > "trace_v2_$i.txt" 2>&1

  # run with fstrace
  sudo ./target/debug/fstrace sh -c "$cmd" > "fstrace_$i.txt" 2>&1

  rm "./dump.txt"
done
