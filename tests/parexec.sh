#!/bin/sh

if [ $# -eq 0 ]; then
    echo "Usage: $0 command [arg1 arg2 ...]"
    exit 1
fi

par_num="$1"

shift 1

command_to_run="$1"

shift 1

for i in $(seq 1 "$par_num")
do
    exec "$command_to_run" "$@" &
done

wait
