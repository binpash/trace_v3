#!/usr/bin/env bash

END_TIME=$((SECONDS + 20))
echo $$
ls
while [ $SECONDS -lt $END_TIME ]; do
    sleep 4
    ls
done

