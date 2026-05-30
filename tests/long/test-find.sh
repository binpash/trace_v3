#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests/long

SCRIPT_NAME=$(basename "$0" .sh)

fstrace \
    --dep-file "${TEST}/${SCRIPT_NAME}.deps" \
    --trace-file "${TEST}/${SCRIPT_NAME}.trace" \
    --missed-file "${TEST}/${SCRIPT_NAME}.missed" \
    -- sh -c "find / >/dev/null 2>&1"

[ $(($(cat "${TEST}/${SCRIPT_NAME}.missed"))) -eq 0 ]
