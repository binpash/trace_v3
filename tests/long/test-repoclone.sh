#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests/long
mkdir -p "${TEST}"/repoclone

SCRIPT_NAME=$(basename "$0" .sh)

fstrace \
    --dep-file "${TEST}/${SCRIPT_NAME}.deps" \
    --trace-file "${TEST}/${SCRIPT_NAME}.trace" \
    --missed-file "${TEST}/${SCRIPT_NAME}.missed" \
    -- sh -c "git clone https://github.com/git/git.git ${TEST}/repoclone >/dev/null 2>&1"

rm -rf "${TEST}"/repoclone

[ $(($(cat "${TEST}/${SCRIPT_NAME}.missed"))) -eq 0 ]
