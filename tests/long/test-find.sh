#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests
TRACE=${TRACE:-$1}

"${TRACE}" sh -c "find /"

