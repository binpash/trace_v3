#!/bin/sh
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
TEST="${PROJ_ROOT}"/tests/long
TRACE=${TRACE:-$1}

mkdir -p "${TEST}"/repoclone
cd "${TEST}"/repoclone

"${TRACE}" sh -c "git clone https://github.com/git/git.git"

rm -rf "${TEST}"/repoclone/*
rmdir "${TEST}"/repoclone
