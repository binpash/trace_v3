#!/bin/sh
set -x

export PROJ_ROOT="$(git rev-parse --show-toplevel)"

cargo build --release
sudo install -o root -m 4755 "${PROJ_ROOT}/target/release/trace_v3" /usr/local/bin/
