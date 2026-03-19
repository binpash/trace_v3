#!/bin/sh
set -x

export PROJ_ROOT="$(git rev-parse --show-toplevel)"

cargo build --release
sudo install -o root -m 4755 "${PROJ_ROOT}/target/release/trace_v3" /usr/local/bin/

sudo mkdir -p /usr/local/share/man/man1
sudo install -o root -m 0644 "${PROJ_ROOT}/man/trace_v3.1" /usr/local/share/man/man1/trace_v3.1

sudo mandb
