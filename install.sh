#!/bin/sh
set -ex

export PROJ_ROOT="$(git rev-parse --show-toplevel)"

cargo build --release
sudo install -o root -m 4755 "${PROJ_ROOT}/target/release/trace_v3" /usr/local/bin/

MAN_SRC="$(find "${PROJ_ROOT}/target" -path '*/out/trace_v3.1' | head -n1)"

sudo mkdir -p /usr/local/share/man/man1
sudo install -o root -m 0644 "$MAN_SRC" /usr/local/share/man/man1/trace_v3.1

sudo mandb
