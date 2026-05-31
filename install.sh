#!/bin/sh
set -ex

PROJ_ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! command -v rustup > /dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    . "$HOME/.cargo/env"
fi

if ! command -v uv > /dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    . "$HOME/.local/bin/env"
fi

if ! command -v hyperfine > /dev/null 2>&1; then
    cargo install hyperfine
fi

if [ ! -d "${PROJ_ROOT}/.venv" ]; then
    uv venv "${PROJ_ROOT}/.venv"
    uv pip install --python "${PROJ_ROOT}/.venv" -r "${PROJ_ROOT}/requirements.txt"
fi

cargo build --release
sudo install -o root -m 4755 "${PROJ_ROOT}/target/release/fstrace" /usr/local/bin/

MAN_SRC="$(find "${PROJ_ROOT}/target" -path '*/out/fstrace.1' | head -n1)"

sudo mkdir -p /usr/local/share/man/man1
sudo install -o root -m 0644 "$MAN_SRC" /usr/local/share/man/man1/fstrace.1

sudo mandb
