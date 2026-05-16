#!/bin/sh

set -ex

setup_apt() {
    sudo apt update
    sudo apt install -y gcc clang llvm libbpf-dev zlib1g-dev libelf-dev autopoint flex bison pkg-config
}

setup_apt
