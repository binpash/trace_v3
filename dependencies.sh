#!/bin/sh

set -ex




setup_apt() {
    sudo apt install gcc clang llvm libbpf-dev zlib1g-dev libelf-dev autopoint flex bison
}


setup_apt
