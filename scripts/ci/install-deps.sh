#!/bin/sh
set -eu
. /etc/os-release
case "$ID" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git build-essential cmake perl \
      clang libclang-dev pkg-config python3 python3-venv openssl nodejs golang-go openjdk-21-jdk-headless binutils
    rm -rf /var/lib/apt/lists/*
    ;;
  fedora)
    # Exclude optional desktop dependencies; Java/JSSE and all client defaults
    # remain the distribution packages. Bound slow mirror retries in CI.
    dnf install -y --setopt=install_weak_deps=False --setopt=timeout=30 --setopt=minrate=10000 \
      ca-certificates curl-minimal git gcc gcc-c++ make cmake perl clang \
      clang-devel pkgconf-pkg-config python3 python3-pip openssl nodejs golang java-21-openjdk-devel binutils
    dnf clean all
    ;;
  alpine)
    apk add --no-cache ca-certificates curl git build-base cmake perl clang clang-dev llvm-dev \
      pkgconf python3 py3-pip openssl nodejs go openjdk21-jdk linux-headers binutils
    ;;
  *) echo "Unsupported distribution: $ID" >&2; exit 2 ;;
esac
