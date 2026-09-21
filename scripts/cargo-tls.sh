#!/bin/sh
# Build the pinned backend patch without modifying Cargo registry sources.
set -eu
command=${1:?usage: sh scripts/cargo-tls.sh build|test|clippy|check [cargo options]}
shift
case "$command" in build|test|clippy|check) ;; *) echo "unsupported cargo command" >&2; exit 2;; esac
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
BORING_BSSL_SOURCE_PATH=$(python3 "$script_dir/prepare_tls.py")
export BORING_BSSL_SOURCE_PATH
export BORING_BSSL_ASSUME_PATCHED=1
exec cargo "$command" --features patched-tls "$@"
