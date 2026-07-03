#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic: Rust binary + pre-compiled BPF objects.
# Pre-compiles BPF objects so end users don't need clang/libbpf-dev.
# Supports --system (system-wide) and --user (default, ~/.local).
# Run WITHOUT sudo: the script escalates via sudo ONLY for --system install steps.

set -euo pipefail

PROJECT_NAME="zelynic"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="https://github.com/oxyzenQ/zelynic"

usage() {
    cat <<EOF
Usage: $0 [--system|--user]

  --system   Install system-wide:
               binary       → /usr/bin/${PROJECT_NAME}
               BPF objects  → /usr/lib/${PROJECT_NAME}/
             (script invokes sudo for the install steps)
  --user     Install to user-local (default, no sudo):
               binary       → ~/.local/bin/${PROJECT_NAME}
               BPF objects  → ~/.local/lib/${PROJECT_NAME}/

The BPF compile step (clang) and build step (cargo build --release --locked)
ALWAYS run as the current user. Sudo is used ONLY for the install steps in
--system mode.
EOF
}

MODE="--user"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --system) MODE="--system"; shift ;;
        --user)   MODE="--user";   shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

cd "${REPO_ROOT}"

if [[ ! -f Cargo.toml ]]; then
    echo "error: Cargo.toml not found. Run this script from the repo root." >&2
    exit 1
fi

# Step 1: Compile BPF objects (if clang available, or use pre-compiled)
# Runs as the current user — writes to the repo's bpf/ directory.
BPF_DIR="bpf"
BPF_LIMITER="${BPF_DIR}/limiter.bpf.o"
BPF_OBSERVER="${BPF_DIR}/observer.bpf.o"

if [[ ! -f "${BPF_LIMITER}" ]] || [[ ! -f "${BPF_OBSERVER}" ]]; then
    if command -v clang >/dev/null 2>&1; then
        echo ">> [1/3] Compiling BPF objects..."
        ARCH_INCLUDE=""
        if [[ -d "/usr/include/$(uname -m)-linux-gnu" ]]; then
            ARCH_INCLUDE="-I/usr/include/$(uname -m)-linux-gnu"
        fi
        clang -O2 -g -target bpf ${ARCH_INCLUDE} \
            -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
        clang -O2 -g -target bpf ${ARCH_INCLUDE} \
            -c bpf/observer.bpf.c -o bpf/observer.bpf.o
        echo "   BPF objects compiled"
    else
        echo "error: BPF objects not found and clang not installed." >&2
        echo "  Install clang + libbpf-dev, or download pre-compiled release." >&2
        echo "  On Ubuntu/Debian: sudo apt install clang libbpf-dev linux-libc-dev" >&2
        echo "  On Arch: sudo pacman -S clang libbpf" >&2
        exit 1
    fi
else
    echo ">> [1/3] BPF objects already compiled (using pre-compiled)"
fi

# Step 2: Build Rust binary with eBPF feature
# Runs as the current user — cargo cache stays user-owned.
echo ">> [2/3] Building ${PROJECT_NAME} with eBPF support (release, locked)..."
cargo build --release --locked --features ebpf

BINARY="target/release/${PROJECT_NAME}"
if [[ ! -f "${BINARY}" ]]; then
    echo "error: build produced no binary at ${BINARY}" >&2
    exit 1
fi

# Step 3: Install binary + BPF objects
# Sudo is used ONLY for --system mode install steps.
echo ">> [3/3] Installing ${PROJECT_NAME} (${MODE})"
case "${MODE}" in
    --system)
        sudo install -Dm755 "${BINARY}" "/usr/bin/${PROJECT_NAME}"
        echo "   installed: /usr/bin/${PROJECT_NAME}"
        sudo install -d "/usr/lib/${PROJECT_NAME}"
        sudo install -Dm644 "${BPF_LIMITER}"  "/usr/lib/${PROJECT_NAME}/limiter.bpf.o"
        sudo install -Dm644 "${BPF_OBSERVER}" "/usr/lib/${PROJECT_NAME}/observer.bpf.o"
        echo "   BPF objects installed: /usr/lib/${PROJECT_NAME}/"
        ;;
    --user)
        user_bin="${HOME}/.local/bin"
        user_bpf="${HOME}/.local/lib/${PROJECT_NAME}"
        mkdir -p "${user_bin}" "${user_bpf}"
        install -Dm755 "${BINARY}" "${user_bin}/${PROJECT_NAME}"
        echo "   installed: ${user_bin}/${PROJECT_NAME}"
        install -Dm644 "${BPF_LIMITER}"  "${user_bpf}/limiter.bpf.o"
        install -Dm644 "${BPF_OBSERVER}" "${user_bpf}/observer.bpf.o"
        echo "   BPF objects installed: ${user_bpf}/"
        ;;
esac

echo
echo ">> Done."
echo
echo "Next steps:"
case "${MODE}" in
    --system)
        echo "  - Verify eBPF support: ${PROJECT_NAME} doctor"
        echo "  - Run: ${PROJECT_NAME} --help"
        ;;
    --user)
        echo "  - Ensure ~/.local/bin is on your PATH"
        echo "  - Verify eBPF support: ${PROJECT_NAME} doctor"
        echo "  - Run: ${PROJECT_NAME} --help"
        ;;
esac
echo "  - Uninstall: ./scripts/uninstall.sh"
echo "  - Docs: ${REPO_URL}#readme"
