#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
# Pre-compiles BPF objects so end users don't need clang/libbpf-dev.
#
# Usage:
#   ./scripts/install.sh --user     → install to ~/.local/bin (default)
#   ./scripts/install.sh --system   → install to /usr/bin (requires sudo)

set -euo pipefail

PROJECT_NAME="zelynic"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_MODE="--user"

# Parse args
for arg in "$@"; do
    case "$arg" in
        --system) INSTALL_MODE="--system" ;;
        --user)   INSTALL_MODE="--user" ;;
        --help|-h)
            echo "Usage: $0 [--system|--user]"
            echo "  --user    Install to ~/.local/bin (default)"
            echo "  --system  Install to /usr/bin (requires sudo)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--system|--user]"
            exit 1
            ;;
    esac
done

cd "${REPO_ROOT}"

# Step 1: Compile BPF objects (if clang available, or use pre-compiled)
BPF_DIR="bpf"
BPF_LIMITER="${BPF_DIR}/limiter.bpf.o"
BPF_OBSERVER="${BPF_DIR}/observer.bpf.o"

if [[ ! -f "${BPF_LIMITER}" ]] || [[ ! -f "${BPF_OBSERVER}" ]]; then
    if command -v clang >/dev/null 2>&1; then
        echo "Compiling BPF objects..."
        ARCH_INCLUDE=""
        if [[ -d "/usr/include/$(uname -m)-linux-gnu" ]]; then
            ARCH_INCLUDE="-I/usr/include/$(uname -m)-linux-gnu"
        fi
        clang -O2 -g -target bpf ${ARCH_INCLUDE} \
            -c bpf/limiter.bpf.c -o bpf/limiter.bpf.o
        clang -O2 -g -target bpf ${ARCH_INCLUDE} \
            -c bpf/observer.bpf.c -o bpf/observer.bpf.o
        echo "✓ BPF objects compiled"
    else
        echo "ERROR: BPF objects not found and clang not installed."
        echo "  Install clang + libbpf-dev, or download pre-compiled release."
        echo "  On Ubuntu/Debian: sudo apt install clang libbpf-dev linux-libc-dev"
        echo "  On Arch: sudo pacman -S clang libbpf"
        exit 1
    fi
else
    echo "✓ BPF objects already compiled (using pre-compiled)"
fi

# Step 2: Build Rust binary with eBPF feature
echo "Building ${PROJECT_NAME} with eBPF support..."
cargo build --release --locked --features ebpf

# Step 3: Install binary + BPF objects
if [[ "${INSTALL_MODE}" == "--system" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "System install requires root. Run with sudo."
        echo "  sudo ./scripts/install.sh --system"
        exit 1
    fi
    # Install binary
    install -Dm755 "target/release/${PROJECT_NAME}" "/usr/bin/${PROJECT_NAME}"
    # Install BPF objects to /usr/lib/zelynic/
    install -d /usr/lib/zelynic
    install -Dm644 "${BPF_LIMITER}" "/usr/lib/zelynic/limiter.bpf.o"
    install -Dm644 "${BPF_OBSERVER}" "/usr/lib/zelynic/observer.bpf.o"
    echo "${PROJECT_NAME} installed to /usr/bin/${PROJECT_NAME}"
    echo "BPF objects installed to /usr/lib/zelynic/"
    echo "Run: ${PROJECT_NAME} doctor  (to verify eBPF support)"
else
    # User install
    BINDIR="${HOME}/.local/bin"
    BPF_INSTALL_DIR="${HOME}/.local/lib/zelynic"
    mkdir -p "${BINDIR}" "${BPF_INSTALL_DIR}"
    install -Dm755 "target/release/${PROJECT_NAME}" "${BINDIR}/${PROJECT_NAME}"
    install -Dm644 "${BPF_LIMITER}" "${BPF_INSTALL_DIR}/limiter.bpf.o"
    install -Dm644 "${BPF_OBSERVER}" "${BPF_INSTALL_DIR}/observer.bpf.o"
    echo "${PROJECT_NAME} installed to ${BINDIR}/${PROJECT_NAME}"
    echo "BPF objects installed to ${BPF_INSTALL_DIR}/"
    echo "Make sure ${BINDIR} is in your PATH."
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi
