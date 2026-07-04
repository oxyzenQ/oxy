#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
#
# Works in two modes:
#   1. From release tarball: binary + BPF objects already pre-compiled.
#      Just install them. No clang, no cargo needed.
#   2. From source repo: compile BPF (if needed) + build Rust binary.
#
# Usage:
#   ./install.sh --user     → install to ~/.local/bin (default)
#   ./install.sh --system   → install to /usr/bin (requires sudo)

set -euo pipefail

PROJECT_NAME="zelynic"
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

# Detect mode: release tarball (binary exists) or source repo (Cargo.toml exists)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/${PROJECT_NAME}"
BPF_DIR="${SCRIPT_DIR}/bpf"

if [[ ! -f "${BINARY}" ]]; then
    # Source mode — need to build
    if [[ -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
        REPO_ROOT="${SCRIPT_DIR}"
    elif [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
        REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    else
        echo "ERROR: No pre-compiled binary found and no Cargo.toml."
        echo "  Run from release tarball directory or repo root."
        exit 1
    fi

    cd "${REPO_ROOT}"
    BINARY="target/release/${PROJECT_NAME}"
    BPF_DIR="bpf"

    # Compile BPF objects if not already present
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
            exit 1
        fi
    else
        echo "✓ BPF objects already compiled"
    fi

    # Build Rust binary
    echo "Building ${PROJECT_NAME} with eBPF support..."
    cargo build --release --locked --features ebpf
fi

# Verify binary exists
if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: Binary not found at ${BINARY}"
    exit 1
fi

# Verify BPF objects exist
if [[ ! -f "${BPF_DIR}/limiter.bpf.o" ]] || [[ ! -f "${BPF_DIR}/observer.bpf.o" ]]; then
    echo "ERROR: BPF objects not found in ${BPF_DIR}/"
    exit 1
fi

# Install
if [[ "${INSTALL_MODE}" == "--system" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "System install requires root. Run with sudo."
        echo "  sudo ./install.sh --system"
        exit 1
    fi
    # Install binary
    install -Dm755 "${BINARY}" "/usr/bin/${PROJECT_NAME}"
    # Install BPF objects
    install -d /usr/lib/zelynic
    install -Dm644 "${BPF_DIR}/limiter.bpf.o" "/usr/lib/zelynic/limiter.bpf.o"
    install -Dm644 "${BPF_DIR}/observer.bpf.o" "/usr/lib/zelynic/observer.bpf.o"
    echo "${PROJECT_NAME} installed to /usr/bin/${PROJECT_NAME}"
    echo "BPF objects installed to /usr/lib/zelynic/"
    echo "Run: ${PROJECT_NAME} doctor  (to verify eBPF support)"
else
    # User install
    BINDIR="${HOME}/.local/bin"
    BPF_INSTALL_DIR="${HOME}/.local/lib/zelynic"
    mkdir -p "${BINDIR}" "${BPF_INSTALL_DIR}"
    install -Dm755 "${BINARY}" "${BINDIR}/${PROJECT_NAME}"
    install -Dm644 "${BPF_DIR}/limiter.bpf.o" "${BPF_INSTALL_DIR}/limiter.bpf.o"
    install -Dm644 "${BPF_DIR}/observer.bpf.o" "${BPF_INSTALL_DIR}/observer.bpf.o"
    echo "${PROJECT_NAME} installed to ${BINDIR}/${PROJECT_NAME}"
    echo "BPF objects installed to ${BPF_INSTALL_DIR}/"
    echo "Make sure ${BINDIR} is in your PATH."
fi
