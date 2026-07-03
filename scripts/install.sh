#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
# Builds with --features ebpf (required for eBPF enforcement).
#
# Usage:
#   ./scripts/install.sh           → install to ~/.local/bin
#   ./scripts/install.sh --system  → install to /usr/bin (requires sudo)
#   PREFIX=/opt ./scripts/install.sh → install to /opt/bin

set -euo pipefail

PROJECT_NAME="zelynic"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEM_INSTALL=false

# Parse args
for arg in "$@"; do
    case "$arg" in
        --system)
            SYSTEM_INSTALL=true
            ;;
        --help|-h)
            echo "Usage: $0 [--system]"
            echo "  (default)  Install to ~/.local/bin"
            echo "  --system   Install to /usr/bin (requires sudo)"
            exit 0
            ;;
    esac
done

# Set prefix
if $SYSTEM_INSTALL; then
    PREFIX="${PREFIX:-/usr}"
    if [[ $EUID -ne 0 ]]; then
        echo "System install requires root. Run with sudo."
        exit 1
    fi
else
    PREFIX="${PREFIX:-${HOME}/.local}"
fi

BINDIR="${DESTDIR:-}${PREFIX}/bin"

cd "${REPO_ROOT}"

# Build with eBPF feature (required for enforcement)
echo "Building ${PROJECT_NAME} with eBPF support..."
cargo build --release --locked --features ebpf

# Install binary
mkdir -p "${BINDIR}"
install -m 755 "target/release/${PROJECT_NAME}" "${BINDIR}/${PROJECT_NAME}"

echo "${PROJECT_NAME} installed to ${BINDIR}/${PROJECT_NAME}"

if $SYSTEM_INSTALL; then
    echo "Run: zelynic doctor  (to verify eBPF support)"
else
    echo "Make sure ${BINDIR} is in your PATH."
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi
