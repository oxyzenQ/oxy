#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
# Builds with --features ebpf (required for eBPF enforcement).
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

# Build with eBPF feature
echo "Building ${PROJECT_NAME} with eBPF support..."
cargo build --release --locked --features ebpf

# Install
if [[ "${INSTALL_MODE}" == "--system" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "System install requires root. Run with sudo."
        echo "  sudo ./scripts/install.sh --system"
        exit 1
    fi
    sudo install -Dm755 "target/release/${PROJECT_NAME}" "/usr/bin/${PROJECT_NAME}"
    echo "${PROJECT_NAME} installed to /usr/bin/${PROJECT_NAME}"
    echo "Run: ${PROJECT_NAME} doctor  (to verify eBPF support)"
else
    BINDIR="${HOME}/.local/bin"
    mkdir -p "${BINDIR}"
    install -Dm755 "target/release/${PROJECT_NAME}" "${BINDIR}/${PROJECT_NAME}"
    echo "${PROJECT_NAME} installed to ${BINDIR}/${PROJECT_NAME}"
    echo "Make sure ${BINDIR} is in your PATH."
    echo "  export PATH=\"${BINDIR}:\$PATH\""
fi
