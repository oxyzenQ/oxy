#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# Package script for zelynic releases
# Creates tar.gz archives with proper structure for GitHub Releases

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    printf "${CYAN}→${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}⚠${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}✗${NC} %s\n" "$1" >&2
}

# Get version from Cargo.toml
get_version() {
    VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
    echo "$VERSION"
}

# Build for a specific target
build_target() {
    local target="$1"
    local arch_name="$2"

    log_info "Building for $target..."

    rustup target add "$target" 2>/dev/null || true
    cargo build --release --target "$target" 2>&1 | tail -5

    local binary_path="target/${target}/release/zelynic"
    if [[ "$target" == *"musl"* ]]; then
        if ldd "$binary_path" 2>&1 | grep -q "statically linked"; then
            log_success "Binary is statically linked"
        else
            log_warn "Binary may not be fully static"
        fi
    fi

    echo "$binary_path"
}

# Create tar.gz archive
create_archive() {
    local version="$1"
    local arch_name="$2"
    local binary_path="$3"

    local pkg_name="zelynic-v${version}-${arch_name}"
    local pkg_dir="dist/${pkg_name}"

    log_info "Creating archive: ${pkg_name}.tar.gz"

    rm -rf "$pkg_dir"
    install -dm755 "$pkg_dir"
    install -dm755 "$pkg_dir/man"

    # Copy binary
    install -m755 "$binary_path" "$pkg_dir/zelynic"

    # Copy BPF objects (pre-compiled — users don't need clang)
    install -dm755 "$pkg_dir/bpf"
    if [[ -f "bpf/limiter.bpf.o" ]]; then
        install -m644 bpf/limiter.bpf.o "$pkg_dir/bpf/"
    fi
    if [[ -f "bpf/observer.bpf.o" ]]; then
        install -m644 bpf/observer.bpf.o "$pkg_dir/bpf/"
    fi

    # Copy documentation
    install -m644 README.md "$pkg_dir/"
    install -m644 LICENSE "$pkg_dir/"

    # Generate man page
    log_info "Generating man page..."
    "$binary_path" man > "$pkg_dir/man/zelynic.1" 2>/dev/null || true
    gzip -f "$pkg_dir/man/zelynic.1" 2>/dev/null || true

    # Create archive
    local archive_name="${pkg_name}.tar.gz"
    tar -czf "dist/${archive_name}" -C dist "$pkg_name"

    # Generate SHA512
    cd dist
    sha512sum "$archive_name" > "${archive_name}.sha512sum"
    cd ..

    log_success "Archive created: dist/${archive_name}"
    rm -rf "$pkg_dir"

    echo "dist/${archive_name}"
}

# Main packaging function
main() {
    VERSION=$(get_version)
    log_info "Packaging zelynic v${VERSION}"

    install -dm755 dist

    log_info "=== Building x86_64 (glibc) ==="
    BIN_X64=$(build_target "x86_64-unknown-linux-gnu" "linux-amd64")
    ARCHIVE_X64=$(create_archive "$VERSION" "linux-amd64" "$BIN_X64")

    log_info "=== Building x86_64 (musl - static) ==="
    BIN_MUSL=$(build_target "x86_64-unknown-linux-musl" "linux-amd64-musl")
    ARCHIVE_MUSL=$(create_archive "$VERSION" "linux-amd64-musl" "$BIN_MUSL")

    echo
    log_success "Packaging complete!"
    echo
    echo "  Archives in dist/:"
    ls -lh dist/*.tar.gz | awk '{print "    " $9 " (" $5 ")"}'
    echo
    echo "  SHA512 checksums:"
    cat dist/*.sha512sum | while read line; do
        echo "    $line"
    done
    echo
    echo "  ${CYAN}Ready for GitHub Release${NC}"
}

main "$@"
