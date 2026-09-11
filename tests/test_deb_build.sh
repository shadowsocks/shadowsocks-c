#!/bin/bash
#
# Test that Debian packages build, contain expected files, install, and work.
#
# Usage: bash tests/test_deb_build.sh
#
# Requirements (Linux only):
#   - dpkg-buildpackage, debhelper, fakeroot
#   - Build dependencies listed in debian/control
#   - sudo (for install phase)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- helpers ----------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
FAILURES=""

log() {
    echo "=== [test_deb_build] $* ==="
}

check_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS: $*"
}

check_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES="${FAILURES}  FAIL: $*"$'\n'
    echo "  FAIL: $*"
}

# check_file_in_deb DEB_FILE PATTERN DESCRIPTION
# Verifies that at least one file matching PATTERN exists in the .deb
check_file_in_deb() {
    local deb="$1" pattern="$2" desc="$3"
    # Avoid grep -q: with pipefail, early grep exit causes SIGPIPE on dpkg-deb
    if dpkg-deb -c "$deb" | grep -E "$pattern" >/dev/null; then
        check_pass "$desc"
    else
        check_fail "$desc"
    fi
}

# check_command CMD DESCRIPTION
# Verifies that a command runs successfully (exit 0)
check_command() {
    local desc="$2"
    if eval "$1" >/dev/null 2>&1; then
        check_pass "$desc"
    else
        check_fail "$desc"
    fi
}

summary() {
    echo ""
    log "Results: $PASS_COUNT passed, $FAIL_COUNT failed"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""
        echo "Failures:"
        printf '%s' "$FAILURES"
        exit 1
    fi
}

# --- phase 1: build --------------------------------------------------------

log "Phase 1: Build Debian packages"

cd "$PROJECT_DIR"

# dpkg-buildpackage -b builds binary-only packages (no .orig.tar.gz needed)
dpkg-buildpackage -b -us -uc -j"$(nproc)"

# .deb files are placed in the parent directory
PARENT_DIR="$(dirname "$PROJECT_DIR")"

DEB_MAIN=""
DEB_LIB=""
DEB_DEV=""
for f in "$PARENT_DIR"/shadowsocks-libev_*.deb; do
    [ -f "$f" ] && DEB_MAIN="$f" && break
done
for f in "$PARENT_DIR"/libshadowsocks-libev2_*.deb; do
    [ -f "$f" ] && DEB_LIB="$f" && break
done
for f in "$PARENT_DIR"/libshadowsocks-libev-dev_*.deb; do
    [ -f "$f" ] && DEB_DEV="$f" && break
done

# --- phase 2: verify contents ----------------------------------------------

log "Phase 2: Verify package contents"

# Check all three .deb files exist
if [ -n "$DEB_MAIN" ] && [ -f "$DEB_MAIN" ]; then
    check_pass "shadowsocks-libev .deb exists: $(basename "$DEB_MAIN")"
else
    check_fail "shadowsocks-libev .deb not found"
fi

if [ -n "$DEB_LIB" ] && [ -f "$DEB_LIB" ]; then
    check_pass "libshadowsocks-libev2 .deb exists: $(basename "$DEB_LIB")"
else
    check_fail "libshadowsocks-libev2 .deb not found"
fi

if [ -n "$DEB_DEV" ] && [ -f "$DEB_DEV" ]; then
    check_pass "libshadowsocks-libev-dev .deb exists: $(basename "$DEB_DEV")"
else
    check_fail "libshadowsocks-libev-dev .deb not found"
fi

# Bail early if any .deb is missing - remaining checks would all fail
if [ "$FAIL_COUNT" -gt 0 ]; then
    summary
fi

# Main package: binaries
for bin in ss-local ss-server ss-redir ss-tunnel ss-manager; do
    check_file_in_deb "$DEB_MAIN" "usr/bin/${bin}" "$bin binary in main package"
done

# Main package: man pages
for bin in ss-local ss-server ss-redir ss-tunnel ss-manager; do
    check_file_in_deb "$DEB_MAIN" "usr/share/man/man1/$bin\\.1" "$bin man page in main package"
done

# Shared library package
check_file_in_deb "$DEB_LIB" "usr/lib/.*/libshadowsocks-libev\\.so\\." "shared library in lib package"

# Dev package: header
check_file_in_deb "$DEB_DEV" "usr/include/shadowsocks\\.h" "shadowsocks.h header in dev package"

# Dev package: pkg-config
check_file_in_deb "$DEB_DEV" "usr/lib/.*/pkgconfig/shadowsocks-libev\\.pc" "pkg-config file in dev package"

# Dev package: unversioned .so symlink
check_file_in_deb "$DEB_DEV" "usr/lib/.*/libshadowsocks-libev\\.so[^.]" "unversioned .so symlink in dev package"

# --- phase 3: install -------------------------------------------------------

log "Phase 3: Install packages"

sudo dpkg -i "$DEB_LIB" "$DEB_DEV" "$DEB_MAIN" || true
sudo apt-get -f install -y

# Verify dpkg thinks they are installed
for pkg in shadowsocks-libev libshadowsocks-libev2 libshadowsocks-libev-dev; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        check_pass "$pkg installed"
    else
        check_fail "$pkg not installed"
    fi
done

# --- phase 4: smoke-test ----------------------------------------------------

log "Phase 4: Smoke-test installed binaries"

# Each binary should respond to --help
for bin in ss-local ss-server ss-redir ss-tunnel ss-manager; do
    check_command "$bin --help" "$bin --help runs"
done

# Shared library should be findable by ldconfig
sudo ldconfig
if ldconfig -p | grep -q libshadowsocks-c; then
    check_pass "libshadowsocks-c found by ldconfig"
else
    check_fail "libshadowsocks-c not found by ldconfig"
fi

# Header should be in the include path
if [ -f /usr/include/shadowsocks.h ]; then
    check_pass "shadowsocks.h installed in /usr/include"
else
    check_fail "shadowsocks.h not installed in /usr/include"
fi

# --- summary ----------------------------------------------------------------

summary
