#!/usr/bin/env bash
# Fetch a prebuilt rop4 (github.com/jaimea753/rop4) release for compare-tools.py.
#
# rop4 is a Go port of rop3 with no pip package. Rather than building it from
# source (Go + libcapstone), this script downloads the prebuilt c-shared library
# from a pinned GitHub release plus the matching Python wrapper, into a gitignored
# .rop4/ at the repo root. utils/rop4_worker.py imports the wrapper from
# .rop4/python/ (override the dir with ROP4_HOME); the wrapper loads librop4.so
# sitting next to it (override with ROP4_LIB). The release .so statically bundles
# capstone, so there is no libcapstone runtime dependency.
#
# Pinned to a release tag for reproducible benchmarks (override with ROP4_REF).
# Idempotent: skips when .rop4/python/ is already populated (pass --refresh to
# re-download). Non-fatal by design — the caller (shell.nix shellHook) keeps
# going on failure and compare-tools.py then reports rop4 rows as 'error'.
set -euo pipefail

REPO="${ROP4_REPO:-jaimea753/rop4}"
REF="${ROP4_REF:-v0.0.2}"                       # release tag to pin
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROP4_HOME="${ROP4_HOME:-$HERE/.rop4}"
PYDIR="$ROP4_HOME/python"
SO="$PYDIR/librop4.so"
WRAPPER="$PYDIR/rop4.py"

REFRESH=0
for a in "$@"; do
  case "$a" in
    --refresh) REFRESH=1 ;;
    *) echo "[fetch_rop4] unknown arg: $a" >&2; exit 2 ;;
  esac
done

if [ "$REFRESH" = 0 ] && [ -f "$SO" ] && [ -f "$WRAPPER" ]; then
  echo "[fetch_rop4] already present in $PYDIR (pass --refresh to re-download)"
  exit 0
fi

# --- Pick the release asset for this platform -------------------------------
OS="$(uname -s)"; MACH="$(uname -m)"
case "$MACH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "[fetch_rop4] unsupported CPU $MACH; rop4 rows will be 'error'" >&2; exit 1 ;;
esac
case "$OS" in
  Linux)
    # glibc vs musl: musl ships ld-musl-* / reports "musl" from ldd.
    if ldd --version 2>&1 | grep -qi musl || ls /lib/ld-musl-* >/dev/null 2>&1; then
      LIBC=musl; else LIBC=glibc; fi
    ASSET="librop4-linux-${ARCH}-${LIBC}.so" ;;
  Darwin)
    ASSET="librop4-macos-${ARCH}.dylib" ;;
  *) echo "[fetch_rop4] unsupported OS $OS; rop4 rows will be 'error'" >&2; exit 1 ;;
esac

BASE="https://github.com/$REPO/releases/download/$REF"
RAW="https://raw.githubusercontent.com/$REPO/$REF/python/rop4.py"

dl() {  # dl <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else echo "[fetch_rop4] need curl or wget" >&2; return 1; fi
}

mkdir -p "$PYDIR"
echo "[fetch_rop4] $REPO@$REF  $OS/$MACH  asset=$ASSET"
dl "$RAW" "$WRAPPER"          # the thin ctypes wrapper (loads librop4.so beside it)
dl "$BASE/$ASSET" "$SO"       # prebuilt c-shared library -> librop4.so
echo "$REF" > "$ROP4_HOME/RELEASE"

if [ -f "$SO" ] && [ -f "$WRAPPER" ]; then
  echo "[fetch_rop4] OK: $PYDIR (rop4 $REF)"
else
  echo "[fetch_rop4] download finished but artifacts are missing" >&2
  exit 1
fi
