#!/usr/bin/env bash
# Build vendored Nmap + Ncrack into PREFIX (default: recon/dist).
# Npcap cannot be built on macOS/Linux — use ./recon/build.sh npcap for instructions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_ROOT="$SCRIPT_DIR"
DEFAULT_PREFIX="$RECON_ROOT/dist"
export PREFIX="${PREFIX:-$DEFAULT_PREFIX}"

if [[ "${JOBS:-}" == "" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
  elif command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
  else
    JOBS="4"
  fi
fi

detect_openssl_prefix() {
  if [[ -n "${OPENSSL_PREFIX:-}" ]]; then
    echo "$OPENSSL_PREFIX"
    return 0
  fi
  if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    for p in openssl@3 openssl; do
      local d
      d="$(brew --prefix "$p" 2>/dev/null || true)"
      if [[ -n "$d" && -f "$d/include/openssl/ssl.h" ]]; then
        echo "$d"
        return 0
      fi
    done
  fi
  return 1
}

OPENSSL_ARGS=()
if odir="$(detect_openssl_prefix)"; then
  OPENSSL_ARGS=(--with-openssl="$odir")
  echo "Using OpenSSL: $odir"
else
  echo "Note: OpenSSL not auto-detected; configure may continue without HTTPS scripts. On macOS: brew install openssl"
fi

configure_nmap() {
  cd "$RECON_ROOT/nmap"
  # Optional dbus is often undesirable on minimal CI/macOS SDK-only setups.
  ./configure --prefix="$PREFIX" --disable-dbus "${OPENSSL_ARGS[@]}" "$@"
}

build_nmap() {
  configure_nmap "$@"
  make -j"$JOBS"
}

install_nmap() {
  cd "$RECON_ROOT/nmap"
  make -j"$JOBS" install
}

configure_ncrack() {
  cd "$RECON_ROOT/ncrack"
  ./configure --prefix="$PREFIX" "${OPENSSL_ARGS[@]}" "$@"
}

build_ncrack() {
  configure_ncrack "$@"
  make -j"$JOBS"
}

install_ncrack() {
  cd "$RECON_ROOT/ncrack"
  make -j"$JOBS" install
}

print_npcap_help() {
  cat <<'EOF'
Npcap is Windows-only (kernel driver + DLLs). It is not built by this script on macOS/Linux.

  Install (end users): https://npcap.com/#download

  Build from source (Windows + Visual Studio):
    https://npcap.com/guide/npcap-devguide.html#npcap-building

Source lives in: recon/npcap/
EOF
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <target> [extra ./configure args...]

Targets:
  nmap      Configure and compile Nmap (recon/nmap)
  ncrack    Configure and compile Ncrack (recon/ncrack)
  all       Build Nmap then Ncrack (same PREFIX; extra args passed to both configure runs)
  install   Run 'make install' for both (after successful builds)
  all-install  Same as 'all' then 'install'
  npcap     Print Npcap Windows build / install guidance

Environment:
  PREFIX=$PREFIX
  JOBS=$JOBS
  OPENSSL_PREFIX   Override OpenSSL root (optional)
EOF
}

main() {
  case "${1:-}" in
    ""|-h|--help)
      usage
      exit 0
      ;;
  esac
  local target="$1"
  shift

  case "$target" in
    nmap)
      build_nmap "$@"
      ;;
    ncrack)
      build_ncrack "$@"
      ;;
    all)
      build_nmap "$@"
      build_ncrack "$@"
      ;;
    all-install)
      build_nmap "$@"
      build_ncrack "$@"
      install_nmap
      install_ncrack
      echo "Installed under: $PREFIX"
      echo "Add to PATH: export PATH=$PREFIX/bin:\$PATH"
      ;;
    install)
      install_nmap
      install_ncrack
      echo "Installed under: $PREFIX"
      echo "Add to PATH: export PATH=$PREFIX/bin:\$PATH"
      ;;
    npcap)
      print_npcap_help
      ;;
    *)
      echo "Unknown target: $target" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
