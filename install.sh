#!/bin/sh
# Vaultless installer — downloads the latest release from GitHub Releases.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/vaultless/vaultless/main/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/vaultless/vaultless/main/install.sh | sh

set -e

REPO="vaultless/vaultless"
BINARY="vaultless"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# --- helpers ----------------------------------------------------------------

fail() { echo "Error: $1" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found."
}

detect_os() {
  os="$(uname -s)"
  case "$os" in
    Linux*)  echo "linux"  ;;
    Darwin*) echo "darwin"  ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) fail "Unsupported OS: $os" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *) fail "Unsupported architecture: $arch" ;;
  esac
}

# --- main -------------------------------------------------------------------

need curl

OS="$(detect_os)"
ARCH="$(detect_arch)"

if [ "$OS" = "windows" ]; then
  EXT="zip"
else
  EXT="tar.gz"
fi

echo "Detecting platform: ${OS}/${ARCH}"

# Resolve the latest release tag via the GitHub API.
LATEST="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')"

[ -z "$LATEST" ] && fail "Could not determine the latest release."
echo "Latest release: ${LATEST}"

ASSET="${BINARY}-${OS}-${ARCH}.${EXT}"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${URL}..."
curl -fSL -o "${TMPDIR}/${ASSET}" "$URL"

# Verify checksum if sha256sum is available.
if command -v sha256sum >/dev/null 2>&1; then
  echo "Verifying checksum..."
  curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL"
  (cd "$TMPDIR" && grep "$ASSET" checksums.txt | sha256sum -c --quiet -)
  echo "Checksum OK."
elif command -v shasum >/dev/null 2>&1; then
  echo "Verifying checksum..."
  curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL"
  (cd "$TMPDIR" && grep "$ASSET" checksums.txt | shasum -a 256 -c --quiet -)
  echo "Checksum OK."
else
  echo "Warning: sha256sum/shasum not found — skipping checksum verification."
fi

# Extract
echo "Installing to ${INSTALL_DIR}..."
if [ "$EXT" = "zip" ]; then
  need unzip
  unzip -qo "${TMPDIR}/${ASSET}" -d "${TMPDIR}/extracted"
else
  tar -xzf "${TMPDIR}/${ASSET}" -C "${TMPDIR}/extracted" 2>/dev/null \
    || (mkdir -p "${TMPDIR}/extracted" && tar -xzf "${TMPDIR}/${ASSET}" -C "${TMPDIR}/extracted")
fi

# Install the binary.
mkdir -p "${INSTALL_DIR}"
if [ -f "${TMPDIR}/extracted/${BINARY}" ]; then
  install -m 755 "${TMPDIR}/extracted/${BINARY}" "${INSTALL_DIR}/${BINARY}"
elif [ -f "${TMPDIR}/extracted/${BINARY}.exe" ]; then
  cp "${TMPDIR}/extracted/${BINARY}.exe" "${INSTALL_DIR}/${BINARY}.exe"
else
  fail "Binary not found in the archive."
fi

echo ""
echo "Vaultless ${LATEST} installed to ${INSTALL_DIR}/${BINARY}"
echo "Run 'vaultless init' to get started."
