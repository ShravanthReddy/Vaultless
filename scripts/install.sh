#!/bin/sh
# Vaultless installer
# Usage: curl -fsSL https://raw.githubusercontent.com/vaultless/vaultless/main/install.sh | sh
set -e

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

LATEST=$(curl -sSL "https://api.github.com/repos/vaultless/vaultless/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
URL="https://github.com/vaultless/vaultless/releases/download/v${LATEST}/vaultless-${OS}-${ARCH}.tar.gz"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo "Downloading vaultless v${LATEST} for ${OS}/${ARCH}..."
curl -sSL "$URL" | tar -xz -C "$INSTALL_DIR" vaultless
chmod +x "${INSTALL_DIR}/vaultless"
echo "vaultless v${LATEST} installed to ${INSTALL_DIR}/vaultless"
