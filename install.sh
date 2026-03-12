#!/bin/bash
set -e

# Installation script for ssh-guard
# Downloads and installs the latest (or pinned) release binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/morgaesis/ssh-guard/main/install.sh | bash
#   SSH_GUARD_VERSION=v0.0.1 bash install.sh

# Embedded version (set during release build via sed substitution)
# RELEASE_VERSION_MARKER_START
SSH_GUARD_VERSION=""
# RELEASE_VERSION_MARKER_END

REPO="morgaesis/ssh-guard"
BINARY_NAME="ssh-guard"

if [[ -n "$SSH_GUARD_VERSION" ]]; then
  echo "Installing ssh-guard $SSH_GUARD_VERSION..."
else
  echo "Installing ssh-guard (latest)..."
fi

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')

case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  arm*) ARCH="arm" ;;
esac

# Get version
if [[ -n "$SSH_GUARD_VERSION" ]]; then
  TAG="$SSH_GUARD_VERSION"
else
  if command -v gh &>/dev/null; then
    TAG=$(gh api "repos/$REPO/releases/latest" --jq '.tag_name' 2>/dev/null || true)
  fi
  if [[ -z "$TAG" ]]; then
    RELEASE_INFO=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)
    TAG=$(echo "$RELEASE_INFO" | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4)
  fi
  if [[ -z "$TAG" ]]; then
    echo "ERROR: Failed to fetch release info. GitHub API may be rate-limited."
    echo ""
    echo "Workarounds:"
    echo "  1. Install gh CLI and authenticate: gh auth login"
    echo "  2. Set version manually: SSH_GUARD_VERSION=v0.0.1 bash install.sh"
    echo "  3. Download from: https://github.com/$REPO/releases/latest"
    exit 1
  fi
fi

echo "Version: $TAG"

# Map to asset name
ASSET_NAME=""
case "$OS-$ARCH" in
  linux-amd64)  ASSET_NAME="ssh-guard-$TAG-x86_64-unknown-linux-gnu.tar.gz" ;;
  linux-arm64)  ASSET_NAME="ssh-guard-$TAG-aarch64-unknown-linux-gnu.tar.gz" ;;
  darwin-amd64) ASSET_NAME="ssh-guard-$TAG-x86_64-apple-darwin.tar.gz" ;;
  darwin-arm64) ASSET_NAME="ssh-guard-$TAG-aarch64-apple-darwin.tar.gz" ;;
esac

if [[ -z "$ASSET_NAME" ]]; then
  echo "ERROR: No pre-built binary for $OS-$ARCH"
  echo "Build from source instead:"
  echo "  git clone https://github.com/$REPO && cd ssh-guard && cargo install --path ."
  exit 1
fi

# Download and install
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$ASSET_NAME"
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo "Downloading $ASSET_NAME..."
curl -fsSL -o "$ASSET_NAME" "$DOWNLOAD_URL"

echo "Extracting..."
tar -xzf "$ASSET_NAME"

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
  rm -f "$INSTALL_DIR/$BINARY_NAME"
fi
mv "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Cleanup
cd /
rm -rf "$TEMP_DIR"

# Check PATH
if ! echo "$PATH" | tr ':' '\n' | grep -q "$INSTALL_DIR"; then
  echo ""
  echo "NOTE: $INSTALL_DIR is not in your PATH."
  echo "Add this to your shell profile:"
  echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo ""
echo "Installed ssh-guard to $INSTALL_DIR/$BINARY_NAME"
echo "Run 'ssh-guard --version' to verify."
