#!/bin/sh

set -e  # Exit on any error
set -u  # Treat unset variables as an error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Variables
RELEASE_URL="https://github.com/dhruvan2006/tuenroll/releases/latest/download"
BINARY_NAME="tuenroll"
INSTALL_DIR="$HOME/.local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Determine the binary suffix
case "$OS" in
  linux)
    case "$ARCH" in
      x86_64) FILE_SUFFIX="x86_64-unknown-linux-gnu" ;;
      *) printf "${RED}Unsupported architecture: $ARCH${RESET}\n" >&2; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64) FILE_SUFFIX="x86_64-apple-darwin" ;;
      *) printf "${RED}Unsupported architecture: $ARCH${RESET}\n" >&2; exit 1 ;;
    esac
    ;;
  *)
    printf "${RED}Unsupported OS: $OS${RESET}\n" >&2
    exit 1
    ;;
esac

# Construct the download URL
DOWNLOAD_URL="$RELEASE_URL/tuenroll-$FILE_SUFFIX"

# Download the file
printf "${BLUE}Downloading $BINARY_NAME...${RESET}\n"
curl -fsSL -# -o "$BINARY_NAME" "$DOWNLOAD_URL"

# Make the binary executable
chmod +x "$BINARY_NAME"

# Move the binary to the install directory
printf "${BLUE}Installing $BINARY_NAME to $INSTALL_DIR...${RESET}\n"
mkdir -p "$INSTALL_DIR"
mv "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

# Modify the PATH for the current session
printf "${BLUE}Updating PATH to include $INSTALL_DIR...${RESET}\n"
export PATH="$INSTALL_DIR:$PATH"

# Verify installation using 'which'
printf "${BLUE}Checking if $BINARY_NAME is installed...${RESET}\n"
if which "$BINARY_NAME" >/dev/null 2>&1; then
  printf "${GREEN}$BINARY_NAME has been successfully installed!${RESET}\n"
else
  printf "${RED}Installation failed!${RESET}\n" >&2
  exit 1
fi

# Add install directory to PATH if necessary
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  printf "${YELLOW}To use $BINARY_NAME, add $INSTALL_DIR to your PATH:${RESET}\n"
  printf "${YELLOW}export PATH=$INSTALL_DIR:$PATH${RESET}\n"
fi
