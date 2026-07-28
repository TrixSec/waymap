#!/bin/bash
# Build script for Waymap Debian package
# Run this on a Debian/Kali Linux system

set -e

echo "Building Waymap Debian Package for Kali Linux"
echo "=============================================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This script must be run on Linux"
    echo "Current OS: $OSTYPE"
    exit 1
fi

# Install build dependencies if not already installed
echo "Checking for build dependencies..."
if ! dpkg -l | grep -q debhelper; then
    echo "Installing build dependencies..."
    sudo apt update
    sudo apt install -y debhelper dh-python python3-all python3-setuptools python3-pkg-resources python3-sphinx
fi

# Set executable permissions
echo "Setting executable permissions..."
chmod +x debian/rules
chmod +x debian/waymap.postinst
chmod +x debian/waymap.prerm

# Remove executable permissions from config files
chmod -x debian/install debian/docs debian/manpages debian/links debian/watch 2>/dev/null || true

# Check if we're on a Windows filesystem (WSL)
if [[ "$(pwd)" == /mnt/* ]]; then
    echo "Detected Windows filesystem (WSL). Copying to native Linux filesystem for build..."
    ORIGINAL_DIR="$(pwd)"
    BUILD_DIR="/tmp/waymap-build-$$"
    mkdir -p "$BUILD_DIR"
    cp -r . "$BUILD_DIR/"
    cd "$BUILD_DIR"
    echo "Working in: $BUILD_DIR"
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -f ../waymap_*.deb ../waymap_*.tar.xz ../waymap_*.dsc ../waymap_*.changes
rm -f ../waymap_*.orig.tar.gz
rm -rf debian/.debhelper/

# Build the package
echo "Building package..."
dpkg-buildpackage -us -uc

# Copy results back if we were on WSL
if [[ -n "$BUILD_DIR" ]]; then
    echo "Copying build results back..."
    cp waymap_*.deb waymap_*.tar.xz waymap_*.dsc waymap_*.changes "$ORIGINAL_DIR/" 2>/dev/null || true
    cd "$ORIGINAL_DIR"
    rm -rf "$BUILD_DIR"
    echo "Cleanup complete."
fi

echo ""
echo "=============================================="
echo "Build completed successfully!"
echo ""
echo "Package files created in parent directory:"
echo "  - waymap_8.2.0-1_all.deb (install with: sudo dpkg -i waymap_8.2.0-1_all.deb)"
echo "  - waymap_8.2.0-1.dsc"
echo "  - waymap_8.2.0-1.tar.xz"
echo ""
echo "To install the package:"
echo "  sudo dpkg -i waymap_8.2.0-1_all.deb"
echo ""
echo "To test the installation:"
echo "  waymap --version"
echo "  waymap --help"
