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

# Clean previous builds
echo "Cleaning previous builds..."
rm -f ../waymap_*.deb ../waymap_*.tar.xz ../waymap_*.dsc ../waymap_*.changes
rm -f ../waymap_*.orig.tar.gz
rm -rf debian/.debhelper/

# Build the package
echo "Building package..."
dpkg-buildpackage -us -uc

echo ""
echo "=============================================="
echo "Build completed successfully!"
echo ""
echo "Package files created in parent directory:"
echo "  - waymap_8.2.0-1_all.deb (install with: sudo dpkg -i ../waymap_8.2.0-1_all.deb)"
echo "  - waymap_8.2.0-1.dsc"
echo "  - waymap_8.2.0-1.debian.tar.xz"
echo "  - waymap_8.2.0.orig.tar.gz"
echo ""
echo "To install the package:"
echo "  sudo dpkg -i ../waymap_8.2.0-1_all.deb"
echo ""
echo "To test the installation:"
echo "  waymap --version"
echo "  waymap --help"
