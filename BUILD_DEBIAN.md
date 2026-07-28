# Building Waymap Debian Package for Kali Linux

## Prerequisites

On a Debian/Kali Linux system, install the required build dependencies:

```bash
sudo apt update
sudo apt install debhelper dh-python python3-all python3-setuptools python3-pkg-resources python3-sphinx
```

## Building the Package

1. **Set executable permissions** (Linux only):
```bash
chmod +x debian/rules
chmod +x debian/waymap.postinst
chmod +x debian/waymap.prerm
```

2. **Build the package**:
```bash
dpkg-buildpackage -us -uc
```

This will create the following files in the parent directory:
- `waymap_8.2.0-1_all.deb` - The main Debian package
- `waymap_8.2.0-1.debian.tar.xz` - Debian packaging files
- `waymap_8.2.0-1.dsc` - Package source description
- `waymap_8.2.0.orig.tar.gz` - Original source tarball

3. **Install the package**:
```bash
sudo dpkg -i ../waymap_8.2.0-1_all.deb
```

If there are dependency issues:
```bash
sudo apt-get install -f
```

## Testing the Installation

After installation, verify it works:

```bash
waymap --version
waymap --help
```

## Package Structure

The package installs files to the following locations:
- `/usr/bin/waymap` - Main executable
- `/usr/lib/python3/dist-packages/waymap/` - Python package
- `/usr/share/waymap/` - Data files, payloads, config
- `/usr/share/doc/waymap/` - Documentation
- `/usr/share/man/man1/waymap.1` - Man page
- `/etc/waymap/` - Configuration directory

## Kali Linux Submission

To submit to Kali Linux repository:

1. **Create a git repository**:
```bash
git init
git add .
git commit -m "Initial Debian packaging for waymap"
```

2. **Follow Kali packaging guidelines**:
   - Ensure the package meets Kali's packaging standards
   - Test thoroughly on Kali Linux
   - Check for security vulnerabilities in the package itself

3. **Submit via Kali's bug tracker or follow their contribution guidelines**:
   - https://www.kali.org/docs/community/contributing/
   - Submit to https://bugs.kali.org

## Compliance Checklist

- [x] Proper debian/control with correct dependencies
- [x] debian/copyright with GPL-3.0 license
- [x] debian/changelog with proper format
- [x] debian/rules using pybuild
- [x] Man page included
- [x] Post-installation scripts
- [x] Proper file permissions
- [x] Standards-Version 4.6.2
- [x] Source format 3.0 (quilt)
- [x] Watch file for automatic updates
- [x] README.Debian with instructions

## Notes

- The package uses `dh-python` with `pybuild` for Python 3
- All dependencies are properly declared in debian/control
- The package is architecture: all (pure Python)
- AI features are optional (Recommends: python3-openai)
- Security scanner tools are properly categorized in Section: net
