# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""Setup configuration for Waymap."""

from setuptools import setup, find_packages
import os

# Read the long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from VERSION file
with open("VERSION", "r") as f:
    version = f.read().strip()

setup(
    name="waymap",
    version=version,
    author="Trix Cyrus",
    author_email="trixsec@proton.me",
    description="Advanced Web Application Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/TrixSec/waymap",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "colorama>=0.4.6",
        "urllib3>=2.0.0",
        "tqdm>=4.66.0",
        "packaging>=23.0",
        "fpdf>=1.7.2",
    ],
    entry_points={
        "console_scripts": [
            "waymap=waymap:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["data/*", "*.txt", "*.json", "*.xml"],
    },
    keywords="security scanner vulnerability web-security penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/TrixSec/waymap/issues",
        "Source": "https://github.com/TrixSec/waymap",
        "Documentation": "https://github.com/TrixSec/waymap/blob/main/README.md",
    },
)
