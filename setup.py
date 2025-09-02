from setuptools import setup, find_packages

setup(
    name='waymap',
    version='6.1.8',
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'termcolor',
        'packaging',
        'bs4',
        'urllib3',
        'colorama',
        'tqdm',
        'argparse',
    ],
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'waymap = waymap:main',
        ],
    },
    author="Trix Cyrus",
    author_email="trixcyrus666@gmail.com",
    description="A powerful web security tool for automated scanning.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/TrixSec/waymap",
    project_urls={
        "Source Code": "https://github.com/TrixSec/waymap",
        "Bug Tracker": "https://github.com/TrixSec/waymap/issues",
    },
    keywords=["security", "pentesting", "vulnerability-scanning", "cybersecurity"],
    license="GPL-3.0",  
    license_files=('LICENSE',), 
)
