# Copyright (c) 2024 waymap developers 
# See the file 'LICENSE' for copying permission.

from setuptools import setup, find_packages

setup(
    name='waymap',
    version='2.5.6', 
    description='Waymap is a powerful web vulnerability scanner designed to identify vulnerabilities in websites.#v1.0.3dev',
    author='Trix Cyrus',
    Core_Developer='Trix',
    Developers_Contributors='jenin,Yash',
    author_email='trixcyrus666@gmail.com',  
    url='https://github.com/TrixSec/waymap',  
    packages=find_packages(where='lib'),  
    package_dir={'': 'lib'},
    install_requires=[
        'requests',
        'termcolor',
        'beautifulsoup4'
        'threading',  
    ],
    entry_points={
        'console_scripts': [
            'waymap=waymap:main',  
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GPL-3.0 license',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',  
)
