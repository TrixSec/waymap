from setuptools import setup, find_packages

setup(
    name='waymap',
    version='1.0.3',  # Update this version as needed
    description='Waymap is a powerful web vulnerability scanner designed to identify SQL injection and command injection vulnerabilities in websites.#v1.0.3dev',
    author='Trix Cyrus',
    author_email='trixcyrus666@gmail.com',  # Update with your email
    url='https://github.com/TrixSec/waymap',  # Update with your GitHub repo
    packages=find_packages(where='lib'),  # Assuming your scripts are in the lib directory
    package_dir={'': 'lib'},
    install_requires=[
        'requests',
        'termcolor',
        'beautifulsoup4',  # Include any other dependencies here
    ],
    entry_points={
        'console_scripts': [
            'waymap=waymap:main',  # This assumes your main function is in waymap.py
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GPL-3.0 license',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',  # Update if you need a specific Python version
)
