#!/usr/bin/env python3

from setuptools import setup

setup(
    name="jdwp-knife",
    version="1.0.0",
    url="https://github.com/s0ld13rr/jdwp-knife",
    author="Zhangir Ospanov",
    author_email="zhangir.ospanov@proton.me",
    description="Pentest tool for extracting data from JVMs via JDWP protocol",
    long_description=open("README.md", encoding="utf8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords=["jdwp", "java", "pentest", "debug", "rce", "data extraction"],
    entry_points={
        "console_scripts": ["jdwp-knife = jdwp_knife:main"],
    },
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
