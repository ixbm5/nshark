"""Compatibility shim for editable installs on older pip versions."""

from setuptools import find_packages, setup

setup(
    name="nshark",
    version="1.0.0",
    packages=find_packages(include=["nshark", "nshark.*"]),
)
