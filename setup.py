#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="libzpy",
      version="0.0.6",
      description="zeus-like things",
      author="mak",
      packages=['libzpy', 'libzpy.fmt', 'libzpy.libs', 'libzpy.modules', 'libzpy.structs'],
      install_requires=[
        "pycrypto",
        "mlib"
      ])
