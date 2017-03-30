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
      package_data={'libzpy.libs':['libucl_i368.so','libucl_x64.so']},
      include_package_data=True,
      install_requires=[
        "pycrypto",
        "mlib"
      ])

