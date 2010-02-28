# -*- encoding: utf-8 *-*
#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='Dedupstore',
      version='1.0',
      author='Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['dedupstore'],
      ext_modules=[Extension('_chunkifier', ['dedupstore/_chunkifier.c'])],
     )
    