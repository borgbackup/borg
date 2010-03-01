# -*- encoding: utf-8 *-*
#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='Dedupestore',
      version='1.0',
      author='Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['dedupestore'],
      ext_modules=[Extension('_speedup', ['deduepstore/_speedup.c'])],
     )
    