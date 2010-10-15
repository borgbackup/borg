# -*- encoding: utf-8 *-*
#!/usr/bin/env python

from setuptools import setup, Extension

setup(name='Dedupestore',
      version='0.1',
      author=u'Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['dedupestore'],
      ext_modules=[Extension('_speedups', ['dedupestore/_speedups.c'])],
      entry_points = {
        'console_scripts': [
            'dedupestore = dedupestore.archiver:main',
        ]
    })

