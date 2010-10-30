# -*- encoding: utf-8 *-*
#!/usr/bin/env python
import sys
from setuptools import setup, Extension

dependencies = ['pycrypto', 'msgpack-python', 'pbkdf2.py'],
if sys.version_info < (2, 7):
    dependencies.append('argparse')


setup(name='darc',
      version='0.1',
      author=u'Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['darc'],
      ext_modules=[Extension('darc._speedups', ['darc/_speedups.c'])],
      install_requires=dependencies,
      entry_points = {
        'console_scripts': [
            'darc = darc.archiver:main',
        ]
    })

