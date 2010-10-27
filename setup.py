# -*- encoding: utf-8 *-*
#!/usr/bin/env python

from setuptools import setup, Extension

setup(name='darc',
      version='0.1',
      author=u'Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['darc'],
      ext_modules=[Extension('darc._speedups', ['darc/_speedups.c'])],
      install_requires=['pycrypto', 'msgpack-python', 'pbkdf2.py'],
      entry_points = {
        'console_scripts': [
            'darc = darc.archiver:main',
        ]
    })

