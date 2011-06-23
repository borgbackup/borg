# -*- encoding: utf-8 *-*
#!/usr/bin/env python
import sys
from setuptools import setup, Extension
from Cython.Distutils import build_ext

dependencies = ['pycrypto', 'msgpack-python', 'pbkdf2.py', 'xattr', 'paramiko', 'Pyrex', 'Cython']
if sys.version_info < (2, 7):
    dependencies.append('argparse')


setup(name='darc',
      version='0.1',
      author='Jonas Borgström',
      author_email='jonas@borgstrom.se',
      packages=['darc'],
      cmdclass = {'build_ext': build_ext},
      ext_modules=[
      Extension('darc._speedups', ['darc/_speedups.c']),
                   Extension('darc.hashindex', ['darc/hashindex.pyx', 'darc/_hashindex.c'])],
      install_requires=dependencies,
      entry_points = {
        'console_scripts': [
            'darc = darc.archiver:main',
        ]
    })

