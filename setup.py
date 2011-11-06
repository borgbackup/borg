# -*- encoding: utf-8 *-*
#!/usr/bin/env python
import os
import sys
from glob import glob
import darc

min_python = (2, 5)
if sys.version_info < min_python:
    print "Darc requires Python %d.%d or later" % min_python
    sys.exit(1)

if sys.version_info >= (3,):
    print "Darc doesn't support Python 3 (yet)"
    sys.exit(1)

try:
    import Cython
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fake_pyrex"))
except ImportError:
    pass

from setuptools import setup, Extension
from setuptools.command.sdist import sdist
hashindex_sources = ['darc/hashindex.pyx', 'darc/_hashindex.c']

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('darc/*.pyx'):
                print 'src', src
                cython_compiler.compile(glob('darc/*.pyx'),
                                        cython_compiler.default_options)
            sdist.__init__(self, *args, **kwargs)

        def make_distribution(self):
            self.filelist.append('darc/hashindex.c')
            self.filelist.append('darc/hashindex.h')
            sdist.make_distribution(self)

except ImportError:
    hashindex_sources[0] = hashindex_sources[0].replace('.pyx', '.c')
    from setuptools.command.build_ext import build_ext
    Sdist = sdist
    if not os.path.exists('darc/hashindex.c'):
        raise ImportError('The GIT version of darc needs Cython. Install Cython or use a released version')

dependencies = ['pycrypto', 'msgpack-python', 'pbkdf2.py', 'xattr', 'paramiko']
if sys.version_info < (2, 7):
    dependencies.append('argparse')


setup(name='darc',
      version=darc.__version__,
      author='Jonas Borgström',
      author_email='jonas@borgstrom.se',
      url='http://github.com/jborg/darc/',
      packages=['darc'],
      cmdclass={'build_ext': build_ext, 'sdist': Sdist},
      ext_modules=[
      Extension('darc._speedups', ['darc/_speedups.c']),
      Extension('darc.hashindex', hashindex_sources)],
      install_requires=dependencies,
      entry_points={
        'console_scripts': [
            'darc = darc.archiver:main',
        ]
    })

