# -*- encoding: utf-8 *-*
import os
import sys
from glob import glob
import attic

min_python = (3, 2)
if sys.version_info < min_python:
    print("Attic requires Python %d.%d or later" % min_python)
    sys.exit(1)

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
from distutils.command.sdist import sdist

chunker_source = 'attic/chunker.pyx'
hashindex_source = 'attic/hashindex.pyx'

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('attic/*.pyx'):
                cython_compiler.compile(glob('attic/*.pyx'),
                                        cython_compiler.default_options)
            sdist.__init__(self, *args, **kwargs)

        def make_distribution(self):
            self.filelist.extend(['attic/chunker.c', 'attic/_chunker.c', 'attic/hashindex.c', 'attic/_hashindex.c'])
            super(Sdist, self).make_distribution()

except ImportError:
    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    if not os.path.exists(chunker_source) or not os.path.exists(hashindex_source):
        raise ImportError('The GIT version of attic needs Cython. Install Cython or use a released version')

with open('README.rst', 'r') as fd:
    long_description = fd.read()

setup(
    name='Attic',
    version=attic.__release__,
    author='Jonas Borgström',
    author_email='jonas@borgstrom.se',
    url='http://github.com/jborg/attic/',
    description='Deduplicated backups',
    long_description=long_description,
    license='BSD',
    platforms=['Linux', 'MacOS X'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=['attic', 'attic.testsuite'],
    scripts=['scripts/attic'],
    cmdclass={'build_ext': build_ext, 'sdist': Sdist},
    ext_modules=[
        Extension('attic.chunker', [chunker_source]),
        Extension('attic.hashindex', [hashindex_source])
    ],
    install_requires=['msgpack-python']
)
