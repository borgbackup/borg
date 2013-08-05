# -*- encoding: utf-8 *-*
import os
import sys
from glob import glob
import attic

import versioneer
versioneer.versionfile_source = 'attic/_version.py'
versioneer.versionfile_build = 'attic/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'Attic-' # dirname like 'myproject-1.2.0'


min_python = (3, 2)
if sys.version_info < min_python:
    print("Attic requires Python %d.%d or later" % min_python)
    sys.exit(1)

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

chunker_source = 'attic/chunker.pyx'
hashindex_source = 'attic/hashindex.pyx'

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(versioneer.cmd_sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('attic/*.pyx'):
                cython_compiler.compile(glob('attic/*.pyx'),
                                        cython_compiler.default_options)
            versioneer.cmd_sdist.__init__(self, *args, **kwargs)

        def make_distribution(self):
            self.filelist.extend(['attic/chunker.c', 'attic/_chunker.c', 'attic/hashindex.c', 'attic/_hashindex.c'])
            super(Sdist, self).make_distribution()

except ImportError:
    class Sdist(versioneer.cmd_sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    if not os.path.exists(chunker_source) or not os.path.exists(hashindex_source):
        raise ImportError('The GIT version of attic needs Cython. Install Cython or use a released version')

with open('README.rst', 'r') as fd:
    long_description = fd.read()

cmdclass = versioneer.get_cmdclass()
cmdclass.update({'build_ext': build_ext, 'sdist': Sdist})

setup(
    name='Attic',
    version=versioneer.get_version(),
    author='Jonas Borgström',
    author_email='jonas@borgstrom.se',
    url='https://pythonhosted.org/Attic/',
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
    cmdclass=cmdclass,
    ext_modules=[
        Extension('attic.chunker', [chunker_source]),
        Extension('attic.hashindex', [hashindex_source])
    ],
    install_requires=['msgpack-python']
)
