# -*- encoding: utf-8 *-*
import os
import sys
from glob import glob

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

crypto_source = 'attic/crypto.pyx'
chunker_source = 'attic/chunker.pyx'
hashindex_source = 'attic/hashindex.pyx'
platform_linux_source = 'attic/platform_linux.pyx'
platform_darwin_source = 'attic/platform_darwin.pyx'
platform_freebsd_source = 'attic/platform_freebsd.pyx'

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
            self.filelist.extend(['attic/crypto.c', 'attic/chunker.c', 'attic/_chunker.c', 'attic/hashindex.c', 'attic/_hashindex.c', 'attic/platform_linux.c', 'attic/platform_freebsd.c', 'attic/platform_darwin.c'])
            super(Sdist, self).make_distribution()

except ImportError:
    class Sdist(versioneer.cmd_sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    crypto_source = crypto_source.replace('.pyx', '.c')
    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    platform_linux_source = platform_linux_source.replace('.pyx', '.c')
    platform_freebsd_source = platform_freebsd_source.replace('.pyx', '.c')
    platform_darwin_source = platform_darwin_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    if not all(os.path.exists(path) for path in [crypto_source, chunker_source, hashindex_source, platform_linux_source, platform_freebsd_source]):
        raise ImportError('The GIT version of Attic needs Cython. Install Cython or use a released version')


def detect_openssl(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'openssl', 'evp.h')
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                if 'PKCS5_PBKDF2_HMAC(' in fd.read():
                    return prefix


possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl', '/usr/local/attic', '/opt/local']
if os.environ.get('ATTIC_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('ATTIC_OPENSSL_PREFIX'))
ssl_prefix = detect_openssl(possible_openssl_prefixes)
if not ssl_prefix:
    raise Exception('Unable to find OpenSSL >= 1.0 headers. (Looked here: {})'.format(', '.join(possible_openssl_prefixes)))
include_dirs = [os.path.join(ssl_prefix, 'include')]
library_dirs = [os.path.join(ssl_prefix, 'lib')]


with open('README.rst', 'r') as fd:
    long_description = fd.read()

cmdclass = versioneer.get_cmdclass()
cmdclass.update({'build_ext': build_ext, 'sdist': Sdist})

ext_modules = [
    Extension('attic.crypto', [crypto_source], libraries=['crypto'], include_dirs=include_dirs, library_dirs=library_dirs),
    Extension('attic.chunker', [chunker_source]),
    Extension('attic.hashindex', [hashindex_source])
]
if sys.platform.startswith('linux'):
    ext_modules.append(Extension('attic.platform_linux', [platform_linux_source], libraries=['acl']))
elif sys.platform.startswith('freebsd'):
    ext_modules.append(Extension('attic.platform_freebsd', [platform_freebsd_source]))
elif sys.platform == 'darwin':
    ext_modules.append(Extension('attic.platform_darwin', [platform_darwin_source]))

setup(
    name='Attic',
    version=versioneer.get_version(),
    author='Jonas Borgstrom',
    author_email='jonas@borgstrom.se',
    url='https://attic-backup.org/',
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
    ext_modules=ext_modules,
    install_requires=['msgpack-python']
)
