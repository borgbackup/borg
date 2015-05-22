# -*- encoding: utf-8 *-*
import os
import sys
from glob import glob

import versioneer
versioneer.VCS = 'git'
versioneer.style = 'pep440'
versioneer.versionfile_source = 'borg/_version.py'
versioneer.versionfile_build = 'borg/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'borgbackup-'  # dirname like 'myproject-1.2.0'

min_python = (3, 2)
if sys.version_info < min_python:
    print("Borg requires Python %d.%d or later" % min_python)
    sys.exit(1)

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

crypto_source = 'borg/crypto.pyx'
chunker_source = 'borg/chunker.pyx'
hashindex_source = 'borg/hashindex.pyx'
platform_linux_source = 'borg/platform_linux.pyx'
platform_darwin_source = 'borg/platform_darwin.pyx'
platform_freebsd_source = 'borg/platform_freebsd.pyx'

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(versioneer.cmd_sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('borg/*.pyx'):
                cython_compiler.compile(src, cython_compiler.default_options)
            versioneer.cmd_sdist.__init__(self, *args, **kwargs)

        def make_distribution(self):
            self.filelist.extend([
                'borg/crypto.c',
                'borg/chunker.c', 'borg/_chunker.c',
                'borg/hashindex.c', 'borg/_hashindex.c',
                'borg/platform_linux.c',
                'borg/platform_freebsd.c',
                'borg/platform_darwin.c',
            ])
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
        raise ImportError('The GIT version of Borg needs Cython. Install Cython or use a released version')


def detect_openssl(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'openssl', 'evp.h')
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                if 'PKCS5_PBKDF2_HMAC(' in fd.read():
                    return prefix


possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl', '/usr/local/borg', '/opt/local']
if os.environ.get('BORG_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_OPENSSL_PREFIX'))
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
    Extension('borg.crypto', [crypto_source], libraries=['crypto'], include_dirs=include_dirs, library_dirs=library_dirs),
    Extension('borg.chunker', [chunker_source]),
    Extension('borg.hashindex', [hashindex_source])
]
if sys.platform.startswith('linux'):
    ext_modules.append(Extension('borg.platform_linux', [platform_linux_source], libraries=['acl']))
elif sys.platform.startswith('freebsd'):
    ext_modules.append(Extension('borg.platform_freebsd', [platform_freebsd_source]))
elif sys.platform == 'darwin':
    ext_modules.append(Extension('borg.platform_darwin', [platform_darwin_source]))

setup(
    name='borgbackup',
    version=versioneer.get_version(),
    author='The Borg Collective (see AUTHORS file)',
    author_email='borgbackup@librelist.com',
    url='https://borgbackup.github.io/',
    description='Deduplicated, encrypted, authenticated and compressed backups',
    long_description=long_description,
    license='BSD',
    platforms=['Linux', 'MacOS X', 'FreeBSD', ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=['borg', 'borg.testsuite'],
    scripts=['scripts/borg'],
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    # msgpack pure python data corruption was fixed in 0.4.6.
    # Also, we might use some rather recent API features.
    install_requires=['msgpack-python>=0.4.6']
)
