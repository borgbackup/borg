import os
import io
import re
import sys
from collections import OrderedDict
from datetime import datetime
from glob import glob

try:
    import multiprocessing
except ImportError:
    multiprocessing = None

from distutils.command.clean import clean
from setuptools.command.build_ext import build_ext
from setuptools import setup, find_packages, Extension
from setuptools.command.sdist import sdist

try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = None

import setup_lz4
import setup_zstd
import setup_b2
import setup_docs

# True: use the shared liblz4 (>= 1.7.0 / r129) from the system, False: use the bundled lz4 code
prefer_system_liblz4 = True

# True: use the shared libzstd (>= 1.3.0) from the system, False: use the bundled zstd code
prefer_system_libzstd = True

# True: use the shared libb2 from the system, False: use the bundled blake2 code
prefer_system_libb2 = True

cpu_threads = multiprocessing.cpu_count() if multiprocessing else 1

# Are we building on ReadTheDocs?
on_rtd = os.environ.get('READTHEDOCS')

install_requires = [
    # we are rather picky about msgpack versions, because a good working msgpack is
    # very important for borg, see: https://github.com/borgbackup/borg/issues/3753
    'msgpack >=0.5.6, <=0.6.1',
    # Please note:
    # using any other version is not supported by borg development and
    # any feedback related to issues caused by this will be ignored.
]

# note for package maintainers: if you package borgbackup for distribution,
# please add llfuse as a *requirement* on all platforms that have a working
# llfuse package. "borg mount" needs llfuse to work.
# if you do not have llfuse, do not require it, most of borgbackup will work.
extras_require = {
    # llfuse 1.x should work, llfuse 2.0 will break API
    'fuse': [
        'llfuse >=1.1, <2.0',
        'llfuse >=1.3.4; python_version >="3.7"',
    ],
}

compress_source = 'src/borg/compress.pyx'
crypto_ll_source = 'src/borg/crypto/low_level.pyx'
crypto_helpers = 'src/borg/crypto/_crypto_helpers.c'
chunker_source = 'src/borg/chunker.pyx'
hashindex_source = 'src/borg/hashindex.pyx'
item_source = 'src/borg/item.pyx'
checksums_source = 'src/borg/algorithms/checksums.pyx'
platform_posix_source = 'src/borg/platform/posix.pyx'
platform_linux_source = 'src/borg/platform/linux.pyx'
platform_darwin_source = 'src/borg/platform/darwin.pyx'
platform_freebsd_source = 'src/borg/platform/freebsd.pyx'

cython_sources = [
    compress_source,
    crypto_ll_source,
    chunker_source,
    hashindex_source,
    item_source,
    checksums_source,

    platform_posix_source,
    platform_linux_source,
    platform_freebsd_source,
    platform_darwin_source,
]

if cythonize:
    Sdist = sdist
else:
    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    if not on_rtd and not all(os.path.exists(path) for path in [
        compress_source, crypto_ll_source, chunker_source, hashindex_source, item_source, checksums_source,
        platform_posix_source, platform_linux_source, platform_freebsd_source, platform_darwin_source]):
        raise ImportError('The GIT version of Borg needs Cython. Install Cython or use a released version.')


def detect_openssl(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'openssl', 'evp.h')
        if os.path.exists(filename):
            with open(filename, 'rb') as fd:
                if b'PKCS5_PBKDF2_HMAC(' in fd.read():
                    return prefix


include_dirs = []
library_dirs = []
define_macros = []

possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl',
                             '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_OPENSSL_PREFIX'))
ssl_prefix = detect_openssl(possible_openssl_prefixes)
if not ssl_prefix:
    raise Exception('Unable to find OpenSSL >= 1.0 headers. (Looked here: {})'.format(', '.join(possible_openssl_prefixes)))
include_dirs.append(os.path.join(ssl_prefix, 'include'))
library_dirs.append(os.path.join(ssl_prefix, 'lib'))


possible_liblz4_prefixes = ['/usr', '/usr/local', '/usr/local/opt/lz4', '/usr/local/lz4',
                         '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBLZ4_PREFIX'):
    possible_liblz4_prefixes.insert(0, os.environ.get('BORG_LIBLZ4_PREFIX'))
liblz4_prefix = setup_lz4.lz4_system_prefix(possible_liblz4_prefixes)
if prefer_system_liblz4 and liblz4_prefix:
    print('Detected and preferring liblz4 over bundled LZ4')
    define_macros.append(('BORG_USE_LIBLZ4', 'YES'))
    liblz4_system = True
else:
    liblz4_system = False

possible_libb2_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libb2', '/usr/local/libb2',
                           '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBB2_PREFIX'):
    possible_libb2_prefixes.insert(0, os.environ.get('BORG_LIBB2_PREFIX'))
libb2_prefix = setup_b2.b2_system_prefix(possible_libb2_prefixes)
if prefer_system_libb2 and libb2_prefix:
    print('Detected and preferring libb2 over bundled BLAKE2')
    define_macros.append(('BORG_USE_LIBB2', 'YES'))
    libb2_system = True
else:
    libb2_system = False

possible_libzstd_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libzstd', '/usr/local/libzstd',
                             '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBZSTD_PREFIX'):
    possible_libzstd_prefixes.insert(0, os.environ.get('BORG_LIBZSTD_PREFIX'))
libzstd_prefix = setup_zstd.zstd_system_prefix(possible_libzstd_prefixes)
if prefer_system_libzstd and libzstd_prefix:
    print('Detected and preferring libzstd over bundled ZSTD')
    define_macros.append(('BORG_USE_LIBZSTD', 'YES'))
    libzstd_system = True
else:
    libzstd_system = False


with open('README.rst', 'r') as fd:
    long_description = fd.read()
    # remove header, but have one \n before first headline
    start = long_description.find('What is BorgBackup?')
    assert start >= 0
    long_description = '\n' + long_description[start:]
    # remove badges
    long_description = re.compile(r'^\.\. start-badges.*^\.\. end-badges', re.M | re.S).sub('', long_description)
    # remove unknown directives
    long_description = re.compile(r'^\.\. highlight:: \w+$', re.M).sub('', long_description)


def rm(file):
    try:
        os.unlink(file)
        print('rm', file)
    except FileNotFoundError:
        pass


class Clean(clean):
    def run(self):
        super().run()
        for source in cython_sources:
            genc = source.replace('.pyx', '.c')
            rm(genc)
            compiled_glob = source.replace('.pyx', '.cpython*')
            for compiled in sorted(glob(compiled_glob)):
                rm(compiled)


cmdclass = {
    'build_ext': build_ext,
    'build_usage': setup_docs.build_usage,
    'build_man': setup_docs.build_man,
    'sdist': Sdist,
    'clean': Clean,
}

ext_modules = []
if not on_rtd:
    compress_ext_kwargs = dict(sources=[compress_source], include_dirs=include_dirs, library_dirs=library_dirs,
                               define_macros=define_macros)
    compress_ext_kwargs = setup_lz4.lz4_ext_kwargs(bundled_path='src/borg/algorithms/lz4',
                                                   system_prefix=liblz4_prefix, system=liblz4_system,
                                                   **compress_ext_kwargs)
    compress_ext_kwargs = setup_zstd.zstd_ext_kwargs(bundled_path='src/borg/algorithms/zstd',
                                                     system_prefix=libzstd_prefix, system=libzstd_system,
                                                     multithreaded=False, legacy=False, **compress_ext_kwargs)
    crypto_ext_kwargs = dict(sources=[crypto_ll_source, crypto_helpers], libraries=['crypto'],
                             include_dirs=include_dirs, library_dirs=library_dirs, define_macros=define_macros)
    crypto_ext_kwargs = setup_b2.b2_ext_kwargs(bundled_path='src/borg/algorithms/blake2',
                                               system_prefix=libb2_prefix, system=libb2_system,
                                               **crypto_ext_kwargs)
    ext_modules += [
        Extension('borg.compress', **compress_ext_kwargs),
        Extension('borg.crypto.low_level', **crypto_ext_kwargs),
        Extension('borg.hashindex', [hashindex_source]),
        Extension('borg.item', [item_source]),
        Extension('borg.chunker', [chunker_source]),
        Extension('borg.algorithms.checksums', [checksums_source]),
    ]

    posix_ext = Extension('borg.platform.posix', [platform_posix_source])
    linux_ext = Extension('borg.platform.linux', [platform_linux_source], libraries=['acl'])
    freebsd_ext = Extension('borg.platform.freebsd', [platform_freebsd_source])
    darwin_ext = Extension('borg.platform.darwin', [platform_darwin_source])

    if not sys.platform.startswith(('win32', )):
        ext_modules.append(posix_ext)
    if sys.platform == 'linux':
        ext_modules.append(linux_ext)
    elif sys.platform.startswith('freebsd'):
        ext_modules.append(freebsd_ext)
    elif sys.platform == 'darwin':
        ext_modules.append(darwin_ext)

    # sometimes there's no need to cythonize
    # this breaks chained commands like 'clean sdist'
    cythonizing = len(sys.argv) > 1 and sys.argv[1] not in ('clean', 'egg_info', '--help-commands', '--version') \
                  and '--help' not in sys.argv[1:]

    if cythonize and cythonizing:
        cython_opts = dict(
            # compile .pyx extensions to .c in parallel
            nthreads=cpu_threads + 1,
            # default language_level will be '3str' starting from Cython 3.0.0,
            # but old cython versions (< 0.29) do not know that, thus we use 3 for now.
            compiler_directives={'language_level': 3},
        )
        cythonize([posix_ext, linux_ext, freebsd_ext, darwin_ext], **cython_opts)
        ext_modules = cythonize(ext_modules, **cython_opts)

setup(
    name='borgbackup',
    use_scm_version={
        'write_to': 'src/borg/_version.py',
    },
    author='The Borg Collective (see AUTHORS file)',
    author_email='borgbackup@python.org',
    url='https://borgbackup.readthedocs.io/',
    description='Deduplicated, encrypted, authenticated and compressed backups',
    long_description=long_description,
    license='BSD',
    platforms=['Linux', 'MacOS X', 'FreeBSD', 'OpenBSD', 'NetBSD', ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Operating System :: POSIX :: BSD :: OpenBSD',
        'Operating System :: POSIX :: BSD :: NetBSD',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'borg = borg.archiver:main',
            'borgfs = borg.archiver:main',
        ]
    },
    # See also the MANIFEST.in file.
    # We want to install all the files in the package directories...
    include_package_data=True,
    # ...except the source files which have been compiled (C extensions):
    exclude_package_data={
        '': ['*.c', '*.h', '*.pyx', ],
    },
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    setup_requires=['setuptools_scm>=1.7'],
    install_requires=install_requires,
    extras_require=extras_require,
    python_requires='>=3.5',
)
