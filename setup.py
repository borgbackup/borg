# borgbackup - main setup code (see also other setup_*.py files)

import os
import sys
from collections import defaultdict
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

import setup_compress
import setup_crypto
import setup_docs

# How the build process finds the system libs / uses the bundled code:
#
# 1. it will try to use (system) libs (see 1.1. and 1.2.),
#    except if you use these env vars to force using the bundled code:
#    BORG_USE_BUNDLED_XXX undefined  -->  try using system lib
#    BORG_USE_BUNDLED_XXX=YES        -->  use the bundled code
#    Note: do not use =NO, that is not supported!
# 1.1. if BORG_LIBXXX_PREFIX is set, it will use headers and libs from there.
# 1.2. if not and pkg-config can locate the lib, the lib located by
#      pkg-config will be used. We use the pkg-config tool via the pkgconfig
#      python package, which must be installed before invoking setup.py.
#      if pkgconfig is not installed, this step is skipped.
# 2. if no system lib could be located via 1.1. or 1.2., it will fall back
#    to using the bundled code.

# OpenSSL is required as a (system) lib in any case as we do not bundle it.
# Thus, only step 1.1. and 1.2. apply to openssl (but not 1. and 2.).
# needed: openssl >=1.0.2 or >=1.1.0 (or compatible)
system_prefix_openssl = os.environ.get('BORG_OPENSSL_PREFIX')

# needed: blake2 (>= 0.98.1)
prefer_system_libb2 = not bool(os.environ.get('BORG_USE_BUNDLED_B2'))
system_prefix_libb2 = os.environ.get('BORG_LIBB2_PREFIX')

# needed: lz4 (>= 1.7.0 / r129)
prefer_system_liblz4 = not bool(os.environ.get('BORG_USE_BUNDLED_LZ4'))
system_prefix_liblz4 = os.environ.get('BORG_LIBLZ4_PREFIX')

# needed: zstd (>= 1.3.0)
prefer_system_libzstd = not bool(os.environ.get('BORG_USE_BUNDLED_ZSTD'))
system_prefix_libzstd = os.environ.get('BORG_LIBZSTD_PREFIX')

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

    def members_appended(*ds):
        result = defaultdict(list)
        for d in ds:
            for k, v in d.items():
                assert isinstance(v, list)
                result[k].extend(v)
        return result

    try:
        import pkgconfig as pc
    except ImportError:
        print('Warning: can not import pkgconfig python package.')
        pc = None

    crypto_ext_kwargs = members_appended(
        dict(sources=[crypto_ll_source, crypto_helpers]),
        setup_crypto.crypto_ext_kwargs(pc, system_prefix_openssl),
        setup_crypto.b2_ext_kwargs(pc, prefer_system_libb2, system_prefix_libb2),
    )

    compress_ext_kwargs = members_appended(
        dict(sources=[compress_source]),
        setup_compress.lz4_ext_kwargs(pc, prefer_system_liblz4, system_prefix_liblz4),
        setup_compress.zstd_ext_kwargs(pc, prefer_system_libzstd, system_prefix_libzstd,
                                       multithreaded=False, legacy=False),
    )

    ext_modules += [
        Extension('borg.crypto.low_level', **crypto_ext_kwargs),
        Extension('borg.compress', **compress_ext_kwargs),
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
    long_description=setup_docs.long_desc_from_readme(),
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
