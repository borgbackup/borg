# borgbackup - main setup code (see also pyproject.toml and other setup_*.py files)

import os
import sys
from collections import defaultdict
from glob import glob

try:
    import multiprocessing
except ImportError:
    multiprocessing = None

from setuptools.command.build_ext import build_ext
from setuptools import setup, Extension, Command
from setuptools.command.sdist import sdist

try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = None

sys.path += [os.path.dirname(__file__)]
import setup_checksums
import setup_compress
import setup_crypto
import setup_docs

is_win32 = sys.platform.startswith('win32')

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

# needed: lz4 (>= 1.7.0 / r129)
prefer_system_liblz4 = not bool(os.environ.get('BORG_USE_BUNDLED_LZ4'))
system_prefix_liblz4 = os.environ.get('BORG_LIBLZ4_PREFIX')

# needed: zstd (>= 1.3.0)
prefer_system_libzstd = not bool(os.environ.get('BORG_USE_BUNDLED_ZSTD'))
system_prefix_libzstd = os.environ.get('BORG_LIBZSTD_PREFIX')

prefer_system_libxxhash = not bool(os.environ.get('BORG_USE_BUNDLED_XXHASH'))
system_prefix_libxxhash = os.environ.get('BORG_LIBXXHASH_PREFIX')

# Number of threads to use for cythonize, not used on windows
cpu_threads = multiprocessing.cpu_count() if multiprocessing and multiprocessing.get_start_method() != 'spawn' else None

# Are we building on ReadTheDocs?
on_rtd = os.environ.get('READTHEDOCS')

# Extra cflags for all extensions, usually just warnings we want to explicitly enable
cflags = [
    '-Wall',
    '-Wextra',
    '-Wpointer-arith',
]

compress_source = 'src/borg/compress.pyx'
crypto_ll_source = 'src/borg/crypto/low_level.pyx'
crypto_helpers = 'src/borg/crypto/_crypto_helpers.c'
chunker_source = 'src/borg/chunker.pyx'
hashindex_source = 'src/borg/hashindex.pyx'
item_source = 'src/borg/item.pyx'
checksums_source = 'src/borg/algorithms/checksums.pyx'
platform_posix_source = 'src/borg/platform/posix.pyx'
platform_linux_source = 'src/borg/platform/linux.pyx'
platform_syncfilerange_source = 'src/borg/platform/syncfilerange.pyx'
platform_darwin_source = 'src/borg/platform/darwin.pyx'
platform_freebsd_source = 'src/borg/platform/freebsd.pyx'
platform_windows_source = 'src/borg/platform/windows.pyx'

cython_sources = [
    compress_source,
    crypto_ll_source,
    chunker_source,
    hashindex_source,
    item_source,
    checksums_source,

    platform_posix_source,
    platform_linux_source,
    platform_syncfilerange_source,
    platform_freebsd_source,
    platform_darwin_source,
    platform_windows_source,
]

if cythonize:
    Sdist = sdist
else:
    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    cython_c_files = [fn.replace('.pyx', '.c') for fn in cython_sources]
    if not on_rtd and not all(os.path.exists(path) for path in cython_c_files):
        raise ImportError('The GIT version of Borg needs Cython. Install Cython or use a released version.')


def rm(file):
    try:
        os.unlink(file)
        print('rm', file)
    except FileNotFoundError:
        pass


class Clean(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
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
    'clean2': Clean,
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
        dict(extra_compile_args=cflags),
    )

    compress_ext_kwargs = members_appended(
        dict(sources=[compress_source]),
        setup_compress.lz4_ext_kwargs(pc, prefer_system_liblz4, system_prefix_liblz4),
        setup_compress.zstd_ext_kwargs(pc, prefer_system_libzstd, system_prefix_libzstd,
                                       multithreaded=False, legacy=False),
        dict(extra_compile_args=cflags),
    )

    checksums_ext_kwargs = members_appended(
        dict(sources=[checksums_source]),
        setup_checksums.xxhash_ext_kwargs(pc, prefer_system_libxxhash, system_prefix_libxxhash),
        dict(extra_compile_args=cflags),
    )

    ext_modules += [
        Extension('borg.crypto.low_level', **crypto_ext_kwargs),
        Extension('borg.compress', **compress_ext_kwargs),
        Extension('borg.hashindex', [hashindex_source], extra_compile_args=cflags),
        Extension('borg.item', [item_source], extra_compile_args=cflags),
        Extension('borg.chunker', [chunker_source], extra_compile_args=cflags),
        Extension('borg.algorithms.checksums', **checksums_ext_kwargs),
    ]

    posix_ext = Extension('borg.platform.posix', [platform_posix_source], extra_compile_args=cflags)
    linux_ext = Extension('borg.platform.linux', [platform_linux_source], libraries=['acl'], extra_compile_args=cflags)
    syncfilerange_ext = Extension('borg.platform.syncfilerange', [platform_syncfilerange_source], extra_compile_args=cflags)
    freebsd_ext = Extension('borg.platform.freebsd', [platform_freebsd_source], extra_compile_args=cflags)
    darwin_ext = Extension('borg.platform.darwin', [platform_darwin_source], extra_compile_args=cflags)
    windows_ext = Extension('borg.platform.windows', [platform_windows_source], extra_compile_args=cflags)

    if not is_win32:
        ext_modules.append(posix_ext)
    else:
        ext_modules.append(windows_ext)
    if sys.platform == 'linux':
        ext_modules.append(linux_ext)
        ext_modules.append(syncfilerange_ext)
    elif sys.platform.startswith('freebsd'):
        ext_modules.append(freebsd_ext)
    elif sys.platform == 'darwin':
        ext_modules.append(darwin_ext)

    # sometimes there's no need to cythonize
    # this breaks chained commands like 'clean sdist'
    cythonizing = len(sys.argv) > 1 and sys.argv[1] not in (
        ('clean', 'clean2', 'egg_info', '--help-commands', '--version')) and '--help' not in sys.argv[1:]

    if cythonize and cythonizing:
        cython_opts = dict(
            # 3str is the default in Cython3 and we do not support older Cython releases.
            # we only set this to avoid the related FutureWarning from Cython3.
            compiler_directives={'language_level': '3str'}
        )
        if not is_win32:
            # compile .pyx extensions to .c in parallel, does not work on windows
            cython_opts['nthreads'] = cpu_threads

        # generate C code from Cython for ALL supported platforms, so we have them in the sdist.
        # the sdist does not require Cython at install time, so we need all as C.
        cythonize([posix_ext, linux_ext, syncfilerange_ext, freebsd_ext, darwin_ext, windows_ext], **cython_opts)
        # generate C code from Cython for THIS platform (and for all platform-independent Cython parts).
        ext_modules = cythonize(ext_modules, **cython_opts)

setup(cmdclass=cmdclass, ext_modules=ext_modules, long_description=setup_docs.long_desc_from_readme())
