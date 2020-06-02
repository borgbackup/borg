# Support code for building a C extension with zstd files
#
# Copyright (c) 2016-present, Gregory Szorc
#               2017-present, Thomas Waldmann (mods to make it more generic)
# All rights reserved.
#
# This software may be modified and distributed under the terms
# of the BSD license. See the LICENSE file for details.

import os

# zstd files, structure as seen in zstd project repository:

zstd_sources = [
    'lib/common/debug.c',
    'lib/common/entropy_common.c',
    'lib/common/error_private.c',
    'lib/common/fse_decompress.c',
    'lib/common/pool.c',
    'lib/common/threading.c',
    'lib/common/xxhash.c',
    'lib/common/zstd_common.c',
    'lib/compress/fse_compress.c',
    'lib/compress/hist.c',
    'lib/compress/huf_compress.c',
    'lib/compress/zstd_compress.c',
    'lib/compress/zstd_compress_literals.c',
    'lib/compress/zstd_compress_sequences.c',
    'lib/compress/zstd_compress_superblock.c',
    'lib/compress/zstd_double_fast.c',
    'lib/compress/zstd_fast.c',
    'lib/compress/zstd_lazy.c',
    'lib/compress/zstd_ldm.c',
    'lib/compress/zstd_opt.c',
    'lib/compress/zstdmt_compress.c',
    'lib/decompress/huf_decompress.c',
    'lib/decompress/zstd_ddict.c',
    'lib/decompress/zstd_decompress.c',
    'lib/decompress/zstd_decompress_block.c',
    'lib/dictBuilder/cover.c',
    'lib/dictBuilder/divsufsort.c',
    'lib/dictBuilder/fastcover.c',
    'lib/dictBuilder/zdict.c',
]

zstd_sources_legacy = [
    'lib/deprecated/zbuff_common.c',
    'lib/deprecated/zbuff_compress.c',
    'lib/deprecated/zbuff_decompress.c',
    'lib/legacy/zstd_v01.c',
    'lib/legacy/zstd_v02.c',
    'lib/legacy/zstd_v03.c',
    'lib/legacy/zstd_v04.c',
    'lib/legacy/zstd_v05.c',
    'lib/legacy/zstd_v06.c',
    'lib/legacy/zstd_v07.c',
]

zstd_includes = [
    'lib',
    'lib/common',
    'lib/compress',
    'lib/decompress',
    'lib/dictBuilder',
]

zstd_includes_legacy = [
    'lib/deprecated',
    'lib/legacy',
]


def zstd_system_prefix(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'zstd.h')
        if os.path.exists(filename):
            with open(filename, 'rb') as fd:
                if b'ZSTD_getFrameContentSize' in fd.read():  # checks for zstd >= 1.3.0
                    return prefix


def zstd_ext_kwargs(bundled_path, system_prefix=None, system=False, multithreaded=False, legacy=False, **kwargs):
    """amend kwargs with zstd suff for a distutils.extension.Extension initialization.

    bundled_path: relative (to this file) path to the bundled library source code files
    system_prefix: where the system-installed library can be found
    system: True: use the system-installed shared library, False: use the bundled library code
    multithreaded: True: define ZSTD_MULTITHREAD
    legacy: include legacy API support
    kwargs: distutils.extension.Extension kwargs that should be amended
    returns: amended kwargs
    """
    def multi_join(paths, *path_segments):
        """apply os.path.join on a list of paths"""
        return [os.path.join(*(path_segments + (path, ))) for path in paths]

    use_system = system and system_prefix is not None

    sources = kwargs.get('sources', [])
    if not use_system:
        sources += multi_join(zstd_sources, bundled_path)
        if legacy:
            sources += multi_join(zstd_sources_legacy, bundled_path)

    include_dirs = kwargs.get('include_dirs', [])
    if use_system:
        include_dirs += multi_join(['include'], system_prefix)
    else:
        include_dirs += multi_join(zstd_includes, bundled_path)
        if legacy:
            include_dirs += multi_join(zstd_includes_legacy, bundled_path)

    library_dirs = kwargs.get('library_dirs', [])
    if use_system:
        library_dirs += multi_join(['lib'], system_prefix)

    libraries = kwargs.get('libraries', [])
    if use_system:
        libraries += ['zstd', ]

    extra_compile_args = kwargs.get('extra_compile_args', [])
    if multithreaded:
        extra_compile_args += ['-DZSTD_MULTITHREAD', ]
    if not use_system:
        extra_compile_args += ['-DZSTDLIB_VISIBILITY=', '-DZDICTLIB_VISIBILITY=', '-DZSTDERRORLIB_VISIBILITY=', ]
                               # '-fvisibility=hidden' does not work, doesn't find PyInit_compress then
        if legacy:
            extra_compile_args += ['-DZSTD_LEGACY_SUPPORT=1', ]

    ret = dict(**kwargs)
    ret.update(dict(sources=sources, extra_compile_args=extra_compile_args,
                    include_dirs=include_dirs, library_dirs=library_dirs, libraries=libraries))
    return ret
