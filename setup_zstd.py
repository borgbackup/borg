# Copyright (c) 2016-present, Gregory Szorc
# All rights reserved.
#
# This software may be modified and distributed under the terms
# of the BSD license. See the LICENSE file for details.

import os
from distutils.extension import Extension


zstd_sources = ['zstd/%s' % p for p in (
    'common/entropy_common.c',
    'common/error_private.c',
    'common/fse_decompress.c',
    'common/pool.c',
    'common/threading.c',
    'common/xxhash.c',
    'common/zstd_common.c',
    'compress/fse_compress.c',
    'compress/huf_compress.c',
    'compress/zstd_compress.c',
    'compress/zstdmt_compress.c',
    'decompress/huf_decompress.c',
    'decompress/zstd_decompress.c',
    'dictBuilder/cover.c',
    'dictBuilder/divsufsort.c',
    'dictBuilder/zdict.c',
)]

zstd_sources_legacy = ['zstd/%s' % p for p in (
    'deprecated/zbuff_common.c',
    'deprecated/zbuff_compress.c',
    'deprecated/zbuff_decompress.c',
    'legacy/zstd_v01.c',
    'legacy/zstd_v02.c',
    'legacy/zstd_v03.c',
    'legacy/zstd_v04.c',
    'legacy/zstd_v05.c',
    'legacy/zstd_v06.c',
    'legacy/zstd_v07.c'
)]

zstd_includes = [
    'zstd',
    'zstd/common',
    'zstd/compress',
    'zstd/decompress',
    'zstd/dictBuilder',
]

zstd_includes_legacy = [
    'zstd/deprecated',
    'zstd/legacy',
]

ext_includes = [
    'c-ext',
    'zstd/common',
]

ext_sources = [
    'zstd/common/pool.c',
    'zstd/common/threading.c',
    'zstd.c',
    'c-ext/bufferutil.c',
    'c-ext/compressiondict.c',
    'c-ext/compressobj.c',
    'c-ext/compressor.c',
    'c-ext/compressoriterator.c',
    'c-ext/compressionparams.c',
    'c-ext/compressionreader.c',
    'c-ext/compressionwriter.c',
    'c-ext/constants.c',
    'c-ext/decompressobj.c',
    'c-ext/decompressor.c',
    'c-ext/decompressoriterator.c',
    'c-ext/decompressionreader.c',
    'c-ext/decompressionwriter.c',
    'c-ext/frameparams.c',
]

zstd_depends = [
    'c-ext/python-zstandard.h',
]


def get_c_extension(support_legacy=False, system_zstd=False, name='zstd'):
    """Obtain a distutils.extension.Extension for the C extension."""
    root = os.path.abspath(os.path.dirname(__file__))

    sources = set([os.path.join(root, p) for p in ext_sources])
    if not system_zstd:
        sources.update([os.path.join(root, p) for p in zstd_sources])
        if support_legacy:
            sources.update([os.path.join(root, p) for p in zstd_sources_legacy])
    sources = list(sources)

    include_dirs = set([os.path.join(root, d) for d in ext_includes])
    if not system_zstd:
        include_dirs.update([os.path.join(root, d) for d in zstd_includes])
        if support_legacy:
            include_dirs.update([os.path.join(root, d) for d in zstd_includes_legacy])
    include_dirs = list(include_dirs)

    depends = [os.path.join(root, p) for p in zstd_depends]

    extra_args = ['-DZSTD_MULTITHREAD']

    if not system_zstd:
        extra_args.append('-DZSTDLIB_VISIBILITY=')
        extra_args.append('-DZDICTLIB_VISIBILITY=')
        extra_args.append('-DZSTDERRORLIB_VISIBILITY=')
        extra_args.append('-fvisibility=hidden')

    if not system_zstd and support_legacy:
        extra_args.append('-DZSTD_LEGACY_SUPPORT=1')

    libraries = ['zstd'] if system_zstd else []

    # TODO compile with optimizations.
    return Extension(name, sources,
                     include_dirs=include_dirs,
                     depends=depends,
                     extra_compile_args=extra_args,
                     libraries=libraries)
