# Support code for building a C extension with compression code

import os


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


# zstd files, structure as seen in zstd project repository:

# path relative (to this file) to the bundled library source code files
zstd_bundled_path = 'src/borg/algorithms/zstd'

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


def zstd_ext_kwargs(pc, prefer_system, system_prefix, multithreaded=False, legacy=False):
    if prefer_system:
        if system_prefix:
            print('Detected and preferring libzstd [via BORG_LIBZSTD_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['zstd'])

        if pc and pc.installed('libzstd', '>= 1.3.0'):
            print('Detected and preferring libzstd [via pkg-config]')
            return pc.parse('libzstd')

    print('Using bundled ZSTD')
    sources = multi_join(zstd_sources, zstd_bundled_path)
    if legacy:
        sources += multi_join(zstd_sources_legacy, zstd_bundled_path)
    include_dirs = multi_join(zstd_includes, zstd_bundled_path)
    if legacy:
        include_dirs += multi_join(zstd_includes_legacy, zstd_bundled_path)
    extra_compile_args = ['-DZSTDLIB_VISIBILITY=', '-DZDICTLIB_VISIBILITY=', '-DZSTDERRORLIB_VISIBILITY=', ]
    # '-fvisibility=hidden' does not work, doesn't find PyInit_compress then
    if legacy:
        extra_compile_args += ['-DZSTD_LEGACY_SUPPORT=1', ]
    if multithreaded:
        extra_compile_args += ['-DZSTD_MULTITHREAD', ]
    define_macros = [('BORG_USE_BUNDLED_ZSTD', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs,
                extra_compile_args=extra_compile_args, define_macros=define_macros)


# lz4 files, structure as seen in lz4 project repository:

# path relative (to this file) to the bundled library source code files
lz4_bundled_path = 'src/borg/algorithms/lz4'

lz4_sources = [
    'lib/lz4.c',
]

lz4_includes = [
    'lib',
]


def lz4_ext_kwargs(pc, prefer_system, system_prefix):
    if prefer_system:
        if system_prefix:
            print('Detected and preferring liblz4 [via BORG_LIBLZ4_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['lz4'])

        if pc and pc.installed('liblz4', '>= 1.7.0'):
            print('Detected and preferring liblz4 [via pkg-config]')
            return pc.parse('liblz4')

    print('Using bundled LZ4')
    sources = multi_join(lz4_sources, lz4_bundled_path)
    include_dirs = multi_join(lz4_includes, lz4_bundled_path)
    define_macros = [('BORG_USE_BUNDLED_LZ4', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs, define_macros=define_macros)
