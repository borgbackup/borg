# Support code for building a C extension with zstd

import os

# zstd files, structure as seen in zstd project repository:

# bundled_path: relative (to this file) path to the bundled library source code files
bundled_path = 'src/borg/algorithms/zstd'

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


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


def zstd_ext_kwargs(pc, prefer_system, multithreaded=False, legacy=False):
    if prefer_system:
        system_prefix = os.environ.get('BORG_LIBZSTD_PREFIX')
        if system_prefix:
            print('Detected and preferring libzstd [via BORG_LIBZSTD_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['zstd'])

        if pc and pc.installed('libzstd', '>= 1.3.0'):
            print('Detected and preferring libzstd [via pkg-config]')
            return pc.parse('libzstd')

    print('Using bundled ZSTD')
    sources = multi_join(zstd_sources, bundled_path)
    if legacy:
        sources += multi_join(zstd_sources_legacy, bundled_path)
    include_dirs = multi_join(zstd_includes, bundled_path)
    if legacy:
        include_dirs += multi_join(zstd_includes_legacy, bundled_path)
    extra_compile_args = ['-DZSTDLIB_VISIBILITY=', '-DZDICTLIB_VISIBILITY=', '-DZSTDERRORLIB_VISIBILITY=', ]
    # '-fvisibility=hidden' does not work, doesn't find PyInit_compress then
    if legacy:
        extra_compile_args += ['-DZSTD_LEGACY_SUPPORT=1', ]
    if multithreaded:
        extra_compile_args += ['-DZSTD_MULTITHREAD', ]
    define_macros = [('BORG_USE_BUNDLED_ZSTD', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs,
                extra_compile_args=extra_compile_args, define_macros=define_macros)
