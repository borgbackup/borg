# Support code for building a C extension with lz4 files

import os

# lz4 files, structure as seen in lz4 project repository:

# bundled_path: relative (to this file) path to the bundled library source code files
bundled_path = 'src/borg/algorithms/lz4'

lz4_sources = [
    'lib/lz4.c',
]

lz4_includes = [
    'lib',
]


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


def lz4_ext_kwargs(pc, prefer_system):
    if prefer_system:
        system_prefix = os.environ.get('BORG_LIBLZ4_PREFIX')
        if system_prefix:
            print('Detected and preferring liblz4 [via BORG_LIBLZ4_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['lz4'])

        if pc and pc.installed('liblz4', '>= 1.7.0'):
            print('Detected and preferring liblz4 [via pkg-config]')
            return pc.parse('liblz4')

    print('Using bundled LZ4')
    sources = multi_join(lz4_sources, bundled_path)
    include_dirs = multi_join(lz4_includes, bundled_path)
    define_macros = [('BORG_USE_BUNDLED_LZ4', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs, define_macros=define_macros)
