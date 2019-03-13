# Support code for building a C extension with blake2

import os

# b2 files, structure as seen in BLAKE2 (reference implementation) project repository:

# bundled_path: relative (to this file) path to the bundled library source code files
bundled_path = 'src/borg/algorithms/blake2'

b2_sources = [
    'ref/blake2b-ref.c',
]

b2_includes = [
    'ref',
]


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


def b2_ext_kwargs(prefer_system):
    if prefer_system:
        system_prefix = os.environ.get('BORG_LIBB2_PREFIX')
        if system_prefix:
            print('Detected and preferring libb2 [via BORG_LIBB2_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['b2'])

        import pkgconfig

        if pkgconfig.installed('libb2', '>= 0.98.1'):
            print('Detected and preferring libb2 [via pkg-config]')
            return pkgconfig.parse('libb2')

    print('Using bundled BLAKE2')
    sources = multi_join(b2_sources, bundled_path)
    include_dirs = multi_join(b2_includes, bundled_path)
    define_macros = [('BORG_USE_BUNDLED_B2', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs, define_macros=define_macros)
