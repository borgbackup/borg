# Support code for building a C extension with checksums code

import os


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


# xxhash files, structure as seen in xxhash project repository:

# path relative (to this file) to the bundled library source code files
xxhash_bundled_path = 'src/borg/algorithms/xxh64'

xxhash_sources = [
    'xxhash.c',
]

xxhash_includes = [
    '',
]


def xxhash_ext_kwargs(pc, prefer_system, system_prefix):
    if prefer_system:
        if system_prefix:
            print('Detected and preferring libxxhash [via BORG_LIBXXHASH_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['xxhash'])

        if pc and pc.installed('libxxhash', '>= 0.7.3'):
            print('Detected and preferring libxxhash [via pkg-config]')
            return pc.parse('libxxhash')

    print('Using bundled xxhash')
    sources = multi_join(xxhash_sources, xxhash_bundled_path)
    include_dirs = multi_join(xxhash_includes, xxhash_bundled_path)
    define_macros = [('BORG_USE_BUNDLED_XXHASH', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs, define_macros=define_macros)

