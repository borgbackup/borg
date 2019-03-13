# Support code for building a C extension with lz4 files
#
# Copyright (c) 2016-present, Gregory Szorc (original code for zstd)
#               2017-present, Thomas Waldmann (mods to make it more generic, code for lz4)
# All rights reserved.
#
# This software may be modified and distributed under the terms
# of the BSD license. See the LICENSE file for details.

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


def lz4_ext_kwargs(prefer_system):
    """return kwargs with lz4 stuff for a distutils.extension.Extension initialization.

    prefer_system: prefer the system-installed library (if found) over the bundled C code
    returns: kwargs for this lib
    """
    def multi_join(paths, *path_segments):
        """apply os.path.join on a list of paths"""
        return [os.path.join(*(path_segments + (path, ))) for path in paths]

    define_macros = []

    system_prefix = os.environ.get('BORG_LIBLZ4_PREFIX')
    if prefer_system and system_prefix:
        print('Detected and preferring liblz4 over bundled LZ4')
        define_macros.append(('BORG_USE_LIBLZ4', 'YES'))
        system = True
    else:
        print('Using bundled LZ4')
        system = False

    use_system = system and system_prefix is not None

    if use_system:
        sources = []
        include_dirs = multi_join(['include'], system_prefix)
        library_dirs = multi_join(['lib'], system_prefix)
        libraries = ['lz4', ]
    else:
        sources = multi_join(lz4_sources, bundled_path)
        include_dirs = multi_join(lz4_includes, bundled_path)
        library_dirs = []
        libraries = []

    extra_compile_args = []

    return dict(sources=sources, define_macros=define_macros, extra_compile_args=extra_compile_args,
               include_dirs=include_dirs, library_dirs=library_dirs, libraries=libraries)
