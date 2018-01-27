# Support code for building a C extension with blake2 files
#
# Copyright (c) 2016-present, Gregory Szorc (original code for zstd)
#               2017-present, Thomas Waldmann (mods to make it more generic, code for blake2)
# All rights reserved.
#
# This software may be modified and distributed under the terms
# of the BSD license. See the LICENSE file for details.

import os

# b2 files, structure as seen in BLAKE2 (reference implementation) project repository:

b2_sources = [
    'ref/blake2b-ref.c',
]

b2_includes = [
    'ref',
]


def b2_system_prefix(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'blake2.h')
        if os.path.exists(filename):
            with open(filename, 'rb') as fd:
                if b'blake2b_init' in fd.read():
                    return prefix


def b2_ext_kwargs(bundled_path, system_prefix=None, system=False, **kwargs):
    """amend kwargs with b2 stuff for a distutils.extension.Extension initialization.

    bundled_path: relative (to this file) path to the bundled library source code files
    system_prefix: where the system-installed library can be found
    system: True: use the system-installed shared library, False: use the bundled library code
    kwargs: distutils.extension.Extension kwargs that should be amended
    returns: amended kwargs
    """
    def multi_join(paths, *path_segments):
        """apply os.path.join on a list of paths"""
        return [os.path.join(*(path_segments + (path, ))) for path in paths]

    use_system = system and system_prefix is not None

    sources = kwargs.get('sources', [])
    if not use_system:
        sources += multi_join(b2_sources, bundled_path)

    include_dirs = kwargs.get('include_dirs', [])
    if use_system:
        include_dirs += multi_join(['include'], system_prefix)
    else:
        include_dirs += multi_join(b2_includes, bundled_path)

    library_dirs = kwargs.get('library_dirs', [])
    if use_system:
        library_dirs += multi_join(['lib'], system_prefix)

    libraries = kwargs.get('libraries', [])
    if use_system:
        libraries += ['b2', ]

    extra_compile_args = kwargs.get('extra_compile_args', [])
    if not use_system:
        extra_compile_args += []  # not used yet

    ret = dict(**kwargs)
    ret.update(dict(sources=sources, extra_compile_args=extra_compile_args,
                    include_dirs=include_dirs, library_dirs=library_dirs, libraries=libraries))
    return ret
