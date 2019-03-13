# Support code for building a C extension with crypto from OpenSSL
#
# Copyright (c) 2016-present, Gregory Szorc (original code for zstd)
#               2017-present, Thomas Waldmann (mods to make it more generic, code for openssl)
# All rights reserved.
#
# This software may be modified and distributed under the terms
# of the BSD license. See the LICENSE file for details.

import os


def crypto_ext_kwargs():
    """return kwargs with crypto stuff for a distutils.extension.Extension initialization.

    returns: kwargs for this lib
    """
    def multi_join(paths, *path_segments):
        """apply os.path.join on a list of paths"""
        return [os.path.join(*(path_segments + (path, ))) for path in paths]

    system_prefix = os.environ.get('BORG_OPENSSL_PREFIX')
    if system_prefix:
        print('Detected system OpenSSL')
    else:
        raise Exception('Could not find OpenSSL lib/headers, please set BORG_OPENSSL_PREFIX')

    include_dirs = multi_join(['include'], system_prefix)
    library_dirs = multi_join(['lib'], system_prefix)
    libraries = ['crypto', ]

    return dict(include_dirs=include_dirs, library_dirs=library_dirs, libraries=libraries)
