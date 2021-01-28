# Support code for building a C extension with crypto code

import os
import sys

is_win32 = sys.platform.startswith('win32')


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


def crypto_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected OpenSSL [via BORG_OPENSSL_PREFIX]')
        if is_win32:
            lib_dir = system_prefix
            lib_name = 'libcrypto'
        else:
            lib_dir = os.path.join(system_prefix, 'lib')
            lib_name = 'crypto'

        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[lib_dir],
                    libraries=[lib_name])

    if pc and pc.exists('libcrypto'):
        print('Detected OpenSSL [via pkg-config]')
        return pc.parse('libcrypto')

    raise Exception('Could not find OpenSSL lib/headers, please set BORG_OPENSSL_PREFIX')
