# Support code for building a C extension with compression code

import os


def zstd_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected and preferring libzstd [via BORG_LIBZSTD_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['zstd'])

    if pc and pc.installed('libzstd', '>= 1.3.0'):
        print('Detected and preferring libzstd [via pkg-config]')
        return pc.parse('libzstd')

    raise Exception('Could not find zstd lib/headers, please set BORG_LIBZSTD_PREFIX')


def lz4_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected and preferring liblz4 [via BORG_LIBLZ4_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['lz4'])

    if pc and pc.installed('liblz4', '>= 1.7.0'):
        print('Detected and preferring liblz4 [via pkg-config]')
        return pc.parse('liblz4')

    raise Exception('Could not find lz4 lib/headers, please set BORG_LIBLZ4_PREFIX')
