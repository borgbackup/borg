# Support code for building a C extension with checksums code

import os


def xxhash_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected and preferring libxxhash [via BORG_LIBXXHASH_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['xxhash'])

    if pc and pc.installed('libxxhash', '>= 0.7.3'):
        print('Detected and preferring libxxhash [via pkg-config]')
        return pc.parse('libxxhash')

    raise Exception('Could not find xxhash lib/headers, please set BORG_LIBXXHASH_PREFIX')


def deflate_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected and preferring libdeflate [via BORG_LIBDEFLATE_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['deflate'])

    if pc and pc.installed('libdeflate', '>= 1.5'):
        print('Detected and preferring libdeflate [via pkg-config]')
        return pc.parse('libdeflate')

    raise Exception('Could not find deflate lib/headers, please set BORG_LIBDEFLATE_PREFIX')
