# Support code for building a C extension with crypto code

import os


def multi_join(paths, *path_segments):
    """apply os.path.join on a list of paths"""
    return [os.path.join(*(path_segments + (path,))) for path in paths]


def crypto_ext_kwargs(pc, system_prefix):
    if system_prefix:
        print('Detected OpenSSL [via BORG_OPENSSL_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['crypto'])

    if pc and pc.exists('libcrypto'):
        print('Detected OpenSSL [via pkg-config]')
        return pc.parse('libcrypto')

    raise Exception('Could not find OpenSSL lib/headers, please set BORG_OPENSSL_PREFIX')


# b2 files, structure as seen in BLAKE2 (reference implementation) project repository:

# path relative (to this file) to the bundled library source code files
b2_bundled_path = 'src/borg/algorithms/blake2'

b2_sources = [
    'ref/blake2b-ref.c',
]

b2_includes = [
    'ref',
]


def b2_ext_kwargs(pc, prefer_system, system_prefix):
    if prefer_system:
        if system_prefix:
            print('Detected and preferring libb2 [via BORG_LIBB2_PREFIX]')
            return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                        library_dirs=[os.path.join(system_prefix, 'lib')],
                        libraries=['b2'])

        if pc and pc.installed('libb2', '>= 0.98.1'):
            print('Detected and preferring libb2 [via pkg-config]')
            return pc.parse('libb2')

    print('Using bundled BLAKE2')
    sources = multi_join(b2_sources, b2_bundled_path)
    include_dirs = multi_join(b2_includes, b2_bundled_path)
    define_macros = [('BORG_USE_BUNDLED_B2', 'YES')]
    return dict(sources=sources, include_dirs=include_dirs, define_macros=define_macros)
