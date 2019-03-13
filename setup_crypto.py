# Support code for building a C extension with crypto from OpenSSL / LibreSSL

import os


def crypto_ext_kwargs(pc):
    system_prefix = os.environ.get('BORG_OPENSSL_PREFIX')
    if system_prefix:
        print('Detected OpenSSL [via BORG_OPENSSL_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['crypto'])

    if pc and pc.exists('libcrypto'):
        print('Detected OpenSSL [via pkg-config]')
        return pc.parse('libcrypto')

    raise Exception('Could not find OpenSSL lib/headers, please set BORG_OPENSSL_PREFIX')
