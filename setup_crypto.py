# Support code for building a C extension with crypto from OpenSSL / LibreSSL

import os


def crypto_ext_kwargs():
    system_prefix = os.environ.get('BORG_OPENSSL_PREFIX')
    if system_prefix:
        print('Detected OpenSSL [via BORG_OPENSSL_PREFIX]')
        return dict(include_dirs=[os.path.join(system_prefix, 'include')],
                    library_dirs=[os.path.join(system_prefix, 'lib')],
                    libraries=['crypto'])

    import pkgconfig

    if pkgconfig.exists('libcrypto'):
        print('Detected OpenSSL [via pkg-config]')
        return pkgconfig.parse('libcrypto')

    raise Exception('Could not find OpenSSL lib/headers, please set BORG_OPENSSL_PREFIX')
