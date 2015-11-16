# -*- encoding: utf-8 *-*
import os
import re
import sys
from glob import glob

from distutils.command.build import build
from distutils.core import Command

min_python = (3, 2)
my_python = sys.version_info

if my_python < min_python:
    print("Borg requires Python %d.%d or later" % min_python)
    sys.exit(1)

# Are we building on ReadTheDocs?
on_rtd = os.environ.get('READTHEDOCS')

# msgpack pure python data corruption was fixed in 0.4.6.
# Also, we might use some rather recent API features.
install_requires=['msgpack-python>=0.4.6', ]


from setuptools import setup, Extension
from setuptools.command.sdist import sdist


compress_source = 'borg/compress.pyx'
crypto_source = 'borg/crypto.pyx'
chunker_source = 'borg/chunker.pyx'
hashindex_source = 'borg/hashindex.pyx'
platform_linux_source = 'borg/platform_linux.pyx'
platform_darwin_source = 'borg/platform_darwin.pyx'
platform_freebsd_source = 'borg/platform_freebsd.pyx'

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('borg/*.pyx'):
                cython_compiler.compile(src, cython_compiler.default_options)
            super().__init__(*args, **kwargs)

        def make_distribution(self):
            self.filelist.extend([
                'borg/compress.c',
                'borg/crypto.c',
                'borg/chunker.c', 'borg/_chunker.c',
                'borg/hashindex.c', 'borg/_hashindex.c',
                'borg/platform_linux.c',
                'borg/platform_freebsd.c',
                'borg/platform_darwin.c',
            ])
            super().make_distribution()

except ImportError:
    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    compress_source = compress_source.replace('.pyx', '.c')
    crypto_source = crypto_source.replace('.pyx', '.c')
    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    platform_linux_source = platform_linux_source.replace('.pyx', '.c')
    platform_freebsd_source = platform_freebsd_source.replace('.pyx', '.c')
    platform_darwin_source = platform_darwin_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    if not on_rtd and not all(os.path.exists(path) for path in [
        compress_source, crypto_source, chunker_source, hashindex_source,
        platform_linux_source, platform_freebsd_source]):
        raise ImportError('The GIT version of Borg needs Cython. Install Cython or use a released version.')


def detect_openssl(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'openssl', 'evp.h')
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                if 'PKCS5_PBKDF2_HMAC(' in fd.read():
                    return prefix


def detect_lz4(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'lz4.h')
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                if 'LZ4_decompress_safe' in fd.read():
                    return prefix


include_dirs = []
library_dirs = []

possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl', '/usr/local/borg', '/opt/local']
if os.environ.get('BORG_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_OPENSSL_PREFIX'))
ssl_prefix = detect_openssl(possible_openssl_prefixes)
if not ssl_prefix:
    raise Exception('Unable to find OpenSSL >= 1.0 headers. (Looked here: {})'.format(', '.join(possible_openssl_prefixes)))
include_dirs.append(os.path.join(ssl_prefix, 'include'))
library_dirs.append(os.path.join(ssl_prefix, 'lib'))


possible_lz4_prefixes = ['/usr', '/usr/local', '/usr/local/opt/lz4', '/usr/local/lz4', '/usr/local/borg', '/opt/local']
if os.environ.get('BORG_LZ4_PREFIX'):
    possible_lz4_prefixes.insert(0, os.environ.get('BORG_LZ4_PREFIX'))
lz4_prefix = detect_lz4(possible_lz4_prefixes)
if lz4_prefix:
    include_dirs.append(os.path.join(lz4_prefix, 'include'))
    library_dirs.append(os.path.join(lz4_prefix, 'lib'))
elif not on_rtd:
    raise Exception('Unable to find LZ4 headers. (Looked here: {})'.format(', '.join(possible_lz4_prefixes)))


with open('README.rst', 'r') as fd:
    long_description = fd.read()

class build_usage(Command):
    description = "generate usage for each command"

    user_options = [
        ('output=', 'O', 'output directory'),
    ]
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print('generating usage docs')
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver
        parser = Archiver().build_parser(prog='borg')
        choices = {}
        for action in parser._actions:
            if action.choices is not None:
                choices.update(action.choices)
        print('found commands: %s' % list(choices.keys()))
        if not os.path.exists('docs/usage'):
            os.mkdir('docs/usage')
        for command, parser in choices.items():
            print('generating help for %s' % command)
            with open('docs/usage/%s.rst' % command, 'w') as doc:
                if command == 'help':
                    for topic in Archiver.helptext:
                        params = {"topic": topic,
                                  "underline": '~' * len('borg help ' + topic)}
                        doc.write(".. _borg_{topic}:\n\n".format(**params))
                        doc.write("borg help {topic}\n{underline}\n::\n\n".format(**params))
                        doc.write(Archiver.helptext[topic])
                else:
                    params = {"command": command,
                              "underline": '-' * len('borg ' + command),
                              "description": parser.description,
                    }
                    doc.write(".. _borg_{command}:\n\n".format(**params))
                    doc.write("borg {command}\n{underline}\n\n{description}\n\nSynopsis\n~~~~~~~~\n\n::\n\n".format(**params))
                    doc.write(re.sub("^", "    ", parser.format_usage().replace('usage: ', '', 1), flags=re.M))
                    formatter = parser._get_formatter()
                    # positionals, optionals and user-defined groups
                    for action_group in parser._action_groups:
                        if len(action_group._group_actions) > 0:
                            formatter.start_section("XXX%s\nXXX%s\nXXX\nXXX:" % (action_group.title, '~' * len(action_group.title)))
                            formatter.add_text("\n")
                            formatter.add_text(action_group.description)
                            formatter.add_arguments(action_group._group_actions)
                            formatter.end_section()
                    doc.write("\n" + re.sub("^(?!XXX)", "    ", formatter.format_help(), flags=re.M).replace('XXX', ''))
                    doc.write("\nDescription\n~~~~~~~~~~~\n")
                    doc.write(parser.epilog)
                    if hasattr(parser, 'examples'):
                        doc.write("\nExamples\n~~~~~~~~\n")
                        doc.write(parser.examples)


class build_api(Command):
    description = "generate a basic api.rst file based on the modules available"

    user_options = [
        ('output=', 'O', 'output directory'),
    ]
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print("auto-generating API documentation")
        with open("docs/api.rst", "w") as doc:
            doc.write("""
API Documentation
=================
""")
            for mod in glob('borg/*.py') + glob('borg/*.pyx'):
                print("examining module %s" % mod)
                mod = mod.replace('.pyx', '').replace('.py', '').replace('/', '.')
                if "._" not in mod:
                    doc.write("""
.. automodule:: %s
    :members:
    :undoc-members:
""" % mod)


cmdclass = {
    'build_ext': build_ext,
    'build_api': build_api,
    'build_usage': build_usage,
    'sdist': Sdist
}

ext_modules = []
if not on_rtd:
    ext_modules += [
    Extension('borg.compress', [compress_source], libraries=['lz4'], include_dirs=include_dirs, library_dirs=library_dirs),
    Extension('borg.crypto', [crypto_source], libraries=['crypto'], include_dirs=include_dirs, library_dirs=library_dirs),
    Extension('borg.chunker', [chunker_source]),
    Extension('borg.hashindex', [hashindex_source])
]
    if sys.platform.startswith('linux'):
        ext_modules.append(Extension('borg.platform_linux', [platform_linux_source], libraries=['acl']))
    elif sys.platform.startswith('freebsd'):
        ext_modules.append(Extension('borg.platform_freebsd', [platform_freebsd_source]))
    elif sys.platform == 'darwin':
        ext_modules.append(Extension('borg.platform_darwin', [platform_darwin_source]))

setup(
    name='borgbackup',
    use_scm_version={
        'write_to': 'borg/_version.py',
    },
    author='The Borg Collective (see AUTHORS file)',
    author_email='borgbackup@librelist.com',
    url='https://borgbackup.readthedocs.org/',
    description='Deduplicated, encrypted, authenticated and compressed backups',
    long_description=long_description,
    license='BSD',
    platforms=['Linux', 'MacOS X', 'FreeBSD', 'OpenBSD', 'NetBSD', ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Operating System :: POSIX :: BSD :: OpenBSD',
        'Operating System :: POSIX :: BSD :: NetBSD',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=['borg', 'borg.testsuite', 'borg.support', ],
    entry_points={
        'console_scripts': [
            'borg = borg.archiver:main',
        ]
    },
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    setup_requires=['setuptools_scm>=1.7'],
    install_requires=install_requires,
)
