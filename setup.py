# -*- encoding: utf-8 *-*
import os
import re
import sys
from glob import glob

from distutils.command.build import build
from distutils.core import Command

import textwrap

min_python = (3, 4)
my_python = sys.version_info

if my_python < min_python:
    print("Borg requires Python %d.%d or later" % min_python)
    sys.exit(1)

# Are we building on ReadTheDocs?
on_rtd = os.environ.get('READTHEDOCS')

# msgpack pure python data corruption was fixed in 0.4.6.
# Also, we might use some rather recent API features.
install_requires = ['msgpack-python>=0.4.6', ]

# note for package maintainers: if you package borgbackup for distribution,
# please add llfuse as a *requirement* on all platforms that have a working
# llfuse package. "borg mount" needs llfuse to work.
# if you do not have llfuse, do not require it, most of borgbackup will work.
extras_require = {
    # llfuse 0.40 (tested, proven, ok), needs FUSE version >= 2.8.0
    # llfuse 0.41 (tested shortly, looks ok), needs FUSE version >= 2.8.0
    # llfuse 0.41.1 (tested shortly, looks ok), needs FUSE version >= 2.8.0
    # llfuse 0.42 (tested shortly, looks ok), needs FUSE version >= 2.8.0
    # llfuse 1.0 (tested shortly, looks ok), needs FUSE version >= 2.8.0
    # llfuse 1.1.1 (tested shortly, looks ok), needs FUSE version >= 2.8.0
    # llfuse 2.0 will break API
    'fuse': ['llfuse<2.0', ],
}

if sys.platform.startswith('freebsd'):
    # llfuse was frequently broken / did not build on freebsd
    # llfuse 0.41.1, 1.1 are ok
    extras_require['fuse'] = ['llfuse <2.0, !=0.42.*, !=0.43, !=1.0', ]

from setuptools import setup, find_packages, Extension
from setuptools.command.sdist import sdist

compress_source = 'src/borg/compress.pyx'
crypto_source = 'src/borg/crypto.pyx'
chunker_source = 'src/borg/chunker.pyx'
hashindex_source = 'src/borg/hashindex.pyx'
item_source = 'src/borg/item.pyx'
crc32_source = 'src/borg/crc32.pyx'
platform_posix_source = 'src/borg/platform/posix.pyx'
platform_linux_source = 'src/borg/platform/linux.pyx'
platform_darwin_source = 'src/borg/platform/darwin.pyx'
platform_freebsd_source = 'src/borg/platform/freebsd.pyx'

cython_sources = [
    compress_source,
    crypto_source,
    chunker_source,
    hashindex_source,
    item_source,
    crc32_source,

    platform_posix_source,
    platform_linux_source,
    platform_freebsd_source,
    platform_darwin_source,
]

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in cython_sources:
                cython_compiler.compile(src, cython_compiler.default_options)
            super().__init__(*args, **kwargs)

        def make_distribution(self):
            self.filelist.extend([
                'src/borg/compress.c',
                'src/borg/crypto.c',
                'src/borg/chunker.c', 'src/borg/_chunker.c',
                'src/borg/hashindex.c', 'src/borg/_hashindex.c',
                'src/borg/item.c',
                'src/borg/crc32.c',
                'src/borg/_crc32/crc32.c', 'src/borg/_crc32/clmul.c', 'src/borg/_crc32/slice_by_8.c',
                'src/borg/platform/posix.c',
                'src/borg/platform/linux.c',
                'src/borg/platform/freebsd.c',
                'src/borg/platform/darwin.c',
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
    item_source = item_source.replace('.pyx', '.c')
    crc32_source = crc32_source.replace('.pyx', '.c')
    platform_posix_source = platform_posix_source.replace('.pyx', '.c')
    platform_linux_source = platform_linux_source.replace('.pyx', '.c')
    platform_freebsd_source = platform_freebsd_source.replace('.pyx', '.c')
    platform_darwin_source = platform_darwin_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    if not on_rtd and not all(os.path.exists(path) for path in [
        compress_source, crypto_source, chunker_source, hashindex_source, item_source, crc32_source,
        platform_posix_source, platform_linux_source, platform_freebsd_source, platform_darwin_source]):
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


def detect_libb2(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'blake2.h')
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                if 'blake2b_init' in fd.read():
                    return prefix


include_dirs = []
library_dirs = []
define_macros = []
crypto_libraries = ['crypto']

possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl',
                             '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_OPENSSL_PREFIX'))
ssl_prefix = detect_openssl(possible_openssl_prefixes)
if not ssl_prefix:
    raise Exception('Unable to find OpenSSL >= 1.0 headers. (Looked here: {})'.format(', '.join(possible_openssl_prefixes)))
include_dirs.append(os.path.join(ssl_prefix, 'include'))
library_dirs.append(os.path.join(ssl_prefix, 'lib'))


possible_lz4_prefixes = ['/usr', '/usr/local', '/usr/local/opt/lz4', '/usr/local/lz4',
                         '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LZ4_PREFIX'):
    possible_lz4_prefixes.insert(0, os.environ.get('BORG_LZ4_PREFIX'))
lz4_prefix = detect_lz4(possible_lz4_prefixes)
if lz4_prefix:
    include_dirs.append(os.path.join(lz4_prefix, 'include'))
    library_dirs.append(os.path.join(lz4_prefix, 'lib'))
elif not on_rtd:
    raise Exception('Unable to find LZ4 headers. (Looked here: {})'.format(', '.join(possible_lz4_prefixes)))

possible_libb2_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libb2', '/usr/local/libb2',
                           '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBB2_PREFIX'):
    possible_libb2_prefixes.insert(0, os.environ.get('BORG_LIBB2_PREFIX'))
libb2_prefix = detect_libb2(possible_libb2_prefixes)
if libb2_prefix:
    print('Detected and preferring libb2 over bundled BLAKE2')
    include_dirs.append(os.path.join(libb2_prefix, 'include'))
    library_dirs.append(os.path.join(libb2_prefix, 'lib'))
    crypto_libraries.append('b2')
    define_macros.append(('BORG_USE_LIBB2', 'YES'))


with open('README.rst', 'r') as fd:
    long_description = fd.read()
    # remove badges
    long_description = re.compile(r'^\.\. start-badges.*^\.\. end-badges', re.M | re.S).sub('', long_description)
    # remove |substitutions|
    long_description = re.compile(r'\|screencast\|').sub('', long_description)
    # remove unknown directives
    long_description = re.compile(r'^\.\. highlight:: \w+$', re.M).sub('', long_description)


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
        if not os.path.exists('docs/usage'):
            os.mkdir('docs/usage')
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver
        parser = Archiver(prog='borg').parser

        self.generate_level("", parser, Archiver)

    def generate_level(self, prefix, parser, Archiver):
        is_subcommand = False
        choices = {}
        for action in parser._actions:
            if action.choices is not None and 'SubParsersAction' in str(action.__class__):
                is_subcommand = True
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if prefix and not choices:
            return
        print('found commands: %s' % list(choices.keys()))

        for command, parser in sorted(choices.items()):
            if command.startswith('debug'):
                print('skipping', command)
                continue
            print('generating help for %s' % command)

            if self.generate_level(command + " ", parser, Archiver):
                continue

            with open('docs/usage/%s.rst.inc' % command.replace(" ", "_"), 'w') as doc:
                doc.write(".. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!\n\n")
                if command == 'help':
                    for topic in Archiver.helptext:
                        params = {"topic": topic,
                                  "underline": '~' * len('borg help ' + topic)}
                        doc.write(".. _borg_{topic}:\n\n".format(**params))
                        doc.write("borg help {topic}\n{underline}\n\n".format(**params))
                        doc.write(Archiver.helptext[topic])
                else:
                    params = {"command": command,
                              "command_": command.replace(' ', '_'),
                              "underline": '-' * len('borg ' + command)}
                    doc.write(".. _borg_{command_}:\n\n".format(**params))
                    doc.write("borg {command}\n{underline}\n::\n\n    borg {command}".format(**params))
                    self.write_usage(parser, doc)
                    epilog = parser.epilog
                    parser.epilog = None
                    self.write_options(parser, doc)
                    doc.write("\n\nDescription\n~~~~~~~~~~~\n")
                    doc.write(epilog)

        if 'create' in choices:
            common_options = [group for group in choices['create']._action_groups if group.title == 'Common options'][0]
            with open('docs/usage/common-options.rst.inc', 'w') as doc:
                self.write_options_group(common_options, doc, False)

        return is_subcommand

    def write_usage(self, parser, fp):
        if any(len(o.option_strings) for o in parser._actions):
            fp.write(' <options>')
        for option in parser._actions:
            if option.option_strings:
                continue
            fp.write(' ' + option.metavar)

    def write_options(self, parser, fp):
        for group in parser._action_groups:
            if group.title == 'Common options':
                fp.write('\n\n`Common options`_\n')
                fp.write('    |')
            else:
                self.write_options_group(group, fp)

    def write_options_group(self, group, fp, with_title=True):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        def get_help(option):
            text = textwrap.dedent((option.help or '') % option.__dict__)
            return '\n'.join('| ' + line for line in text.splitlines())

        def shipout(text):
            fp.write(textwrap.indent('\n'.join(text), ' ' * 4))

        if not group._group_actions:
            return

        if with_title:
            fp.write('\n\n')
            fp.write(group.title + '\n')
        text = []

        if is_positional_group(group):
            for option in group._group_actions:
                text.append(option.metavar)
                text.append(textwrap.indent(option.help or '', ' ' * 4))
            shipout(text)
            return

        options = []
        for option in group._group_actions:
            if option.metavar:
                option_fmt = '``%%s %s``' % option.metavar
            else:
                option_fmt = '``%s``'
            option_str = ', '.join(option_fmt % s for s in option.option_strings)
            options.append((option_str, option))
        for option_str, option in options:
            help = textwrap.indent(get_help(option), ' ' * 4)
            text.append(option_str)
            text.append(help)
        shipout(text)


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
            for mod in glob('src/borg/*.py') + glob('src/borg/*.pyx'):
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
    Extension('borg.compress', [compress_source], libraries=['lz4'], include_dirs=include_dirs, library_dirs=library_dirs, define_macros=define_macros),
    Extension('borg.crypto', [crypto_source], libraries=crypto_libraries, include_dirs=include_dirs, library_dirs=library_dirs, define_macros=define_macros),
    Extension('borg.chunker', [chunker_source]),
    Extension('borg.hashindex', [hashindex_source]),
    Extension('borg.item', [item_source]),
    Extension('borg.crc32', [crc32_source]),
]
    if not sys.platform.startswith(('win32', )):
        ext_modules.append(Extension('borg.platform.posix', [platform_posix_source]))

    if sys.platform == 'linux':
        ext_modules.append(Extension('borg.platform.linux', [platform_linux_source], libraries=['acl']))
    elif sys.platform.startswith('freebsd'):
        ext_modules.append(Extension('borg.platform.freebsd', [platform_freebsd_source]))
    elif sys.platform == 'darwin':
        ext_modules.append(Extension('borg.platform.darwin', [platform_darwin_source]))

setup(
    name='borgbackup',
    use_scm_version={
        'write_to': 'src/borg/_version.py',
    },
    author='The Borg Collective (see AUTHORS file)',
    author_email='borgbackup@python.org',
    url='https://borgbackup.readthedocs.io/',
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
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'borg = borg.archiver:main',
            'borgfs = borg.archiver:main',
        ]
    },
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    setup_requires=['setuptools_scm>=1.7'],
    install_requires=install_requires,
    extras_require=extras_require,
)
