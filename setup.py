# -*- encoding: utf-8 *-*
import os
import re
import sys
from glob import glob

from distutils.command.build import build
from distutils.core import Command
from distutils.errors import DistutilsOptionError
from distutils import log
from setuptools.command.build_py import build_py

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
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_LZ4_PREFIX'))
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
        if 'BORG_CYTHON_DISABLE' not in os.environ:
            os.environ['BORG_CYTHON_DISABLE'] = self.__class__.__name__
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
            if command is 'help':
                continue
            with open('docs/usage/%s.rst.inc' % command, 'w') as doc:
                print('generating help for %s' % command)
                params = {"command": command,
                          "underline": '-' * len('borg ' + command)}
                doc.write(".. _borg_{command}:\n\n".format(**params))
                doc.write("borg {command}\n{underline}\n::\n\n".format(**params))
                epilog = parser.epilog
                parser.epilog = None
                doc.write(re.sub("^", "    ", parser.format_help(), flags=re.M))
                doc.write("\nDescription\n~~~~~~~~~~~\n")
                doc.write(epilog)
        # return to regular Cython configuration, if we changed it
        if os.environ.get('BORG_CYTHON_DISABLE') == self.__class__.__name__:
            del os.environ['BORG_CYTHON_DISABLE']


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
Borg Backup API documentation
=============================
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

# (function, predicate), see http://docs.python.org/2/distutils/apiref.html#distutils.cmd.Command.sub_commands
# seems like this doesn't work on RTD, see below for build_py hack.
build.sub_commands.append(('build_api', None))
build.sub_commands.append(('build_usage', None))


class build_py_custom(build_py):
    """override build_py to also build our stuff

    it is unclear why this is necessary, but in some environments
    (Readthedocs.org, specifically), the above
    ``build.sub_commands.append()`` doesn't seem to have an effect:
    our custom build commands seem to be ignored when running
    ``setup.py install``.

    This class overrides the ``build_py`` target by forcing it to run
    our custom steps as well.

    See also the `bug report on RTD
    <https://github.com/rtfd/readthedocs.org/issues/1740>`_.
    """
    def run(self):
        super().run()
        self.announce('calling custom build steps', level=log.INFO)
        self.run_command('build_ext')
        self.run_command('build_api')
        self.run_command('build_usage')


cmdclass = {
    'build_ext': build_ext,
    'build_api': build_api,
    'build_usage': build_usage,
    'build_py': build_py_custom,
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
