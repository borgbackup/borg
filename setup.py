# -*- encoding: utf-8 *-*
import os
import io
import re
import sys
import textwrap
from collections import OrderedDict
from datetime import datetime
from glob import glob

import setup_lz4
import setup_zstd
import setup_b2
import setup_xxhash

# True: use the shared liblz4 (>= 1.7.0 / r129) from the system, False: use the bundled lz4 code
prefer_system_liblz4 = True

# True: use the shared libzstd (>= 1.3.0) from the system, False: use the bundled zstd code
prefer_system_libzstd = True

# True: use the shared libb2 from the system, False: use the bundled blake2 code
prefer_system_libb2 = True

# True: use the shared libxxhash (>= 0.6.5 [>= 0.7.2 on ARM]) from the system, False: use the bundled xxhash code
prefer_system_libxxhash = True

# prefer_system_msgpack is another option, but you need to set it in src/borg/helpers.py.

min_python = (3, 5)
my_python = sys.version_info

if my_python < min_python:
    print("Borg requires Python %d.%d or later" % min_python)
    sys.exit(1)

# Are we building on ReadTheDocs?
on_rtd = os.environ.get('READTHEDOCS')

install_requires = [
    'packaging',
]

# note for package maintainers: if you package borgbackup for distribution,
# please add llfuse as a *requirement* on all platforms that have a working
# llfuse package. "borg mount" needs llfuse to work.
# if you do not have llfuse, do not require it, most of borgbackup will work.
extras_require = {
    'fuse': [
        # 1.3.8 is the fixed version that works on py39 AND freebsd.
        # if you cythonize yourself and make sure llfuse works for your
        # OS and python version, you can use other versions than 1.3.8, too.
        'llfuse >=1.3.4',  # should nowadays pull 1.3.8 or better
    ],
}

from setuptools import setup, find_packages, Extension, Command
from setuptools.command.sdist import sdist

compress_source = 'src/borg/compress.pyx'
crypto_ll_source = 'src/borg/crypto/low_level.pyx'
chunker_source = 'src/borg/chunker.pyx'
hashindex_source = 'src/borg/hashindex.pyx'
item_source = 'src/borg/item.pyx'
checksums_source = 'src/borg/algorithms/checksums.pyx'
platform_posix_source = 'src/borg/platform/posix.pyx'
platform_linux_source = 'src/borg/platform/linux.pyx'
platform_syncfilerange_source = 'src/borg/platform/syncfilerange.pyx'
platform_darwin_source = 'src/borg/platform/darwin.pyx'
platform_freebsd_source = 'src/borg/platform/freebsd.pyx'
msgpack_packer_source = 'src/borg/algorithms/msgpack/_packer.pyx'
msgpack_unpacker_source = 'src/borg/algorithms/msgpack/_unpacker.pyx'

cython_c_sources = [
    # these .pyx will get compiled to .c
    compress_source,
    crypto_ll_source,
    chunker_source,
    hashindex_source,
    item_source,
    checksums_source,
    platform_posix_source,
    platform_linux_source,
    platform_syncfilerange_source,
    platform_freebsd_source,
    platform_darwin_source,
]

cython_cpp_sources = [
    # these .pyx will get compiled to .cpp
    msgpack_packer_source,
    msgpack_unpacker_source,
]

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in cython_c_sources:
                cython_compiler.compile(src, cython_compiler.default_options)
            for src in cython_cpp_sources:
                cython_compiler.compile(src, cplus=True)
            super().__init__(*args, **kwargs)

        def make_distribution(self):
            self.filelist.extend([
                'src/borg/compress.c',
                'src/borg/crypto/low_level.c',
                'src/borg/chunker.c', 'src/borg/_chunker.c',
                'src/borg/hashindex.c', 'src/borg/_hashindex.c',
                'src/borg/cache_sync/cache_sync.c', 'src/borg/cache_sync/sysdep.h', 'src/borg/cache_sync/unpack.h',
                'src/borg/cache_sync/unpack_define.h', 'src/borg/cache_sync/unpack_template.h',
                'src/borg/item.c',
                'src/borg/algorithms/checksums.c',
                'src/borg/algorithms/crc32_dispatch.c', 'src/borg/algorithms/crc32_clmul.c', 'src/borg/algorithms/crc32_slice_by_8.c',
                'src/borg/algorithms/xxh64/xxhash.h', 'src/borg/algorithms/xxh64/xxhash.c',
                'src/borg/platform/posix.c',
                'src/borg/platform/linux.c',
                'src/borg/platform/syncfilerange.c',
                'src/borg/platform/freebsd.c',
                'src/borg/platform/darwin.c',
                'src/borg/algorithms/msgpack/_packer.cpp',
                'src/borg/algorithms/msgpack/_unpacker.cpp',
            ])
            super().make_distribution()

except ImportError:
    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception('Cython is required to run sdist')

    compress_source = compress_source.replace('.pyx', '.c')
    crypto_ll_source = crypto_ll_source.replace('.pyx', '.c')
    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    item_source = item_source.replace('.pyx', '.c')
    checksums_source = checksums_source.replace('.pyx', '.c')
    platform_posix_source = platform_posix_source.replace('.pyx', '.c')
    platform_linux_source = platform_linux_source.replace('.pyx', '.c')
    platform_syncfilerange_source = platform_syncfilerange_source.replace('.pyx', '.c')
    platform_freebsd_source = platform_freebsd_source.replace('.pyx', '.c')
    platform_darwin_source = platform_darwin_source.replace('.pyx', '.c')

    msgpack_packer_source = msgpack_packer_source.replace('.pyx', '.cpp')
    msgpack_unpacker_source = msgpack_unpacker_source.replace('.pyx', '.cpp')

    from setuptools.command.build_ext import build_ext
    if not on_rtd and not all(os.path.exists(path) for path in [
        compress_source, crypto_ll_source, chunker_source, hashindex_source, item_source, checksums_source,
        platform_posix_source, platform_linux_source, platform_syncfilerange_source, platform_freebsd_source, platform_darwin_source,
        msgpack_packer_source, msgpack_unpacker_source]):
        raise ImportError('The GIT version of Borg needs Cython. Install Cython or use a released version.')


def detect_openssl(prefixes):
    for prefix in prefixes:
        filename = os.path.join(prefix, 'include', 'openssl', 'evp.h')
        if os.path.exists(filename):
            with open(filename, 'rb') as fd:
                if b'PKCS5_PBKDF2_HMAC(' in fd.read():
                    return prefix


include_dirs = []
library_dirs = []
define_macros = []

possible_openssl_prefixes = ['/usr', '/usr/local', '/usr/local/opt/openssl', '/usr/local/ssl', '/usr/local/openssl',
                             '/usr/local/borg', '/opt/local', '/opt/pkg', '/opt/homebrew/opt/openssl@1.1', ]
if os.environ.get('BORG_OPENSSL_PREFIX'):
    possible_openssl_prefixes.insert(0, os.environ.get('BORG_OPENSSL_PREFIX'))
ssl_prefix = detect_openssl(possible_openssl_prefixes)
if not ssl_prefix:
    raise Exception('Unable to find OpenSSL >= 1.0 headers. (Looked here: {})'.format(', '.join(possible_openssl_prefixes)))
include_dirs.append(os.path.join(ssl_prefix, 'include'))
library_dirs.append(os.path.join(ssl_prefix, 'lib'))


possible_liblz4_prefixes = ['/usr', '/usr/local', '/usr/local/opt/lz4', '/usr/local/lz4',
                         '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBLZ4_PREFIX'):
    possible_liblz4_prefixes.insert(0, os.environ.get('BORG_LIBLZ4_PREFIX'))
liblz4_prefix = setup_lz4.lz4_system_prefix(possible_liblz4_prefixes)
if prefer_system_liblz4 and liblz4_prefix:
    print('Detected and preferring liblz4 over bundled LZ4')
    define_macros.append(('BORG_USE_LIBLZ4', 'YES'))
    liblz4_system = True
else:
    liblz4_system = False

possible_libb2_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libb2', '/usr/local/libb2',
                           '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBB2_PREFIX'):
    possible_libb2_prefixes.insert(0, os.environ.get('BORG_LIBB2_PREFIX'))
libb2_prefix = setup_b2.b2_system_prefix(possible_libb2_prefixes)
if prefer_system_libb2 and libb2_prefix:
    print('Detected and preferring libb2 over bundled BLAKE2')
    define_macros.append(('BORG_USE_LIBB2', 'YES'))
    libb2_system = True
else:
    libb2_system = False

possible_libzstd_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libzstd', '/usr/local/libzstd',
                             '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBZSTD_PREFIX'):
    possible_libzstd_prefixes.insert(0, os.environ.get('BORG_LIBZSTD_PREFIX'))
libzstd_prefix = setup_zstd.zstd_system_prefix(possible_libzstd_prefixes)
if prefer_system_libzstd and libzstd_prefix:
    print('Detected and preferring libzstd over bundled ZSTD')
    define_macros.append(('BORG_USE_LIBZSTD', 'YES'))
    libzstd_system = True
else:
    libzstd_system = False

possible_libxxhash_prefixes = ['/usr', '/usr/local', '/usr/local/opt/libxxhash', '/usr/local/libxxhash',
                           '/usr/local/borg', '/opt/local', '/opt/pkg', ]
if os.environ.get('BORG_LIBXXHASH_PREFIX'):
    possible_libxxhash_prefixes.insert(0, os.environ.get('BORG_LIBXXHASH_PREFIX'))
libxxhash_prefix = setup_xxhash.xxhash_system_prefix(possible_libxxhash_prefixes)
if prefer_system_libxxhash and libxxhash_prefix:
    print('Detected and preferring libxxhash over bundled XXHASH')
    define_macros.append(('BORG_USE_LIBXXHASH', 'YES'))
    libxxhash_system = True
else:
    libxxhash_system = False


with open('README.rst', 'r') as fd:
    long_description = fd.read()
    # remove header, but have one \n before first headline
    start = long_description.find('What is BorgBackup?')
    assert start >= 0
    long_description = '\n' + long_description[start:]
    # remove badges
    long_description = re.compile(r'^\.\. start-badges.*^\.\. end-badges', re.M | re.S).sub('', long_description)
    # remove unknown directives
    long_description = re.compile(r'^\.\. highlight:: \w+$', re.M).sub('', long_description)


def format_metavar(option):
    if option.nargs in ('*', '...'):
        return '[%s...]' % option.metavar
    elif option.nargs == '?':
        return '[%s]' % option.metavar
    elif option.nargs is None:
        return option.metavar
    else:
        raise ValueError('Can\'t format metavar %s, unknown nargs %s!' % (option.metavar, option.nargs))


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
        import borg
        borg.doc_mode = 'build_man'
        if not os.path.exists('docs/usage'):
            os.mkdir('docs/usage')
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver
        parser = Archiver(prog='borg').build_parser()
        # borgfs has a separate man page to satisfy debian's "every program from a package
        # must have a man page" requirement, but it doesn't need a separate HTML docs page
        #borgfs_parser = Archiver(prog='borgfs').build_parser()

        self.generate_level("", parser, Archiver)

    def generate_level(self, prefix, parser, Archiver, extra_choices=None):
        is_subcommand = False
        choices = {}
        for action in parser._actions:
            if action.choices is not None and 'SubParsersAction' in str(action.__class__):
                is_subcommand = True
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
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
                    doc.write("borg {command}\n{underline}\n.. code-block:: none\n\n    borg [common options] {command}".format(**params))
                    self.write_usage(parser, doc)
                    epilog = parser.epilog
                    parser.epilog = None
                    self.write_options(parser, doc)
                    doc.write("\n\nDescription\n~~~~~~~~~~~\n")
                    doc.write(epilog)

        if 'create' in choices:
            common_options = [group for group in choices['create']._action_groups if group.title == 'Common options'][0]
            with open('docs/usage/common-options.rst.inc', 'w') as doc:
                self.write_options_group(common_options, doc, False, base_indent=0)

        return is_subcommand

    def write_usage(self, parser, fp):
        if any(len(o.option_strings) for o in parser._actions):
            fp.write(' [options]')
        for option in parser._actions:
            if option.option_strings:
                continue
            fp.write(' ' + format_metavar(option))
        fp.write('\n\n')

    def write_options(self, parser, fp):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        # HTML output:
        # A table using some column-spans

        def html_write(s):
            for line in s.splitlines():
                fp.write('    ' + line + '\n')

        rows = []
        for group in parser._action_groups:
            if group.title == 'Common options':
                # (no of columns used, columns, ...)
                rows.append((1, '.. class:: borg-common-opt-ref\n\n:ref:`common_options`'))
            else:
                if not group._group_actions:
                    continue
                group_header = '**%s**' % group.title
                if group.description:
                    group_header += ' — ' + group.description
                rows.append((1, group_header))
                if is_positional_group(group):
                    for option in group._group_actions:
                        rows.append((3, '', '``%s``' % option.metavar, option.help or ''))
                else:
                    for option in group._group_actions:
                        if option.metavar:
                            option_fmt = '``%s ' + option.metavar + '``'
                        else:
                            option_fmt = '``%s``'
                        option_str = ', '.join(option_fmt % s for s in option.option_strings)
                        option_desc = textwrap.dedent((option.help or '') % option.__dict__)
                        rows.append((3, '', option_str, option_desc))

        fp.write('.. only:: html\n\n')
        table = io.StringIO()
        table.write('.. class:: borg-options-table\n\n')
        self.rows_to_table(rows, table.write)
        fp.write(textwrap.indent(table.getvalue(), ' ' * 4))

        # LaTeX output:
        # Regular rST option lists (irregular column widths)
        latex_options = io.StringIO()
        for group in parser._action_groups:
            if group.title == 'Common options':
                latex_options.write('\n\n:ref:`common_options`\n')
                latex_options.write('    |')
            else:
                self.write_options_group(group, latex_options)
        fp.write('\n.. only:: latex\n\n')
        fp.write(textwrap.indent(latex_options.getvalue(), ' ' * 4))

    def rows_to_table(self, rows, write):
        def write_row_separator():
            write('+')
            for column_width in column_widths:
                write('-' * (column_width + 1))
                write('+')
            write('\n')

        # Find column count and width
        column_count = max(columns for columns, *_ in rows)
        column_widths = [0] * column_count
        for columns, *cells in rows:
            for i in range(columns):
                # "+ 1" because we want a space between the cell contents and the delimiting "|" in the output
                column_widths[i] = max(column_widths[i], len(cells[i]) + 1)

        for columns, *original_cells in rows:
            write_row_separator()
            # If a cell contains newlines, then the row must be split up in individual rows
            # where each cell contains no newline.
            rowspanning_cells = []
            original_cells = list(original_cells)
            while any('\n' in cell for cell in original_cells):
                cell_bloc = []
                for i, cell in enumerate(original_cells):
                    pre, _, original_cells[i] = cell.partition('\n')
                    cell_bloc.append(pre)
                rowspanning_cells.append(cell_bloc)
            rowspanning_cells.append(original_cells)
            for cells in rowspanning_cells:
                for i, column_width in enumerate(column_widths):
                    if i < columns:
                        write('| ')
                        write(cells[i].ljust(column_width))
                    else:
                        write('  ')
                        write(''.ljust(column_width))
                write('|\n')

        write_row_separator()
        # This bit of JavaScript kills the <colgroup> that is invariably inserted by docutils,
        # but does absolutely no good here. It sets bogus column widths which cannot be overridden
        # with CSS alone.
        # Since this is HTML-only output, it would be possible to just generate a <table> directly,
        # but then we'd lose rST formatting.
        write(textwrap.dedent("""
        .. raw:: html

            <script type='text/javascript'>
            $(document).ready(function () {
                $('.borg-options-table colgroup').remove();
            })
            </script>
        """))

    def write_options_group(self, group, fp, with_title=True, base_indent=4):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        indent = ' ' * base_indent

        if is_positional_group(group):
            for option in group._group_actions:
                fp.write(option.metavar + '\n')
                fp.write(textwrap.indent(option.help or '', ' ' * base_indent) + '\n')
            return

        if not group._group_actions:
            return

        if with_title:
            fp.write('\n\n')
            fp.write(group.title + '\n')

        opts = OrderedDict()

        for option in group._group_actions:
            if option.metavar:
                option_fmt = '%s ' + option.metavar
            else:
                option_fmt = '%s'
            option_str = ', '.join(option_fmt % s for s in option.option_strings)
            option_desc = textwrap.dedent((option.help or '') % option.__dict__)
            opts[option_str] = textwrap.indent(option_desc, ' ' * 4)

        padding = len(max(opts)) + 1

        for option, desc in opts.items():
            fp.write(indent + option.ljust(padding) + desc + '\n')


class build_man(Command):
    description = 'build man pages'

    user_options = []

    see_also = {
        'create': ('delete', 'prune', 'check', 'patterns', 'placeholders', 'compression'),
        'recreate': ('patterns', 'placeholders', 'compression'),
        'list': ('info', 'diff', 'prune', 'patterns'),
        'info': ('list', 'diff'),
        'init': ('create', 'delete', 'check', 'list', 'key-import', 'key-export', 'key-change-passphrase'),
        'key-import': ('key-export', ),
        'key-export': ('key-import', ),
        'mount': ('umount', 'extract'),  # Would be cooler if these two were on the same page
        'umount': ('mount', ),
        'extract': ('mount', ),
    }

    rst_prelude = textwrap.dedent("""
    .. role:: ref(title)

    .. |project_name| replace:: Borg

    """)

    usage_group = {
        'break-lock': 'lock',
        'with-lock': 'lock',

        'change-passphrase': 'key',
        'key_change-passphrase': 'key',
        'key_export': 'key',
        'key_import': 'key',
        'key_migrate-to-repokey': 'key',

        'export-tar': 'tar',

        'benchmark_crud': 'benchmark',

        'umount': 'mount',
    }

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print('building man pages (in docs/man)', file=sys.stderr)
        import borg
        borg.doc_mode = 'build_man'
        os.makedirs('docs/man', exist_ok=True)
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver
        parser = Archiver(prog='borg').build_parser()
        borgfs_parser = Archiver(prog='borgfs').build_parser()

        self.generate_level('', parser, Archiver, {'borgfs': borgfs_parser})
        self.build_topic_pages(Archiver)
        self.build_intro_page()

    def generate_level(self, prefix, parser, Archiver, extra_choices=None):
        is_subcommand = False
        choices = {}
        for action in parser._actions:
            if action.choices is not None and 'SubParsersAction' in str(action.__class__):
                is_subcommand = True
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            if command.startswith('debug') or command == 'help':
                continue

            if command == "borgfs":
                man_title = command
            else:
                man_title = 'borg-' + command.replace(' ', '-')
            print('building man page', man_title + '(1)', file=sys.stderr)

            is_intermediary = self.generate_level(command + ' ', parser, Archiver)

            doc, write = self.new_doc()
            self.write_man_header(write, man_title, parser.description)

            self.write_heading(write, 'SYNOPSIS')
            if is_intermediary:
                subparsers = [action for action in parser._actions if 'SubParsersAction' in str(action.__class__)][0]
                for subcommand in subparsers.choices:
                    write('| borg', '[common options]', command, subcommand, '...')
                    self.see_also.setdefault(command, []).append('%s-%s' % (command, subcommand))
            else:
                if command == "borgfs":
                    write(command, end='')
                else:
                    write('borg', '[common options]', command, end='')
                self.write_usage(write, parser)
            write('\n')

            description, _, notes = parser.epilog.partition('\n.. man NOTES')

            if description:
                self.write_heading(write, 'DESCRIPTION')
                write(description)

            if not is_intermediary:
                self.write_heading(write, 'OPTIONS')
                write('See `borg-common(1)` for common options of Borg commands.')
                write()
                self.write_options(write, parser)

                self.write_examples(write, command)

            if notes:
                self.write_heading(write, 'NOTES')
                write(notes)

            self.write_see_also(write, man_title)

            self.gen_man_page(man_title, doc.getvalue())

        # Generate the borg-common(1) man page with the common options.
        if 'create' in choices:
            doc, write = self.new_doc()
            man_title = 'borg-common'
            self.write_man_header(write, man_title, 'Common options of Borg commands')

            common_options = [group for group in choices['create']._action_groups if group.title == 'Common options'][0]

            self.write_heading(write, 'SYNOPSIS')
            self.write_options_group(write, common_options)
            self.write_see_also(write, man_title)
            self.gen_man_page(man_title, doc.getvalue())

        return is_subcommand

    def build_topic_pages(self, Archiver):
        for topic, text in Archiver.helptext.items():
            doc, write = self.new_doc()
            man_title = 'borg-' + topic
            print('building man page', man_title + '(1)', file=sys.stderr)

            self.write_man_header(write, man_title, 'Details regarding ' + topic)
            self.write_heading(write, 'DESCRIPTION')
            write(text)
            self.gen_man_page(man_title, doc.getvalue())

    def build_intro_page(self):
        print('building man page borg(1)', file=sys.stderr)
        with open('docs/man_intro.rst') as fd:
            man_intro = fd.read()
        self.gen_man_page('borg', self.rst_prelude + man_intro)

    def new_doc(self):
        doc = io.StringIO(self.rst_prelude)
        doc.read()
        write = self.printer(doc)
        return doc, write

    def printer(self, fd):
        def write(*args, **kwargs):
            print(*args, file=fd, **kwargs)
        return write

    def write_heading(self, write, header, char='-', double_sided=False):
        write()
        if double_sided:
            write(char * len(header))
        write(header)
        write(char * len(header))
        write()

    def write_man_header(self, write, title, description):
        self.write_heading(write, title, '=', double_sided=True)
        self.write_heading(write, description, double_sided=True)
        # man page metadata
        write(':Author: The Borg Collective')
        write(':Date:', datetime.utcnow().date().isoformat())
        write(':Manual section: 1')
        write(':Manual group: borg backup tool')
        write()

    def write_examples(self, write, command):
        command = command.replace(' ', '_')
        with open('docs/usage/%s.rst' % self.usage_group.get(command, command)) as fd:
            usage = fd.read()
            usage_include = '.. include:: %s.rst.inc' % command
            begin = usage.find(usage_include)
            end = usage.find('.. include', begin + 1)
            # If a command has a dedicated anchor, it will occur before the command's include.
            if 0 < usage.find('.. _', begin + 1) < end:
                end = usage.find('.. _', begin + 1)
            examples = usage[begin:end]
            examples = examples.replace(usage_include, '')
            examples = examples.replace('Examples\n~~~~~~~~', '')
            examples = examples.replace('Miscellaneous Help\n------------------', '')
            examples = examples.replace('``docs/misc/prune-example.txt``:', '``docs/misc/prune-example.txt``.')
            examples = examples.replace('.. highlight:: none\n', '')  # we don't support highlight
            examples = re.sub('^(~+)$', lambda matches: '+' * len(matches.group(0)), examples, flags=re.MULTILINE)
            examples = examples.strip()
        if examples:
            self.write_heading(write, 'EXAMPLES', '-')
            write(examples)

    def write_see_also(self, write, man_title):
        see_also = self.see_also.get(man_title.replace('borg-', ''), ())
        see_also = ['`borg-%s(1)`' % s for s in see_also]
        see_also.insert(0, '`borg-common(1)`')
        self.write_heading(write, 'SEE ALSO')
        write(', '.join(see_also))

    def gen_man_page(self, name, rst):
        from docutils.writers import manpage
        from docutils.core import publish_string
        from docutils.nodes import inline
        from docutils.parsers.rst import roles

        def issue(name, rawtext, text, lineno, inliner, options={}, content=[]):
            return [inline(rawtext, '#' + text)], []

        roles.register_local_role('issue', issue)
        # We give the source_path so that docutils can find relative includes
        # as-if the document where located in the docs/ directory.
        man_page = publish_string(source=rst, source_path='docs/%s.rst' % name, writer=manpage.Writer())
        with open('docs/man/%s.1' % name, 'wb') as fd:
            fd.write(man_page)

    def write_usage(self, write, parser):
        if any(len(o.option_strings) for o in parser._actions):
            write(' [options] ', end='')
        for option in parser._actions:
            if option.option_strings:
                continue
            write(format_metavar(option), end=' ')

    def write_options(self, write, parser):
        for group in parser._action_groups:
            if group.title == 'Common options' or not group._group_actions:
                continue
            title = 'arguments' if group.title == 'positional arguments' else group.title
            self.write_heading(write, title, '+')
            self.write_options_group(write, group)

    def write_options_group(self, write, group):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        if is_positional_group(group):
            for option in group._group_actions:
                write(option.metavar)
                write(textwrap.indent(option.help or '', ' ' * 4))
            return

        opts = OrderedDict()

        for option in group._group_actions:
            if option.metavar:
                option_fmt = '%s ' + option.metavar
            else:
                option_fmt = '%s'
            option_str = ', '.join(option_fmt % s for s in option.option_strings)
            option_desc = textwrap.dedent((option.help or '') % option.__dict__)
            opts[option_str] = textwrap.indent(option_desc, ' ' * 4)

        padding = len(max(opts)) + 1

        for option, desc in opts.items():
            write(option.ljust(padding), desc)


def rm(file):
    try:
        os.unlink(file)
        print('rm', file)
    except FileNotFoundError:
        pass


class Clean(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        for source in cython_c_sources:
            genc = source.replace('.pyx', '.c')
            rm(genc)
        for source in cython_cpp_sources:
            gencpp = source.replace('.pyx', '.cpp')
            rm(gencpp)
        for source in cython_c_sources + cython_cpp_sources:
            compiled_glob = source.replace('.pyx', '.cpython*')
            for compiled in sorted(glob(compiled_glob)):
                rm(compiled)

cmdclass = {
    'build_ext': build_ext,
    'build_usage': build_usage,
    'build_man': build_man,
    'sdist': Sdist,
    'clean2': Clean,
}

ext_modules = []
if not on_rtd:
    compress_ext_kwargs = dict(sources=[compress_source], include_dirs=include_dirs, library_dirs=library_dirs,
                               define_macros=define_macros)
    compress_ext_kwargs = setup_lz4.lz4_ext_kwargs(bundled_path='src/borg/algorithms/lz4',
                                                   system_prefix=liblz4_prefix, system=liblz4_system,
                                                   **compress_ext_kwargs)
    compress_ext_kwargs = setup_zstd.zstd_ext_kwargs(bundled_path='src/borg/algorithms/zstd',
                                                     system_prefix=libzstd_prefix, system=libzstd_system,
                                                     multithreaded=False, legacy=False, **compress_ext_kwargs)
    crypto_ext_kwargs = dict(sources=[crypto_ll_source], libraries=['crypto'],
                             include_dirs=include_dirs, library_dirs=library_dirs, define_macros=define_macros)
    crypto_ext_kwargs = setup_b2.b2_ext_kwargs(bundled_path='src/borg/algorithms/blake2',
                                               system_prefix=libb2_prefix, system=libb2_system,
                                               **crypto_ext_kwargs)

    crypto_ext_kwargs = setup_xxhash.xxhash_ext_kwargs(bundled_path='src/borg/algorithms/xxh64',
                                               system_prefix=libxxhash_prefix, system=libxxhash_system,
                                               **crypto_ext_kwargs)

    msgpack_endian = '__BIG_ENDIAN__' if (sys.byteorder == 'big') else '__LITTLE_ENDIAN__'
    msgpack_macros = [(msgpack_endian, '1')]
    msgpack_packer_ext_kwargs = dict(
        sources=[msgpack_packer_source],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        define_macros=msgpack_macros,
        language='c++',
    )
    msgpack_unpacker_ext_kwargs = dict(
        sources=[msgpack_unpacker_source],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        define_macros=msgpack_macros,
        language='c++',
    )

    ext_modules += [
        Extension('borg.algorithms.msgpack._packer', **msgpack_packer_ext_kwargs),
        Extension('borg.algorithms.msgpack._unpacker', **msgpack_unpacker_ext_kwargs),
        Extension('borg.compress', **compress_ext_kwargs),
        Extension('borg.crypto.low_level', **crypto_ext_kwargs),
        Extension('borg.hashindex', [hashindex_source]),
        Extension('borg.item', [item_source]),
        Extension('borg.chunker', [chunker_source]),
        Extension('borg.algorithms.checksums', [checksums_source]),
    ]
    if not sys.platform.startswith(('win32', )):
        ext_modules.append(Extension('borg.platform.posix', [platform_posix_source]))
    if sys.platform == 'linux':
        ext_modules.append(Extension('borg.platform.linux', [platform_linux_source], libraries=['acl']))
        ext_modules.append(Extension('borg.platform.syncfilerange', [platform_syncfilerange_source]))
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
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Archiving :: Backup',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'borg = borg.archiver:main',
            'borgfs = borg.archiver:main',
        ]
    },
    # See also the MANIFEST.in file.
    # We want to install all the files in the package directories...
    include_package_data=True,
    # ...except the source files which have been compiled (C extensions):
    exclude_package_data={
        '': ['*.c', '*.h', '*.pyx', ],
    },
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    setup_requires=['setuptools_scm>=1.7'],
    install_requires=install_requires,
    extras_require=extras_require,
)
