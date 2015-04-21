import argparse
from binascii import hexlify
from datetime import datetime
from operator import attrgetter
import functools
import io
import os
import stat
import sys
import textwrap

from attic import __version__
from attic.archive import Archive, ArchiveChecker
from attic.repository import Repository
from attic.cache import Cache
from attic.key import key_creator
from attic.helpers import Error, location_validator, format_time, \
    format_file_mode, ExcludePattern, exclude_path, adjust_patterns, to_localtime, \
    get_cache_dir, get_keys_dir, format_timedelta, prune_within, prune_split, \
    Manifest, remove_surrogates, update_excludes, format_archive, check_extension_modules, Statistics, \
    is_cachedir, bigint_to_int
from attic.remote import RepositoryServer, RemoteRepository


class Archiver:

    def __init__(self):
        self.exit_code = 0

    def open_repository(self, location, create=False, exclusive=False):
        if location.proto == 'ssh':
            repository = RemoteRepository(location, create=create)
        else:
            repository = Repository(location.path, create=create, exclusive=exclusive)
        repository._location = location
        return repository

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = 1
        print('attic: ' + msg, file=sys.stderr)

    def print_verbose(self, msg, *args, **kw):
        if self.verbose:
            msg = args and msg % args or msg
            if kw.get('newline', True):
                print(msg)
            else:
                print(msg, end=' ')

    def do_serve(self, args):
        """Start Attic in server mode. This command is usually not used manually.
        """
        return RepositoryServer(restrict_to_paths=args.restrict_to_paths).serve()

    def do_init(self, args):
        """Initialize an empty repository"""
        print('Initializing repository at "%s"' % args.repository.orig)
        repository = self.open_repository(args.repository, create=True, exclusive=True)
        key = key_creator(repository, args)
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit()
        Cache(repository, key, manifest, warn_if_unencrypted=False)
        return self.exit_code

    def do_check(self, args):
        """Check repository consistency"""
        repository = self.open_repository(args.repository, exclusive=args.repair)
        if args.repair:
            while not os.environ.get('ATTIC_CHECK_I_KNOW_WHAT_I_AM_DOING'):
                self.print_error("""Warning: 'check --repair' is an experimental feature that might result
in data loss.

Type "Yes I am sure" if you understand this and want to continue.\n""")
                if input('Do you want to continue? ') == 'Yes I am sure':
                    break
        if not args.archives_only:
            print('Starting repository check...')
            if repository.check(repair=args.repair):
                print('Repository check complete, no problems found.')
            else:
                return 1
        if not args.repo_only and not ArchiveChecker().check(repository, repair=args.repair):
                return 1
        return 0

    def do_change_passphrase(self, args):
        """Change repository key file passphrase"""
        repository = self.open_repository(args.repository)
        manifest, key = Manifest.load(repository)
        key.change_passphrase()
        return 0

    def do_create(self, args):
        """Create new archive"""
        t0 = datetime.now()
        repository = self.open_repository(args.archive, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archive = Archive(repository, key, manifest, args.archive.archive, cache=cache,
                          create=True, checkpoint_interval=args.checkpoint_interval,
                          numeric_owner=args.numeric_owner)
        # Add Attic cache dir to inode_skip list
        skip_inodes = set()
        try:
            st = os.stat(get_cache_dir())
            skip_inodes.add((st.st_ino, st.st_dev))
        except IOError:
            pass
        # Add local repository dir to inode_skip list
        if not args.archive.host:
            try:
                st = os.stat(args.archive.path)
                skip_inodes.add((st.st_ino, st.st_dev))
            except IOError:
                pass
        for path in args.paths:
            path = os.path.normpath(path)
            if args.dontcross:
                try:
                    restrict_dev = os.lstat(path).st_dev
                except OSError as e:
                    self.print_error('%s: %s', path, e)
                    continue
            else:
                restrict_dev = None
            self._process(archive, cache, args.excludes, args.exclude_caches, skip_inodes, path, restrict_dev)
        archive.save()
        if args.stats:
            t = datetime.now()
            diff = t - t0
            print('-' * 78)
            print('Archive name: %s' % args.archive.archive)
            print('Archive fingerprint: %s' % hexlify(archive.id).decode('ascii'))
            print('Start time: %s' % t0.strftime('%c'))
            print('End time: %s' % t.strftime('%c'))
            print('Duration: %s' % format_timedelta(diff))
            print('Number of files: %d' % archive.stats.nfiles)
            archive.stats.print_('This archive:', cache)
            print('-' * 78)
        return self.exit_code

    def _process(self, archive, cache, excludes, exclude_caches, skip_inodes, path, restrict_dev):
        if exclude_path(path, excludes):
            return
        try:
            st = os.lstat(path)
        except OSError as e:
            self.print_error('%s: %s', path, e)
            return
        if (st.st_ino, st.st_dev) in skip_inodes:
            return
        # Entering a new filesystem?
        if restrict_dev and st.st_dev != restrict_dev:
            return
        # Ignore unix sockets
        if stat.S_ISSOCK(st.st_mode):
            return
        self.print_verbose(remove_surrogates(path))
        if stat.S_ISREG(st.st_mode):
            try:
                archive.process_file(path, st, cache)
            except IOError as e:
                self.print_error('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            if exclude_caches and is_cachedir(path):
                return
            archive.process_item(path, st)
            try:
                entries = os.listdir(path)
            except OSError as e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    self._process(archive, cache, excludes, exclude_caches, skip_inodes,
                                  os.path.join(path, filename), restrict_dev)
        elif stat.S_ISLNK(st.st_mode):
            archive.process_symlink(path, st)
        elif stat.S_ISFIFO(st.st_mode):
            archive.process_item(path, st)
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            archive.process_dev(path, st)
        else:
            self.print_error('Unknown file type: %s', path)

    def do_extract(self, args):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == 'ascii':
            print('Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.')
        os.umask(0o077)
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.archive.archive,
                          numeric_owner=args.numeric_owner)
        patterns = adjust_patterns(args.paths, args.excludes)
        dry_run = args.dry_run
        strip_components = args.strip_components
        dirs = []
        for item in archive.iter_items(lambda item: not exclude_path(item[b'path'], patterns), preload=True):
            orig_path = item[b'path']
            if strip_components:
                item[b'path'] = os.sep.join(orig_path.split(os.sep)[strip_components:])
                if not item[b'path']:
                    continue
            if not args.dry_run:
                while dirs and not item[b'path'].startswith(dirs[-1][b'path']):
                    archive.extract_item(dirs.pop(-1))
            self.print_verbose(remove_surrogates(orig_path))
            try:
                if dry_run:
                    archive.extract_item(item, dry_run=True)
                else:
                    if stat.S_ISDIR(item[b'mode']):
                        dirs.append(item)
                        archive.extract_item(item, restore_attrs=False)
                    else:
                        archive.extract_item(item)
            except IOError as e:
                self.print_error('%s: %s', remove_surrogates(orig_path), e)

        if not args.dry_run:
            while dirs:
                archive.extract_item(dirs.pop(-1))
        return self.exit_code

    def do_delete(self, args):
        """Delete an existing archive"""
        repository = self.open_repository(args.archive, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archive = Archive(repository, key, manifest, args.archive.archive, cache=cache)
        stats = Statistics()
        archive.delete(stats)
        manifest.write()
        repository.commit()
        cache.commit()
        if args.stats:
            stats.print_('Deleted data:', cache)
        return self.exit_code

    def do_mount(self, args):
        """Mount archive or an entire repository as a FUSE fileystem"""
        try:
            from attic.fuse import AtticOperations
        except ImportError:
            self.print_error('the "llfuse" module is required to use this feature')
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error('%s: Mountpoint must be a writable directory' % args.mountpoint)
            return self.exit_code

        repository = self.open_repository(args.src)
        manifest, key = Manifest.load(repository)
        if args.src.archive:
            archive = Archive(repository, key, manifest, args.src.archive)
        else:
            archive = None
        operations = AtticOperations(key, repository, manifest, archive)
        self.print_verbose("Mounting filesystem")
        try:
            operations.mount(args.mountpoint, args.options, args.foreground)
        except RuntimeError:
            # Relevant error message already printed to stderr by fuse
            self.exit_code = 1
        return self.exit_code

    def do_list(self, args):
        """List archive or repository contents"""
        repository = self.open_repository(args.src)
        manifest, key = Manifest.load(repository)
        if args.src.archive:
            tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 0o10: '-', 0o12: 'l', 0o14: 's'}
            archive = Archive(repository, key, manifest, args.src.archive)
            for item in archive.iter_items():
                type = tmap.get(item[b'mode'] // 4096, '?')
                mode = format_file_mode(item[b'mode'])
                size = 0
                if type == '-':
                    try:
                        size = sum(size for _, size, _ in item[b'chunks'])
                    except KeyError:
                        pass
                mtime = format_time(datetime.fromtimestamp(bigint_to_int(item[b'mtime']) / 1e9))
                if b'source' in item:
                    if type == 'l':
                        extra = ' -> %s' % item[b'source']
                    else:
                        type = 'h'
                        extra = ' link to %s' % item[b'source']
                else:
                    extra = ''
                print('%s%s %-6s %-6s %8d %s %s%s' % (type, mode, item[b'user'] or item[b'uid'],
                                                  item[b'group'] or item[b'gid'], size, mtime,
                                                  remove_surrogates(item[b'path']), extra))
        else:
            for archive in sorted(Archive.list_archives(repository, key, manifest), key=attrgetter('ts')):
                print(format_archive(archive))
        return self.exit_code

    def do_info(self, args):
        """Show archive details such as disk space used"""
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archive = Archive(repository, key, manifest, args.archive.archive, cache=cache)
        stats = archive.calc_stats(cache)
        print('Name:', archive.name)
        print('Fingerprint: %s' % hexlify(archive.id).decode('ascii'))
        print('Hostname:', archive.metadata[b'hostname'])
        print('Username:', archive.metadata[b'username'])
        print('Time: %s' % to_localtime(archive.ts).strftime('%c'))
        print('Command line:', remove_surrogates(' '.join(archive.metadata[b'cmdline'])))
        print('Number of files: %d' % stats.nfiles)
        stats.print_('This archive:', cache)
        return self.exit_code

    def do_prune(self, args):
        """Prune repository archives according to specified rules"""
        repository = self.open_repository(args.repository, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archives = list(sorted(Archive.list_archives(repository, key, manifest, cache),
                               key=attrgetter('ts'), reverse=True))
        if args.hourly + args.daily + args.weekly + args.monthly + args.yearly == 0 and args.within is None:
            self.print_error('At least one of the "within", "hourly", "daily", "weekly", "monthly" or "yearly" '
                             'settings must be specified')
            return 1
        if args.prefix:
            archives = [archive for archive in archives if archive.name.startswith(args.prefix)]
        keep = []
        if args.within:
            keep += prune_within(archives, args.within)
        if args.hourly:
            keep += prune_split(archives, '%Y-%m-%d %H', args.hourly, keep)
        if args.daily:
            keep += prune_split(archives, '%Y-%m-%d', args.daily, keep)
        if args.weekly:
            keep += prune_split(archives, '%G-%V', args.weekly, keep)
        if args.monthly:
            keep += prune_split(archives, '%Y-%m', args.monthly, keep)
        if args.yearly:
            keep += prune_split(archives, '%Y', args.yearly, keep)

        keep.sort(key=attrgetter('ts'), reverse=True)
        to_delete = [a for a in archives if a not in keep]
        stats = Statistics()
        for archive in keep:
            self.print_verbose('Keeping archive: %s' % format_archive(archive))
        for archive in to_delete:
            if args.dry_run:
                self.print_verbose('Would prune:     %s' % format_archive(archive))
            else:
                self.print_verbose('Pruning archive: %s' % format_archive(archive))
                archive.delete(stats)
        if to_delete and not args.dry_run:
            manifest.write()
            repository.commit()
            cache.commit()
        if args.stats:
            stats.print_('Deleted data:', cache)
        return self.exit_code

    helptext = {}
    helptext['patterns'] = '''
        Exclude patterns use a variant of shell pattern syntax, with '*' matching any
        number of characters, '?' matching any single character, '[...]' matching any
        single character specified, including ranges, and '[!...]' matching any
        character not specified.  For the purpose of these patterns, the path
        separator ('\\' for Windows and '/' on other systems) is not treated
        specially.  For a path to match a pattern, it must completely match from
        start to end, or must match from the start to just before a path separator.
        Except for the root path, paths will never end in the path separator when
        matching is attempted.  Thus, if a given pattern ends in a path separator, a
        '*' is appended before matching is attempted.  Patterns with wildcards should
        be quoted to protect them from shell expansion.

        Examples:

        # Exclude '/home/user/file.o' but not '/home/user/file.odt':
        $ attic create -e '*.o' repo.attic /

        # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
        # not '/home/user/importantjunk' or '/etc/junk':
        $ attic create -e '/home/*/junk' repo.attic /

        # Exclude the contents of '/home/user/cache' but not the directory itself:
        $ attic create -e /home/user/cache/ repo.attic /

        # The file '/home/user/cache/important' is *not* backed up:
        $ attic create -e /home/user/cache/ repo.attic / /home/user/cache/important
        '''

    def do_help(self, parser, commands, args):
        if not args.topic:
            parser.print_help()
        elif args.topic in self.helptext:
            print(self.helptext[args.topic])
        elif args.topic in commands:
            if args.epilog_only:
                print(commands[args.topic].epilog)
            elif args.usage_only:
                commands[args.topic].epilog = None
                commands[args.topic].print_help()
            else:
                commands[args.topic].print_help()
        else:
            parser.error('No help available on %s' % (args.topic,))
        return self.exit_code

    def preprocess_args(self, args):
        deprecations = [
            ('--hourly', '--keep-hourly', 'Warning: "--hourly" has been deprecated. Use "--keep-hourly" instead.'),
            ('--daily', '--keep-daily', 'Warning: "--daily" has been deprecated. Use "--keep-daily" instead.'),
            ('--weekly', '--keep-weekly', 'Warning: "--weekly" has been deprecated. Use "--keep-weekly" instead.'),
            ('--monthly', '--keep-monthly', 'Warning: "--monthly" has been deprecated. Use "--keep-monthly" instead.'),
            ('--yearly', '--keep-yearly', 'Warning: "--yearly" has been deprecated. Use "--keep-yearly" instead.')
        ]
        if args and args[0] == 'verify':
            print('Warning: "attic verify" has been deprecated. Use "attic extract --dry-run" instead.')
            args = ['extract', '--dry-run'] + args[1:]
        for i, arg in enumerate(args[:]):
            for old_name, new_name, warning in deprecations:
                if arg.startswith(old_name):
                    args[i] = arg.replace(old_name, new_name)
                    print(warning)
        return args

    def run(self, args=None):
        check_extension_modules()
        keys_dir = get_keys_dir()
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
            os.chmod(keys_dir, stat.S_IRWXU)
        cache_dir = get_cache_dir()
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
            os.chmod(cache_dir, stat.S_IRWXU)
            with open(os.path.join(cache_dir, 'CACHEDIR.TAG'), 'w') as fd:
                fd.write(textwrap.dedent("""
                    Signature: 8a477f597d28d172789f06886806bc55
                    # This file is a cache directory tag created by Attic.
                    # For information about cache directory tags, see:
                    #       http://www.brynosaurus.com/cachedir/
                    """).lstrip())
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='verbose output')

        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)

        parser = argparse.ArgumentParser(description='Attic %s - Deduplicated Backups' % __version__)
        subparsers = parser.add_subparsers(title='Available commands')

        subparser = subparsers.add_parser('serve', parents=[common_parser],
                                          description=self.do_serve.__doc__)
        subparser.set_defaults(func=self.do_serve)
        subparser.add_argument('--restrict-to-path', dest='restrict_to_paths', action='append',
                               metavar='PATH', help='restrict repository access to PATH')
        init_epilog = textwrap.dedent("""
        This command initializes an empty repository. A repository is a filesystem
        directory containing the deduplicated data from zero or more archives.
        Encryption can be enabled at repository init time.
        """)
        subparser = subparsers.add_parser('init', parents=[common_parser],
                                          description=self.do_init.__doc__, epilog=init_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to create')
        subparser.add_argument('-e', '--encryption', dest='encryption',
                               choices=('none', 'passphrase', 'keyfile'), default='none',
                               help='select encryption method')

        check_epilog = textwrap.dedent("""
        The check command verifies the consistency of a repository and the corresponding
        archives. The underlying repository data files are first checked to detect bit rot
        and other types of damage. After that the consistency and correctness of the archive
        metadata is verified.

        The archive metadata checks can be time consuming and requires access to the key
        file and/or passphrase if encryption is enabled. These checks can be skipped using
        the --repository-only option.
        """)
        subparser = subparsers.add_parser('check', parents=[common_parser],
                                          description=self.do_check.__doc__,
                                          epilog=check_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_check)
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to check consistency of')
        subparser.add_argument('--repository-only', dest='repo_only', action='store_true',
                               default=False,
                               help='only perform repository checks')
        subparser.add_argument('--archives-only', dest='archives_only', action='store_true',
                               default=False,
                               help='only perform archives checks')
        subparser.add_argument('--repair', dest='repair', action='store_true',
                               default=False,
                               help='attempt to repair any inconsistencies found')

        change_passphrase_epilog = textwrap.dedent("""
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.
        """)
        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser],
                                          description=self.do_change_passphrase.__doc__,
                                          epilog=change_passphrase_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False))

        create_epilog = textwrap.dedent("""
        This command creates a backup archive containing all files found while recursively
        traversing all paths specified. The archive will consume almost no disk space for
        files or parts of files that have already been stored in other archives.

        See "attic help patterns" for more help on exclude patterns.
        """)

        subparser = subparsers.add_parser('create', parents=[common_parser],
                                          description=self.do_create.__doc__,
                                          epilog=create_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the created archive')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--exclude-from', dest='exclude_files',
                               type=argparse.FileType('r'), action='append',
                               metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        subparser.add_argument('--exclude-caches', dest='exclude_caches',
                               action='store_true', default=False,
                               help='exclude directories that contain a CACHEDIR.TAG file (http://www.brynosaurus.com/cachedir/spec.html)')
        subparser.add_argument('-c', '--checkpoint-interval', dest='checkpoint_interval',
                               type=int, default=300, metavar='SECONDS',
                               help='write checkpoint every SECONDS seconds (Default: 300)')
        subparser.add_argument('--do-not-cross-mountpoints', dest='dontcross',
                               action='store_true', default=False,
                               help='do not cross mount points')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='only store numeric user and group identifiers')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to create')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='paths to archive')

        extract_epilog = textwrap.dedent("""
        This command extracts the contents of an archive. By default the entire
        archive is extracted but a subset of files and directories can be selected
        by passing a list of ``PATHs`` as arguments. The file selection can further
        be restricted by using the ``--exclude`` option.

        See "attic help patterns" for more help on exclude patterns.
        """)
        subparser = subparsers.add_parser('extract', parents=[common_parser],
                                          description=self.do_extract.__doc__,
                                          epilog=extract_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not actually change any files')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--exclude-from', dest='exclude_files',
                               type=argparse.FileType('r'), action='append',
                               metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='only obey numeric user and group identifiers')
        subparser.add_argument('--strip-components', dest='strip_components',
                               type=int, default=0, metavar='NUMBER',
                               help='Remove the specified number of leading path elements. Pathnames with fewer elements will be silently skipped.')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to extract')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to extract')

        delete_epilog = textwrap.dedent("""
        This command deletes an archive from the repository. Any disk space not
        shared with any other existing archive is also reclaimed.
        """)
        subparser = subparsers.add_parser('delete', parents=[common_parser],
                                          description=self.do_delete.__doc__,
                                          epilog=delete_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to delete')

        list_epilog = textwrap.dedent("""
        This command lists the contents of a repository or an archive.
        """)
        subparser = subparsers.add_parser('list', parents=[common_parser],
                                          description=self.do_list.__doc__,
                                          epilog=list_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('src', metavar='REPOSITORY_OR_ARCHIVE', type=location_validator(),
                               help='repository/archive to list contents of')
        mount_epilog = textwrap.dedent("""
        This command mounts an archive as a FUSE filesystem. This can be useful for
        browsing an archive or restoring individual files. Unless the ``--foreground``
        option is given the command will run in the background until the filesystem
        is ``umounted``.
        """)
        subparser = subparsers.add_parser('mount', parents=[common_parser],
                                          description=self.do_mount.__doc__,
                                          epilog=mount_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_mount)
        subparser.add_argument('src', metavar='REPOSITORY_OR_ARCHIVE', type=location_validator(),
                               help='repository/archive to mount')
        subparser.add_argument('mountpoint', metavar='MOUNTPOINT', type=str,
                               help='where to mount filesystem')
        subparser.add_argument('-f', '--foreground', dest='foreground',
                               action='store_true', default=False,
                               help='stay in foreground, do not daemonize')
        subparser.add_argument('-o', dest='options', type=str,
                               help='Extra mount options')

        info_epilog = textwrap.dedent("""
        This command displays some detailed information about the specified archive.
        """)
        subparser = subparsers.add_parser('info', parents=[common_parser],
                                          description=self.do_info.__doc__,
                                          epilog=info_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to display information about')

        prune_epilog = textwrap.dedent("""
        The prune command prunes a repository by deleting archives not matching
        any of the specified retention options. This command is normally used by
        automated backup scripts wanting to keep a certain number of historic backups.

        As an example, "-d 7" means to keep the latest backup on each day for 7 days.
        Days without backups do not count towards the total.
        The rules are applied from hourly to yearly, and backups selected by previous
        rules do not count towards those of later rules. The time that each backup
        completes is used for pruning purposes. Dates and times are interpreted in
        the local timezone, and weeks go from Monday to Sunday. Specifying a
        negative number of archives to keep means that there is no limit.

        The "--keep-within" option takes an argument of the form "<int><char>",
        where char is "H", "d", "w", "m", "y". For example, "--keep-within 2d" means
        to keep all archives that were created within the past 48 hours.
        "1m" is taken to mean "31d". The archives kept with this option do not
        count towards the totals specified by any other options.

        If a prefix is set with -p, then only archives that start with the prefix are
        considered for deletion and only those archives count towards the totals
        specified by the rules.
        """)
        subparser = subparsers.add_parser('prune', parents=[common_parser],
                                          description=self.do_prune.__doc__,
                                          epilog=prune_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not change repository')
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('--keep-within', dest='within', type=str, metavar='WITHIN',
                               help='keep all archives within this time interval')
        subparser.add_argument('-H', '--keep-hourly', dest='hourly', type=int, default=0,
                               help='number of hourly archives to keep')
        subparser.add_argument('-d', '--keep-daily', dest='daily', type=int, default=0,
                               help='number of daily archives to keep')
        subparser.add_argument('-w', '--keep-weekly', dest='weekly', type=int, default=0,
                               help='number of weekly archives to keep')
        subparser.add_argument('-m', '--keep-monthly', dest='monthly', type=int, default=0,
                               help='number of monthly archives to keep')
        subparser.add_argument('-y', '--keep-yearly', dest='yearly', type=int, default=0,
                               help='number of yearly archives to keep')
        subparser.add_argument('-p', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to prune')

        subparser = subparsers.add_parser('help', parents=[common_parser],
                                          description='Extra help')
        subparser.add_argument('--epilog-only', dest='epilog_only',
                               action='store_true', default=False)
        subparser.add_argument('--usage-only', dest='usage_only',
                               action='store_true', default=False)
        subparser.set_defaults(func=functools.partial(self.do_help, parser, subparsers.choices))
        subparser.add_argument('topic', metavar='TOPIC', type=str, nargs='?',
                               help='additional help on TOPIC')

        args = parser.parse_args(args or ['-h'])
        self.verbose = args.verbose
        update_excludes(args)
        return args.func(args)


def main():
    # Make sure stdout and stderr have errors='replace') to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, 'replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, 'replace', line_buffering=True)
    archiver = Archiver()
    try:
        exit_code = archiver.run(sys.argv[1:])
    except Error as e:
        archiver.print_error(e.get_message())
        exit_code = e.exit_code
    except KeyboardInterrupt:
        archiver.print_error('Error: Keyboard interrupt')
        exit_code = 1
    else:
        if exit_code:
            archiver.print_error('Exiting with failure status due to previous errors')
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
