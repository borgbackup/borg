from .support import argparse  # see support/__init__.py docstring
                               # DEPRECATED - remove after requiring py 3.4

from binascii import hexlify
from datetime import datetime
from operator import attrgetter
import functools
import inspect
import io
import os
import signal
import stat
import sys
import textwrap
import traceback

from . import __version__
from .archive import Archive, ArchiveChecker, CHUNKER_PARAMS
from .compress import Compressor, COMPR_BUFFER
from .repository import Repository
from .cache import Cache
from .key import key_creator
from .helpers import Error, location_validator, format_time, format_file_size, \
    format_file_mode, ExcludePattern, IncludePattern, exclude_path, adjust_patterns, to_localtime, timestamp, \
    get_cache_dir, get_keys_dir, format_timedelta, prune_within, prune_split, \
    Manifest, remove_surrogates, update_excludes, format_archive, check_extension_modules, Statistics, \
    is_cachedir, bigint_to_int, ChunkerParams, CompressionSpec
from .remote import RepositoryServer, RemoteRepository

has_lchflags = hasattr(os, 'lchflags')


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
        print('borg: ' + msg, file=sys.stderr)

    def print_verbose(self, msg, *args, **kw):
        if self.verbose:
            msg = args and msg % args or msg
            if kw.get('newline', True):
                print(msg)
            else:
                print(msg, end=' ')

    def do_serve(self, args):
        """Start in server mode. This command is usually not used manually.
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
            while not os.environ.get('BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'):
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
        if not args.repo_only and not ArchiveChecker().check(
                repository, repair=args.repair, archive=args.repository.archive, last=args.last):
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
        dry_run = args.dry_run
        t0 = datetime.now()
        if not dry_run:
            repository = self.open_repository(args.archive, exclusive=True)
            manifest, key = Manifest.load(repository)
            compr_args = dict(buffer=COMPR_BUFFER)
            compr_args.update(args.compression)
            key.compressor = Compressor(**compr_args)
            cache = Cache(repository, key, manifest, do_files=args.cache_files)
            archive = Archive(repository, key, manifest, args.archive.archive, cache=cache,
                              create=True, checkpoint_interval=args.checkpoint_interval,
                              numeric_owner=args.numeric_owner, progress=args.progress,
                              chunker_params=args.chunker_params)
        else:
            archive = cache = None
        # Add cache dir to inode_skip list
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
            if path == '-':  # stdin
                path = 'stdin'
                if not dry_run:
                    try:
                        status = archive.process_stdin(path, cache)
                    except IOError as e:
                        self.print_error('%s: %s', path, e)
                else:
                    status = '-'
                self.print_verbose("%1s %s", status, path)
                continue
            path = os.path.normpath(path)
            if args.dontcross:
                try:
                    restrict_dev = os.lstat(path).st_dev
                except OSError as e:
                    self.print_error('%s: %s', path, e)
                    continue
            else:
                restrict_dev = None
            self._process(archive, cache, args.excludes, args.exclude_caches, skip_inodes, path, restrict_dev,
                          read_special=args.read_special, dry_run=dry_run)
        if not dry_run:
            archive.save(timestamp=args.timestamp)
            if args.progress:
                archive.stats.show_progress(final=True)
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

    def _process(self, archive, cache, excludes, exclude_caches, skip_inodes, path, restrict_dev,
                 read_special=False, dry_run=False):
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
        status = None
        # Ignore if nodump flag is set
        if has_lchflags and (st.st_flags & stat.UF_NODUMP):
            return
        if (stat.S_ISREG(st.st_mode) or
            read_special and not stat.S_ISDIR(st.st_mode)):
            if not dry_run:
                try:
                    status = archive.process_file(path, st, cache)
                except IOError as e:
                    self.print_error('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            if exclude_caches and is_cachedir(path):
                return
            if not dry_run:
                status = archive.process_dir(path, st)
            try:
                entries = os.listdir(path)
            except OSError as e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    entry_path = os.path.normpath(os.path.join(path, filename))
                    self._process(archive, cache, excludes, exclude_caches, skip_inodes,
                                  entry_path, restrict_dev, read_special=read_special,
                                  dry_run=dry_run)
        elif stat.S_ISLNK(st.st_mode):
            if not dry_run:
                status = archive.process_symlink(path, st)
        elif stat.S_ISFIFO(st.st_mode):
            if not dry_run:
                status = archive.process_fifo(path, st)
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            if not dry_run:
                status = archive.process_dev(path, st)
        elif stat.S_ISSOCK(st.st_mode):
            # Ignore unix sockets
            return
        else:
            self.print_error('Unknown file type: %s', path)
            return
        # Status output
        # A lowercase character means a file type other than a regular file,
        # borg usually just stores them. E.g. (d)irectory.
        # Hardlinks to already seen content are indicated by (h).
        # A uppercase character means a regular file that was (A)dded,
        # (M)odified or was (U)nchanged.
        # Note: A/M/U is relative to the "files" cache, not to the repo.
        # This would be an issue if the files cache is not used.
        if status is None:
            if not dry_run:
                status = '?'  # need to add a status code somewhere
            else:
                status = '-'  # dry run, item was not backed up
        # output ALL the stuff - it can be easily filtered using grep.
        # even stuff considered unchanged might be interesting.
        self.print_verbose("%1s %s", status, remove_surrogates(path))

    def do_extract(self, args):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == 'ascii':
            print('Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.')
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.archive.archive,
                          numeric_owner=args.numeric_owner)
        patterns = adjust_patterns(args.paths, args.excludes)
        dry_run = args.dry_run
        stdout = args.stdout
        sparse = args.sparse
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
                    archive.extract_item(dirs.pop(-1), stdout=stdout)
            self.print_verbose(remove_surrogates(orig_path))
            try:
                if dry_run:
                    archive.extract_item(item, dry_run=True)
                else:
                    if stat.S_ISDIR(item[b'mode']):
                        dirs.append(item)
                        archive.extract_item(item, restore_attrs=False)
                    else:
                        archive.extract_item(item, stdout=stdout, sparse=sparse)
            except IOError as e:
                self.print_error('%s: %s', remove_surrogates(orig_path), e)

        if not args.dry_run:
            while dirs:
                archive.extract_item(dirs.pop(-1))
        for pattern in (patterns or []):
            if isinstance(pattern, IncludePattern) and  pattern.match_count == 0:
                self.print_error("Warning: Include pattern '%s' never matched.", pattern)
        return self.exit_code

    def do_rename(self, args):
        """Rename an existing archive"""
        repository = self.open_repository(args.archive, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archive = Archive(repository, key, manifest, args.archive.archive, cache=cache)
        archive.rename(args.name)
        manifest.write()
        repository.commit()
        cache.commit()
        return self.exit_code

    def do_delete(self, args):
        """Delete an existing repository or archive"""
        repository = self.open_repository(args.target, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, do_files=args.cache_files)
        if args.target.archive:
            archive = Archive(repository, key, manifest, args.target.archive, cache=cache)
            stats = Statistics()
            archive.delete(stats)
            manifest.write()
            repository.commit()
            cache.commit()
            if args.stats:
                stats.print_('Deleted data:', cache)
        else:
            print("You requested to completely DELETE the repository *including* all archives it contains:")
            for archive_info in manifest.list_archive_infos(sort_by='ts'):
                print(format_archive(archive_info))
            if not os.environ.get('BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'):
                print("""Type "YES" if you understand this and want to continue.\n""")
                if input('Do you want to continue? ') != 'YES':
                    self.exit_code = 1
                    return self.exit_code
            repository.destroy()
            cache.destroy()
            print("Repository and corresponding cache were deleted.")
        return self.exit_code

    def do_mount(self, args):
        """Mount archive or an entire repository as a FUSE fileystem"""
        try:
            from .fuse import FuseOperations
        except ImportError as e:
            self.print_error('loading fuse support failed [ImportError: %s]' % str(e))
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
        operations = FuseOperations(key, repository, manifest, archive)
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
            archive = Archive(repository, key, manifest, args.src.archive)
            if args.short:
                for item in archive.iter_items():
                    print(remove_surrogates(item[b'path']))
            else:
                tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 0o10: '-', 0o12: 'l', 0o14: 's'}
                for item in archive.iter_items():
                    type = tmap.get(item[b'mode'] // 4096, '?')
                    mode = format_file_mode(item[b'mode'])
                    size = 0
                    if type == '-':
                        try:
                            size = sum(size for _, size, _ in item[b'chunks'])
                        except KeyError:
                            pass
                    try:
                        mtime = datetime.fromtimestamp(bigint_to_int(item[b'mtime']) / 1e9)
                    except ValueError:
                        # likely a broken mtime and datetime did not want to go beyond year 9999
                        mtime = datetime(9999, 12, 31, 23, 59, 59)
                    if b'source' in item:
                        if type == 'l':
                            extra = ' -> %s' % item[b'source']
                        else:
                            type = 'h'
                            extra = ' link to %s' % item[b'source']
                    else:
                        extra = ''
                    print('%s%s %-6s %-6s %8d %s %s%s' % (
                        type, mode, item[b'user'] or item[b'uid'],
                        item[b'group'] or item[b'gid'], size, format_time(mtime),
                        remove_surrogates(item[b'path']), extra))
        else:
            for archive_info in manifest.list_archive_infos(sort_by='ts'):
                print(format_archive(archive_info))
        return self.exit_code

    def do_info(self, args):
        """Show archive details such as disk space used"""
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, do_files=args.cache_files)
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
        cache = Cache(repository, key, manifest, do_files=args.cache_files)
        archives = manifest.list_archive_infos(sort_by='ts', reverse=True)  # just a ArchiveInfo list
        if args.hourly + args.daily + args.weekly + args.monthly + args.yearly == 0 and args.within is None:
            self.print_error('At least one of the "within", "keep-hourly", "keep-daily", "keep-weekly", '
                             '"keep-monthly" or "keep-yearly" settings must be specified')
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
                Archive(repository, key, manifest, archive.name, cache).delete(stats)
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
        $ borg create -e '*.o' backup /

        # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
        # not '/home/user/importantjunk' or '/etc/junk':
        $ borg create -e '/home/*/junk' backup /

        # Exclude the contents of '/home/user/cache' but not the directory itself:
        $ borg create -e /home/user/cache/ backup /

        # The file '/home/user/cache/important' is *not* backed up:
        $ borg create -e /home/user/cache/ backup / /home/user/cache/important
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
            print('Warning: "borg verify" has been deprecated. Use "borg extract --dry-run" instead.')
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
                    # This file is a cache directory tag created by Borg.
                    # For information about cache directory tags, see:
                    #       http://www.brynosaurus.com/cachedir/
                    """).lstrip())
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                                   default=False,
                                   help='verbose output')
        common_parser.add_argument('--no-files-cache', dest='cache_files', action='store_false',
                                   help='do not load/update the file metadata cache used to detect unchanged files')
        common_parser.add_argument('--umask', dest='umask', type=lambda s: int(s, 8), default=0o077, metavar='M',
                                   help='set umask to M (local and remote, default: 0o077)')
        common_parser.add_argument('--remote-path', dest='remote_path', default='borg', metavar='PATH',
                                   help='set remote path to executable (default: "borg")')

        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)

        parser = argparse.ArgumentParser(description='Borg %s - Deduplicated Backups' % __version__)
        subparsers = parser.add_subparsers(title='Available commands')

        serve_epilog = textwrap.dedent("""
        This command starts a repository server process. This command is usually not used manually.
        """)
        subparser = subparsers.add_parser('serve', parents=[common_parser],
                                          description=self.do_serve.__doc__, epilog=serve_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_serve)
        subparser.add_argument('--restrict-to-path', dest='restrict_to_paths', action='append',
                               metavar='PATH', help='restrict repository access to PATH')
        init_epilog = textwrap.dedent("""
        This command initializes an empty repository. A repository is a filesystem
        directory containing the deduplicated data from zero or more archives.
        Encryption can be enabled at repository init time.
        Please note that the 'passphrase' encryption mode is DEPRECATED (instead of it,
        consider using 'repokey').
        """)
        subparser = subparsers.add_parser('init', parents=[common_parser],
                                          description=self.do_init.__doc__, epilog=init_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('repository', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to create')
        subparser.add_argument('-e', '--encryption', dest='encryption',
                               choices=('none', 'keyfile', 'repokey', 'passphrase'), default='none',
                               help='select encryption key mode')

        check_epilog = textwrap.dedent("""
        The check command verifies the consistency of a repository and the corresponding archives.

        First, the underlying repository data files are checked:

        - For all segments the segment magic (header) is checked
        - For all objects stored in the segments, all metadata (e.g. crc and size) and
          all data is read. The read data is checked by size and CRC. Bit rot and other
          types of accidental damage can be detected this way.
        - If we are in repair mode and a integrity error is detected for a segment,
          we try to recover as many objects from the segment as possible.
        - In repair mode, it makes sure that the index is consistent with the data
          stored in the segments.
        - If you use a remote repo server via ssh:, the repo check is executed on the
          repo server without causing significant network traffic.
        - The repository check can be skipped using the --archives-only option.

        Second, the consistency and correctness of the archive metadata is verified:

        - Is the repo manifest present? If not, it is rebuilt from archive metadata
          chunks (this requires reading and decrypting of all metadata and data).
        - Check if archive metadata chunk is present. if not, remove archive from
          manifest.
        - For all files (items) in the archive, for all chunks referenced by these
          files, check if chunk is present (if not and we are in repair mode, replace
          it with a same-size chunk of zeros). This requires reading of archive and
          file metadata, but not data.
        - If we are in repair mode and we checked all the archives: delete orphaned
          chunks from the repo.
        - if you use a remote repo server via ssh:, the archive check is executed on
          the client machine (because if encryption is enabled, the checks will require
          decryption and this is always done client-side, because key access will be
          required).
        - The archive checks can be time consuming, they can be skipped using the
          --repository-only option.
        """)
        subparser = subparsers.add_parser('check', parents=[common_parser],
                                          description=self.do_check.__doc__,
                                          epilog=check_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_check)
        subparser.add_argument('repository', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
                               help='repository or archive to check consistency of')
        subparser.add_argument('--repository-only', dest='repo_only', action='store_true',
                               default=False,
                               help='only perform repository checks')
        subparser.add_argument('--archives-only', dest='archives_only', action='store_true',
                               default=False,
                               help='only perform archives checks')
        subparser.add_argument('--repair', dest='repair', action='store_true',
                               default=False,
                               help='attempt to repair any inconsistencies found')
        subparser.add_argument('--last', dest='last',
                               type=int, default=None, metavar='N',
                               help='only check last N archives (Default: all)')

        change_passphrase_epilog = textwrap.dedent("""
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.
        """)
        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser],
                                          description=self.do_change_passphrase.__doc__,
                                          epilog=change_passphrase_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('repository', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))

        create_epilog = textwrap.dedent("""
        This command creates a backup archive containing all files found while recursively
        traversing all paths specified. The archive will consume almost no disk space for
        files or parts of files that have already been stored in other archives.

        See the output of the "borg help patterns" command for more help on exclude patterns.
        """)

        subparser = subparsers.add_parser('create', parents=[common_parser],
                                          description=self.do_create.__doc__,
                                          epilog=create_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the created archive')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help='print progress while creating the archive')
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
        subparser.add_argument('--timestamp', dest='timestamp',
                               type=timestamp, default=None,
                               metavar='yyyy-mm-ddThh:mm:ss',
                               help='manually specify the archive creation date/time (UTC). '
                                    'alternatively, give a reference file/directory.')
        subparser.add_argument('--chunker-params', dest='chunker_params',
                               type=ChunkerParams, default=CHUNKER_PARAMS,
                               metavar='CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE',
                               help='specify the chunker parameters. default: %d,%d,%d,%d' % CHUNKER_PARAMS)
        subparser.add_argument('-C', '--compression', dest='compression',
                               type=CompressionSpec, default=dict(name='none'), metavar='COMPRESSION',
                               help='select compression algorithm (and level): '
                                    'none == no compression (default), '
                                    'lz4 == lz4, '
                                    'zlib == zlib (default level 6), '
                                    'zlib,0 .. zlib,9 == zlib (with level 0..9), '
                                    'lzma == lzma (default level 6), '
                                    'lzma,0 .. lzma,9 == lzma (with level 0..9).')
        subparser.add_argument('--read-special', dest='read_special',
                               action='store_true', default=False,
                               help='open and read special files as if they were regular files')
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               action='store_true', default=False,
                               help='do not create a backup archive')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='name of archive to create (must be also a valid directory name)')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='paths to archive')

        extract_epilog = textwrap.dedent("""
        This command extracts the contents of an archive. By default the entire
        archive is extracted but a subset of files and directories can be selected
        by passing a list of ``PATHs`` as arguments. The file selection can further
        be restricted by using the ``--exclude`` option.

        See the output of the "borg help patterns" command for more help on exclude patterns.
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
        subparser.add_argument('--stdout', dest='stdout',
                               action='store_true', default=False,
                               help='write all extracted data to stdout')
        subparser.add_argument('--sparse', dest='sparse',
                               action='store_true', default=False,
                               help='create holes in output sparse file from all-zero chunks')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to extract')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to extract')

        rename_epilog = textwrap.dedent("""
        This command renames an archive in the repository.
        """)
        subparser = subparsers.add_parser('rename', parents=[common_parser],
                                          description=self.do_rename.__doc__,
                                          epilog=rename_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_rename)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to rename')
        subparser.add_argument('name', metavar='NEWNAME', type=str,
                               help='the new archive name to use')

        delete_epilog = textwrap.dedent("""
        This command deletes an archive from the repository or the complete repository.
        Disk space is reclaimed accordingly. If you delete the complete repository, the
        local cache for it (if any) is also deleted.
        """)
        subparser = subparsers.add_parser('delete', parents=[common_parser],
                                          description=self.do_delete.__doc__,
                                          epilog=delete_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('target', metavar='TARGET', nargs='?', default='',
                               type=location_validator(),
                               help='archive or repository to delete')

        list_epilog = textwrap.dedent("""
        This command lists the contents of a repository or an archive.
        """)
        subparser = subparsers.add_parser('list', parents=[common_parser],
                                          description=self.do_list.__doc__,
                                          epilog=list_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('--short', dest='short',
                               action='store_true', default=False,
                               help='only print file/directory names, nothing else')
        subparser.add_argument('src', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
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
        Otherwise, *all* archives in the repository are candidates for deletion!
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
        subparser.add_argument('repository', metavar='REPOSITORY', nargs='?', default='',
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
        os.umask(args.umask)
        RemoteRepository.remote_path = args.remote_path
        RemoteRepository.umask = args.umask
        update_excludes(args)
        return args.func(args)


def sig_info_handler(signum, stack):  # pragma: no cover
    """search the stack for infos about the currently processed file and print them"""
    for frame in inspect.getouterframes(stack):
        func, loc = frame[3], frame[0].f_locals
        if func in ('process_file', '_process', ):  # create op
            path = loc['path']
            try:
                pos = loc['fd'].tell()
                total = loc['st'].st_size
            except Exception:
                pos, total = 0, 0
            print("{0} {1}/{2}".format(path, format_file_size(pos), format_file_size(total)))
            break
        if func in ('extract_item', ):  # extract op
            path = loc['item'][b'path']
            try:
                pos = loc['fd'].tell()
            except Exception:
                pos = 0
            print("{0} {1}/???".format(path, format_file_size(pos)))
            break


def setup_signal_handlers():  # pragma: no cover
    sigs = []
    if hasattr(signal, 'SIGUSR1'):
        sigs.append(signal.SIGUSR1)  # kill -USR1 pid
    if hasattr(signal, 'SIGINFO'):
        sigs.append(signal.SIGINFO)  # kill -INFO pid (or ctrl-t)
    for sig in sigs:
        signal.signal(sig, sig_info_handler)


def main():  # pragma: no cover
    # Make sure stdout and stderr have errors='replace') to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, 'replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, 'replace', line_buffering=True)
    setup_signal_handlers()
    archiver = Archiver()
    try:
        exit_code = archiver.run(sys.argv[1:])
    except Error as e:
        archiver.print_error(e.get_message() + "\n%s" % traceback.format_exc())
        exit_code = e.exit_code
    except RemoteRepository.RPCError as e:
        archiver.print_error('Error: Remote Exception.\n%s' % str(e))
        exit_code = 1
    except Exception:
        archiver.print_error('Error: Local Exception.\n%s' % traceback.format_exc())
        exit_code = 1
    except KeyboardInterrupt:
        archiver.print_error('Error: Keyboard interrupt.\n%s' % traceback.format_exc())
        exit_code = 1
    if exit_code:
        archiver.print_error('Exiting with failure status due to previous errors')
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
