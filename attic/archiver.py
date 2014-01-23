import argparse
from binascii import hexlify
from datetime import datetime
from operator import attrgetter
import os
import stat
import sys

from attic import __version__
from attic.archive import Archive
from attic.repository import Repository
from attic.cache import Cache
from attic.key import key_creator
from attic.helpers import Error, location_validator, format_time, \
    format_file_mode, ExcludePattern, exclude_path, adjust_patterns, to_localtime, \
    get_cache_dir, get_keys_dir, format_timedelta, prune_split, Manifest, remove_surrogates
from attic.remote import RepositoryServer, RemoteRepository


class Archiver:

    def __init__(self):
        self.exit_code = 0

    def open_repository(self, location, create=False):
        if location.proto == 'ssh':
            repository = RemoteRepository(location, create=create)
        else:
            repository = Repository(location.path, create=create)
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

    def do_serve(self):
        return RepositoryServer().serve()

    def do_init(self, args):
        """Initialize an empty repository
        """
        print('Initializing repository at "%s"' % args.repository.orig)
        repository = self.open_repository(args.repository, create=True)
        key = key_creator(repository, args)
        manifest = Manifest()
        manifest.repository = repository
        manifest.key = key
        manifest.write()
        repository.commit()
        return self.exit_code

    def do_change_passphrase(self, args):
        """Change repository key file passphrase
        """
        repository = self.open_repository(args.repository)
        manifest, key = Manifest.load(repository)
        key.change_passphrase()
        return self.exit_code

    def do_create(self, args):
        """Create new archive
        """
        t0 = datetime.now()
        repository = self.open_repository(args.archive)
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
            self._process(archive, cache, args.excludes, skip_inodes, path, restrict_dev)
        archive.save()
        if args.stats:
            t = datetime.now()
            diff = t - t0
            print('-' * 40)
            print('Archive name: %s' % args.archive.archive)
            print('Archive fingerprint: %s' % hexlify(archive.id).decode('ascii'))
            print('Start time: %s' % t0.strftime('%c'))
            print('End time: %s' % t.strftime('%c'))
            print('Duration: %s' % format_timedelta(diff))
            archive.stats.print_()
            print('-' * 40)
        return self.exit_code

    def _process(self, archive, cache, excludes, skip_inodes, path, restrict_dev):
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
            archive.process_item(path, st)
            try:
                entries = os.listdir(path)
            except OSError as e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    self._process(archive, cache, excludes, skip_inodes,
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
        """Extract archive contents
        """
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.archive.archive,
                          numeric_owner=args.numeric_owner)
        patterns = adjust_patterns(args.paths, args.excludes)
        dirs = []
        for item in archive.iter_items(lambda item: not exclude_path(item[b'path'], patterns), preload=True):
            while dirs and not item[b'path'].startswith(dirs[-1][b'path']):
                archive.extract_item(dirs.pop(-1))
            self.print_verbose(remove_surrogates(item[b'path']))
            try:
                if stat.S_ISDIR(item[b'mode']):
                    dirs.append(item)
                    archive.extract_item(item, restore_attrs=False)
                else:
                    archive.extract_item(item)
            except IOError as e:
                self.print_error('%s: %s', remove_surrogates(item[b'path']), e)

        while dirs:
            archive.extract_item(dirs.pop(-1))
        return self.exit_code

    def do_delete(self, args):
        """Delete archive
        """
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archive = Archive(repository, key, manifest, args.archive.archive, cache=cache)
        archive.delete(cache)
        return self.exit_code

    def do_mount(self, args):
        """Mount archive as a FUSE fileystem
        """
        try:
            from attic.fuse import AtticOperations
        except ImportError:
            self.print_error('the "llfuse" module is required to use this feature')
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error('%s: Mountpoint must be a writable directory' % args.mountpoint)
            return self.exit_code

        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        self.print_verbose("Loading archive metadata...", newline=False)
        archive = Archive(repository, key, manifest, args.archive.archive)
        self.print_verbose('done')
        operations = AtticOperations(key, repository, archive)
        self.print_verbose("Mounting filesystem")
        try:
            operations.mount(args.mountpoint, args.options, args.foreground)
        except RuntimeError:
            # Relevant error message already printed to stderr by fuse
            self.exit_code = 1
        return self.exit_code

    def do_list(self, args):
        """List archive or repository contents
        """
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
                mtime = format_time(datetime.fromtimestamp(item[b'mtime'] / 10**9))
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
                print('%-20s %s' % (archive.metadata[b'name'], to_localtime(archive.ts).strftime('%c')))
        return self.exit_code

    def do_verify(self, args):
        """Verify archive consistency
        """
        repository = self.open_repository(args.archive)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.archive.archive)
        patterns = adjust_patterns(args.paths, args.excludes)

        def start_cb(item):
            self.print_verbose('%s ...', remove_surrogates(item[b'path']), newline=False)

        def result_cb(item, success):
            if success:
                self.print_verbose('OK')
            else:
                self.print_verbose('ERROR')
                self.print_error('%s: verification failed' % remove_surrogates(item[b'path']))
        for item in archive.iter_items(lambda item: not exclude_path(item[b'path'], patterns), preload=True):
            if stat.S_ISREG(item[b'mode']) and b'chunks' in item:
                archive.verify_file(item, start_cb, result_cb)
        return self.exit_code

    def do_info(self, args):
        """Show archive details such as disk space used
        """
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
        stats.print_()
        return self.exit_code

    def do_prune(self, args):
        """Prune repository archives according to specified rules
        """
        repository = self.open_repository(args.repository)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest)
        archives = list(sorted(Archive.list_archives(repository, key, manifest, cache),
                               key=attrgetter('ts'), reverse=True))
        if args.hourly + args.daily + args.weekly + args.monthly + args.yearly == 0:
            self.print_error('At least one of the "hourly", "daily", "weekly", "monthly" or "yearly" '
                             'settings must be specified')
            return 1
        if args.prefix:
            archives = [archive for archive in archives if archive.name.startswith(args.prefix)]
        keep = []
        if args.hourly:
            keep += prune_split(archives, '%Y-%m-%d %H', args.hourly)
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

        for archive in keep:
            self.print_verbose('Keeping archive "%s"' % archive.name)
        for archive in to_delete:
            self.print_verbose('Pruning archive "%s"', archive.name)
            archive.delete(cache)
        return self.exit_code

    def run(self, args=None):
        keys_dir = get_keys_dir()
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
            os.chmod(keys_dir, stat.S_IRWXU)
        cache_dir = get_cache_dir()
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
            os.chmod(cache_dir, stat.S_IRWXU)
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='verbose output')

        # We can't use argpase for "serve" since we don't want it to show up in "Available commands"
        if args and args[0] == 'serve':
            return self.do_serve()

        parser = argparse.ArgumentParser(description='Attic %s - Deduplicated Backups' % __version__)
        subparsers = parser.add_subparsers(title='Available commands')

        subparser = subparsers.add_parser('init', parents=[common_parser],
                                          description=self.do_init.__doc__)
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to create')
        subparser.add_argument('-e', '--encryption', dest='encryption',
                               choices=('none', 'passphrase', 'keyfile'), default='none',
                               help='select encryption method')

        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser],
                                          description=self.do_change_passphrase.__doc__)
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False))

        subparser = subparsers.add_parser('create', parents=[common_parser],
                                          description=self.do_create.__doc__)
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the created archive')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
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

        subparser = subparsers.add_parser('extract', parents=[common_parser],
                                          description=self.do_extract.__doc__)
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='only obey numeric user and group identifiers')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to extract')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to extract')

        subparser = subparsers.add_parser('delete', parents=[common_parser],
                                          description=self.do_delete.__doc__)
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to delete')

        subparser = subparsers.add_parser('list', parents=[common_parser],
                                          description=self.do_list.__doc__)
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('src', metavar='REPOSITORY_OR_ARCHIVE', type=location_validator(),
                               help='repository/archive to list contents of')

        subparser = subparsers.add_parser('mount', parents=[common_parser],
                                          description=self.do_mount.__doc__)
        subparser.set_defaults(func=self.do_mount)
        subparser.add_argument('archive', metavar='ARCHIVE', type=location_validator(archive=True),
                               help='archive to mount')
        subparser.add_argument('mountpoint', metavar='MOUNTPOINT', type=str,
                               help='where to mount filesystem')
        subparser.add_argument('-f', '--foreground', dest='foreground',
                               action='store_true', default=False,
                               help='stay in foreground, do not daemonize')
        subparser.add_argument('-o', dest='options', type=str,
                               help='Extra mount options')

        subparser = subparsers.add_parser('verify', parents=[common_parser],
                                          description=self.do_verify.__doc__)
        subparser.set_defaults(func=self.do_verify)
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to verity integrity of')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to verify')

        subparser = subparsers.add_parser('info', parents=[common_parser],
                                          description=self.do_info.__doc__)
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to display information about')

        subparser = subparsers.add_parser('prune', parents=[common_parser],
                                          description=self.do_prune.__doc__)
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument('-H', '--hourly', dest='hourly', type=int, default=0,
                               help='number of hourly archives to keep')
        subparser.add_argument('-d', '--daily', dest='daily', type=int, default=0,
                               help='number of daily archives to keep')
        subparser.add_argument('-w', '--weekly', dest='weekly', type=int, default=0,
                               help='number of daily archives to keep')
        subparser.add_argument('-m', '--monthly', dest='monthly', type=int, default=0,
                               help='number of monthly archives to keep')
        subparser.add_argument('-y', '--yearly', dest='yearly', type=int, default=0,
                               help='number of yearly archives to keep')
        subparser.add_argument('-p', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')
        subparser.add_argument('repository', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to prune')
        args = parser.parse_args(args or ['-h'])
        self.verbose = args.verbose
        return args.func(args)


def main():
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
