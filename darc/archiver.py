import argparse
from datetime import datetime
from operator import attrgetter
import os
import stat
import sys

from .archive import Archive
from .store import Store
from .cache import Cache
from .key import key_creator
from .helpers import location_validator, format_time, \
    format_file_mode, IncludePattern, ExcludePattern, exclude_path, adjust_patterns, to_localtime, \
    get_cache_dir, format_timedelta, prune_split, Manifest, Location
from .remote import StoreServer, RemoteStore


class Archiver(object):

    def __init__(self):
        self.exit_code = 0

    def open_store(self, location, create=False):
        if location.proto == 'ssh':
            store = RemoteStore(location, create=create)
        else:
            store = Store(location.path, create=create)
        store._location = location
        return store

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = 1
        print >> sys.stderr, 'darc: ' + msg

    def print_verbose(self, msg, *args, **kw):
        if self.verbose:
            msg = args and msg % args or msg
            if kw.get('newline', True):
                print msg
            else:
                print msg,

    def do_serve(self, args):
        return StoreServer().serve()

    def do_init(self, args):
        print 'Initializing store "%s"' % args.store.orig
        store = self.open_store(args.store, create=True)
        key = key_creator(store, args)
        manifest = Manifest()
        manifest.store = store
        manifest.key = key
        manifest.write()
        store.commit()
        return self.exit_code

    def do_change_passphrase(self, args):
        store = self.open_store(Location(args.store))
        manifest, key = Manifest.load(store)
        key.change_passphrase()
        return self.exit_code

    def do_create(self, args):
        t0 = datetime.now()
        store = self.open_store(args.archive)
        manifest, key = Manifest.load(store)
        cache = Cache(store, key, manifest)
        archive = Archive(store, key, manifest, args.archive.archive, cache=cache,
                          create=True, checkpoint_interval=args.checkpoint_interval,
                          numeric_owner=args.numeric_owner)
        # Add darc cache dir to inode_skip list
        skip_inodes = set()
        try:
            st = os.stat(get_cache_dir())
            skip_inodes.add((st.st_ino, st.st_dev))
        except IOError:
            pass
        # Add local store dir to inode_skip list
        if not args.archive.host:
            try:
                st = os.stat(args.archive.path)
                skip_inodes.add((st.st_ino, st.st_dev))
            except IOError:
                pass
        for path in args.paths:
            if args.dontcross:
                try:
                    restrict_dev = os.lstat(path).st_dev
                except OSError, e:
                    self.print_error('%s: %s', path, e)
                    continue
            else:
                restrict_dev = None
            self._process(archive, cache, args.patterns, skip_inodes, path, restrict_dev)
        archive.save()
        if args.stats:
            t = datetime.now()
            diff = t - t0
            print '-' * 40
            print 'Archive name: %s' % args.archive.archive
            print 'Archive fingerprint: %s' % archive.id.encode('hex')
            print 'Start time: %s' % t0.strftime('%c')
            print 'End time: %s' % t.strftime('%c')
            print 'Duration: %s' % format_timedelta(diff)
            archive.stats.print_()
            print '-' * 40
        return self.exit_code

    def _process(self, archive, cache, patterns, skip_inodes, path, restrict_dev):
        if exclude_path(path, patterns):
            return
        try:
            st = os.lstat(path)
        except OSError, e:
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
        self.print_verbose(path)
        if stat.S_ISREG(st.st_mode):
            try:
                archive.process_file(path, st, cache)
            except IOError, e:
                self.print_error('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            archive.process_item(path, st)
            try:
                entries = os.listdir(path)
            except OSError, e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    self._process(archive, cache, patterns, skip_inodes,
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
        store = self.open_store(args.archive)
        manifest, key = Manifest.load(store)
        archive = Archive(store, key, manifest, args.archive.archive,
                          numeric_owner=args.numeric_owner)
        dirs = []
        for item, peek in archive.iter_items(lambda item: not exclude_path(item['path'], args.patterns)):
            while dirs and not item['path'].startswith(dirs[-1]['path']):
                archive.extract_item(dirs.pop(-1), args.dest)
            self.print_verbose(item['path'])
            try:
                if stat.S_ISDIR(item['mode']):
                    dirs.append(item)
                    archive.extract_item(item, args.dest, restore_attrs=False)
                else:
                    archive.extract_item(item, args.dest, peek=peek)
            except IOError, e:
                self.print_error('%s: %s', item['path'], e)

        while dirs:
            archive.extract_item(dirs.pop(-1), args.dest)
        return self.exit_code

    def do_delete(self, args):
        store = self.open_store(args.archive)
        manifest, key = Manifest.load(store)
        cache = Cache(store, key, manifest)
        archive = Archive(store, key, manifest, args.archive.archive, cache=cache)
        archive.delete(cache)
        return self.exit_code

    def do_list(self, args):
        store = self.open_store(args.src)
        manifest, key = Manifest.load(store)
        if args.src.archive:
            tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 010: '-', 012: 'l', 014: 's'}
            archive = Archive(store, key, manifest, args.src.archive)
            for item, _ in archive.iter_items():
                type = tmap.get(item['mode'] / 4096, '?')
                mode = format_file_mode(item['mode'])
                size = 0
                if type == '-':
                    try:
                        size = sum(size for _, size, _ in item['chunks'])
                    except KeyError:
                        pass
                mtime = format_time(datetime.fromtimestamp(item['mtime']))
                if 'source' in item:
                    if type == 'l':
                        extra = ' -> %s' % item['source']
                    else:
                        type = 'h'
                        extra = ' link to %s' % item['source']
                else:
                    extra = ''
                print '%s%s %-6s %-6s %8d %s %s%s' % (type, mode, item['user'] or item['uid'],
                                                  item['group'] or item['gid'], size, mtime,
                                                  item['path'], extra)
        else:
            for archive in sorted(Archive.list_archives(store, key, manifest), key=attrgetter('ts')):
                print '%-20s %s' % (archive.metadata['name'], to_localtime(archive.ts).strftime('%c'))
        return self.exit_code

    def do_verify(self, args):
        store = self.open_store(args.archive)
        manifest, key = Manifest.load(store)
        archive = Archive(store, key, manifest, args.archive.archive)

        def start_cb(item):
            self.print_verbose('%s ...', item['path'], newline=False)

        def result_cb(item, success):
            if success:
                self.print_verbose('OK')
            else:
                self.print_verbose('ERROR')
                self.print_error('%s: verification failed' % item['path'])
        for item, peek in archive.iter_items(lambda item: not exclude_path(item['path'], args.patterns)):
            if stat.S_ISREG(item['mode']) and 'chunks' in item:
                archive.verify_file(item, start_cb, result_cb, peek=peek)
        return self.exit_code

    def do_info(self, args):
        store = self.open_store(args.archive)
        manifest, key = Manifest.load(store)
        cache = Cache(store, key, manifest)
        archive = Archive(store, key, manifest, args.archive.archive, cache=cache)
        stats = archive.calc_stats(cache)
        print 'Name:', archive.name
        print 'Fingerprint: %s' % archive.id.encode('hex')
        print 'Hostname:', archive.metadata['hostname']
        print 'Username:', archive.metadata['username']
        print 'Time:', to_localtime(archive.ts).strftime('%c')
        print 'Command line:', ' '.join(archive.metadata['cmdline'])
        stats.print_()
        return self.exit_code

    def do_prune(self, args):
        store = self.open_store(args.store)
        manifest, key = Manifest.load(store)
        cache = Cache(store, key, manifest)
        archives = list(sorted(Archive.list_archives(store, key, manifest, cache),
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
        dot_path = os.path.join(os.path.expanduser('~'), '.darc')
        if not os.path.exists(dot_path):
            os.mkdir(dot_path)
            os.mkdir(os.path.join(dot_path, 'keys'))
            os.mkdir(os.path.join(dot_path, 'cache'))
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose output')

        parser = argparse.ArgumentParser(description='DARC - Deduplicating Archiver')
        subparsers = parser.add_subparsers(title='Available subcommands')

        subparser = subparsers.add_parser('serve', parents=[common_parser])
        subparser.set_defaults(func=self.do_serve)

        subparser = subparsers.add_parser('init', parents=[common_parser])
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('store',
                               type=location_validator(archive=False),
                               help='Store to create')
        subparser.add_argument('--key-file', dest='keyfile',
                               action='store_true', default=False,
                               help='Encrypt data using key file')
        subparser.add_argument('--passphrase', dest='passphrase',
                               action='store_true', default=False,
                               help='Encrypt data using passphrase derived key')

        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser])
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('store', type=location_validator(archive=False))

        subparser = subparsers.add_parser('create', parents=[common_parser])
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='Print statistics for the created archive')
        subparser.add_argument('-i', '--include', dest='patterns',
                               type=IncludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('-e', '--exclude', dest='patterns',
                               type=ExcludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('-c', '--checkpoint-interval', dest='checkpoint_interval',
                               type=int, default=300, metavar='SECONDS',
                               help='Write checkpointe ever SECONDS seconds (Default: 300)')
        subparser.add_argument('--do-not-cross-mountpoints', dest='dontcross',
                               action='store_true', default=False,
                               help='Do not cross mount points')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='Only store numeric user and group identifiers')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               default=['.'], help='Paths to add to archive')

        subparser = subparsers.add_parser('extract', parents=[common_parser])
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('-i', '--include', dest='patterns',
                               type=IncludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('-e', '--exclude', dest='patterns',
                               type=ExcludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='Only obey numeric user and group identifiers')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('dest', metavar='DEST', type=str, nargs='?',
                               help='Where to extract files')

        subparser = subparsers.add_parser('delete', parents=[common_parser])
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to delete')

        subparser = subparsers.add_parser('list', parents=[common_parser])
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('src', metavar='SRC', type=location_validator(),
                               help='Store/Archive to list contents of')

        subparser = subparsers.add_parser('verify', parents=[common_parser])
        subparser.set_defaults(func=self.do_verify)
        subparser.add_argument('-i', '--include', dest='patterns',
                               type=IncludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('-e', '--exclude', dest='patterns',
                               type=ExcludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to verity integrity of')

        subparser = subparsers.add_parser('info', parents=[common_parser])
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to display information about')

        subparser = subparsers.add_parser('prune', parents=[common_parser])
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument('-H', '--hourly', dest='hourly', type=int, default=0,
                               help='Number of hourly archives to keep')
        subparser.add_argument('-d', '--daily', dest='daily', type=int, default=0,
                               help='Number of daily archives to keep')
        subparser.add_argument('-w', '--weekly', dest='weekly', type=int, default=0,
                               help='Number of daily archives to keep')
        subparser.add_argument('-m', '--monthly', dest='monthly', type=int, default=0,
                               help='Number of monthly archives to keep')
        subparser.add_argument('-y', '--yearly', dest='yearly', type=int, default=0,
                               help='Number of yearly archives to keep')
        subparser.add_argument('-p', '--prefix', dest='prefix', type=str,
                               help='Only consider archive names starting with this prefix')
        subparser.add_argument('store', metavar='STORE',
                               type=location_validator(archive=False),
                               help='Store to prune')

        args = parser.parse_args(args)
        if getattr(args, 'patterns', None):
            adjust_patterns(args.patterns)
        self.verbose = args.verbose
        return args.func(args)


def main():
    archiver = Archiver()
    try:
        exit_code = archiver.run()
    except Store.DoesNotExist:
        archiver.print_error('Error: Store not found')
        exit_code = 1
    except Store.AlreadyExists:
        archiver.print_error('Error: Store already exists')
        exit_code = 1
    except Archive.AlreadyExists, e:
        archiver.print_error('Error: Archive "%s" already exists', e)
        exit_code = 1
    except Archive.DoesNotExist, e:
        archiver.print_error('Error: Archive "%s" does not exist', e)
        exit_code = 1
    except KeyboardInterrupt:
        archiver.print_error('Error: Keyboard interrupt')
        exit_code = 1
    else:
        if exit_code:
            archiver.print_error('Exiting with failure status due to previous errors')
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
