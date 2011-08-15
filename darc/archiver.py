import argparse
from datetime import datetime
from operator import attrgetter
import os
import stat
import sys

from .archive import Archive
from .store import Store
from .cache import Cache
from .key import Key
from .helpers import location_validator, format_time, \
    format_file_mode, IncludePattern, ExcludePattern, exclude_path, to_localtime, \
    get_cache_dir, format_timedelta, purge_split
from .remote import StoreServer, RemoteStore

class Archiver(object):

    def __init__(self):
        self.exit_code = 0

    def open_store(self, location, create=False):
        if location.proto == 'ssh':
            return RemoteStore(location, create=create)
        else:
            return Store(location.path, create=create)

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = 1
        print >> sys.stderr, msg

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
        store = self.open_store(args.store, create=True)
        key = Key.create(store, args.store.to_key_filename(),
                         password=args.password)
        return self.exit_code

    def do_create(self, args):
        t0 = datetime.now()
        store = self.open_store(args.archive)
        key = Key(store)
        try:
            Archive(store, key, args.archive.archive)
        except Archive.DoesNotExist:
            pass
        else:
            self.print_error('Archive already exists')
            return self.exit_code
        cache = Cache(store, key)
        archive = Archive(store, key, cache=cache)
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
            self._process(archive, cache, args.patterns, skip_inodes, path)
        archive.save(args.archive.archive, cache)
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

    def _process(self, archive, cache, patterns, skip_inodes, path):
        if exclude_path(path, patterns):
            return
        try:
            st = os.lstat(path)
        except OSError, e:
            self.print_error('%s: %s', path, e)
            return
        if (st.st_ino, st.st_dev) in skip_inodes:
            return
        # Ignore unix sockets
        if stat.S_ISSOCK(st.st_mode):
            return
        self.print_verbose(path)
        if stat.S_ISDIR(st.st_mode):
            archive.process_dir(path, st)
            try:
                entries = os.listdir(path)
            except OSError, e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    self._process(archive, cache, patterns, skip_inodes,
                                  os.path.join(path, filename))
        elif stat.S_ISLNK(st.st_mode):
            archive.process_symlink(path, st)
        elif stat.S_ISFIFO(st.st_mode):
            archive.process_fifo(path, st)
        elif stat.S_ISREG(st.st_mode):
            try:
                archive.process_file(path, st, cache)
            except IOError, e:
                self.print_error('%s: %s', path, e)
        else:
            self.print_error('Unknown file type: %s', path)

    def do_extract(self, args):
        def start_cb(item):
            self.print_verbose(item['path'])
        def extract_cb(item):
            if exclude_path(item['path'], args.patterns):
                return
            if stat.S_ISDIR(item['mode']):
                dirs.append(item)
                archive.extract_item(item, args.dest, start_cb, restore_attrs=False)
            else:
                archive.extract_item(item, args.dest, start_cb)
            if dirs and not item['path'].startswith(dirs[-1]['path']):
                # Extract directories twice to make sure mtime is correctly restored
                archive.extract_item(dirs.pop(-1), args.dest)
        store = self.open_store(args.archive)
        key = Key(store)
        archive = Archive(store, key, args.archive.archive)
        dirs = []
        archive.iter_items(extract_cb)
        store.flush_rpc()
        while dirs:
            archive.extract_item(dirs.pop(-1), args.dest)
        return self.exit_code

    def do_delete(self, args):
        store = self.open_store(args.archive)
        key = Key(store)
        cache = Cache(store, key)
        archive = Archive(store, key, args.archive.archive, cache=cache)
        archive.delete(cache)
        return self.exit_code

    def do_list(self, args):
        def callback(item):
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
            print '%s%s %-6s %-6s %8d %s %s%s' % (type, mode, item['user'],
                                              item['group'], size, mtime,
                                              item['path'], extra)

        store = self.open_store(args.src)
        key = Key(store)
        if args.src.archive:
            tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 010: '-', 012: 'l', 014: 's'}
            archive = Archive(store, key, args.src.archive)
            archive.iter_items(callback)
            store.flush_rpc()
        else:
            for archive in sorted(Archive.list_archives(store, key), key=attrgetter('ts')):
                print '%-20s %s' % (archive.metadata['name'], to_localtime(archive.ts).strftime('%c'))
        return self.exit_code

    def do_verify(self, args):
        store = self.open_store(args.archive)
        key = Key(store)
        archive = Archive(store, key, args.archive.archive)
        def start_cb(item):
            self.print_verbose('%s ...', item['path'], newline=False)
        def result_cb(item, success):
            if success:
                self.print_verbose('OK')
            else:
                self.print_verbose('ERROR')
                self.print_error('%s: verification failed' % item['path'])
        def callback(item):
            if exclude_path(item['path'], args.patterns):
                return
            if stat.S_ISREG(item['mode']) and 'chunks' in item:
                archive.verify_file(item, start_cb, result_cb)
        archive.iter_items(callback)
        store.flush_rpc()
        return self.exit_code

    def do_info(self, args):
        store = self.open_store(args.archive)
        key = Key(store)
        cache = Cache(store, key)
        archive = Archive(store, key, args.archive.archive, cache=cache)
        stats = archive.calc_stats(cache)
        print 'Name:', archive.name
        print 'Fingerprint: %s' % archive.id.encode('hex')
        print 'Hostname:', archive.metadata['hostname']
        print 'Username:', archive.metadata['username']
        print 'Time:', to_localtime(archive.ts).strftime('%c')
        print 'Command line:', ' '.join(archive.metadata['cmdline'])
        stats.print_()
        return self.exit_code

    def do_purge(self, args):
        store = self.open_store(args.store)
        key = Key(store)
        cache = Cache(store, key)
        archives = list(sorted(Archive.list_archives(store, key, cache),
                               key=attrgetter('ts'), reverse=True))
        daily = []
        weekly = []
        monthly = []
        yearly = []
        if args.daily + args.weekly + args.monthly + args.yearly == 0:
            self.print_error('At least one of the "daily", "weekly", "monthly" or "yearly" '
                             'settings must be specified')
            return 1

        if args.prefix:
            archives = [archive for archive in archives if archive.name.startswith(args.prefix)]
        if args.daily:
            daily, archives = purge_split(archives, '%Y-%m-%d', args.daily, reverse=True)
        if args.weekly:
            weekly, archives = purge_split(archives, '%Y-%V', args.weekly, reverse=True)
        if args.monthly:
            monthly, archives = purge_split(archives, '%Y-%m', args.monthly, reverse=True)
        if args.yearly:
            yearly, archives = purge_split(archives, '%Y', args.weekly, reverse=True)
        to_delete = archives

        for i, archive in enumerate(daily):
            self.print_verbose('Keeping "%s" as daily archive %d' % (archive.name, i + 1))
        for i, archive in enumerate(weekly):
            self.print_verbose('Keeping "%s" as weekly archive %d' % (archive.name, i + 1))
        for i, archive in enumerate(monthly):
            self.print_verbose('Keeping "%s" as monthly archive %d' % (archive.name, i + 1))
        for i, archive in enumerate(yearly):
            self.print_verbose('Keeping "%s" as yearly archive %d' % (archive.name, i + 1))
        for archive in to_delete:
            if args.really:
                self.print_verbose('Purging archive "%s"', archive.name)
                archive.delete(cache)
            else:
                print ('Archive "%s" marked for deletion. '
                       'Use the "--really" option to actually delete it'
                       % archive.metadata['name'])
        return self.exit_code

    def run(self, args=None):
        dot_path = os.path.join(os.path.expanduser('~'), '.darc')
        if not os.path.exists(dot_path):
            os.mkdir(dot_path)
            os.mkdir(os.path.join(dot_path, 'keys'))
            os.mkdir(os.path.join(dot_path, 'cache'))
        parser = argparse.ArgumentParser(description='DARC - Deduplicating Archiver')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose output')

        subparsers = parser.add_subparsers(title='Available subcommands')

        subparser = subparsers.add_parser('serve')
        subparser.set_defaults(func=self.do_serve)

        subparser = subparsers.add_parser('init')
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('-p', '--password', dest='password',
                               help='Protect store key with password (Default: prompt)')
        subparser.add_argument('store',
                               type=location_validator(archive=False),
                               help='Store to create')

        subparser = subparsers.add_parser('create')
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
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='Paths to add to archive')

        subparser = subparsers.add_parser('extract')
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('-i', '--include', dest='patterns',
                               type=IncludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('-e', '--exclude', dest='patterns',
                               type=ExcludePattern, action='append',
                               help='Include condition')
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('dest', metavar='DEST', type=str, nargs='?',
                               help='Where to extract files')

        subparser = subparsers.add_parser('delete')
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to delete')

        subparser = subparsers.add_parser('list')
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('src', metavar='SRC', type=location_validator(),
                               help='Store/Archive to list contents of')

        subparser= subparsers.add_parser('verify')
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

        subparser = subparsers.add_parser('info')
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to display information about')

        subparser = subparsers.add_parser('purge')
        subparser.set_defaults(func=self.do_purge)
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
        subparser.add_argument('-r', '--really', dest='really',
                               action='store_true', default=False,
                               help='Actually delete archives')
        subparser.add_argument('store', metavar='STORE',
                               type=location_validator(archive=False),
                               help='Store to purge')

        args = parser.parse_args(args)
        self.verbose = args.verbose
        return args.func(args)

def main():
    archiver = Archiver()
    sys.exit(archiver.run())

if __name__ == '__main__':
    main()
