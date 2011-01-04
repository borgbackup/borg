import argparse
from datetime import datetime
import os
import stat
import sys

from .archive import Archive
from .store import Store
from .cache import Cache
from .keychain import Keychain
from .helpers import location_validator, format_file_size, format_time,\
    format_file_mode, IncludePattern, ExcludePattern, exclude_path
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
        if hasattr(sys.stderr, 'encoding'):
            msg = msg.encode(sys.stderr.encoding, 'ignore')
        self.exit_code = 1
        print >> sys.stderr, msg

    def print_verbose(self, msg, *args, **kw):
        if self.verbose:
            msg = args and msg % args or msg
            if hasattr(sys.stdout, 'encoding'):
                msg = msg.encode(sys.stdout.encoding, 'ignore')
            if kw.get('newline', True):
                print msg
            else:
                print msg,

    def do_init(self, args):
        self.open_store(args.store, create=True)
        return self.exit_code

    def do_serve(self, args):
        return StoreServer().serve()

    def do_create(self, args):
        store = self.open_store(args.archive)
        keychain = Keychain(args.keychain)
        try:
            Archive(store, keychain, args.archive.archive)
        except Archive.DoesNotExist:
            pass
        else:
            self.print_error('Archive already exists')
            return self.exit_code
        archive = Archive(store, keychain)
        cache = Cache(store, keychain)
        # Add darc cache dir to inode_skip list
        skip_inodes = set()
        try:
            st = os.stat(Cache.cache_dir_path())
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
            self._process(archive, cache, args.patterns, skip_inodes, unicode(path))
        archive.save(args.archive.archive, cache)
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
        self.print_verbose(path)
        if stat.S_ISDIR(st.st_mode):
            archive.process_dir(path, st)
            try:
                entries = os.listdir(path)
            except OSError, e:
                self.print_error('%s: %s', path, e)
            else:
                for filename in entries:
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
        store = self.open_store(args.archive)
        keychain = Keychain(args.keychain)
        archive = Archive(store, keychain, args.archive.archive)
        dirs = []
        for item in archive.get_items():
            if exclude_path(item['path'], args.patterns):
                continue
            self.print_verbose(item['path'].decode('utf-8'))
            archive.extract_item(item, args.dest)
            if stat.S_ISDIR(item['mode']):
                dirs.append(item)
            if dirs and not item['path'].startswith(dirs[-1]['path']):
                # Extract directories twice to make sure mtime is correctly restored
                archive.extract_item(dirs.pop(-1), args.dest)
        while dirs:
            archive.extract_item(dirs.pop(-1), args.dest)
        return self.exit_code

    def do_delete(self, args):
        store = self.open_store(args.archive)
        keychain = Keychain(args.keychain)
        archive = Archive(store, keychain, args.archive.archive)
        cache = Cache(store, keychain)
        archive.delete(cache)
        return self.exit_code

    def do_list(self, args):
        store = self.open_store(args.src)
        keychain = Keychain(args.keychain)
        if args.src.archive:
            tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 010: '-', 012: 'l', 014: 's'}
            archive = Archive(store, keychain, args.src.archive)
            for item in archive.get_items():
                type = tmap.get(item['mode'] / 4096, '?')
                mode = format_file_mode(item['mode'])
                size = item.get('size', 0)
                mtime = format_time(datetime.fromtimestamp(item['mtime']))
                print '%s%s %-6s %-6s %8d %s %s' % (type, mode, item['user'],
                                                  item['group'], size, mtime, item['path'])
        else:
            for archive in Archive.list_archives(store, keychain):
                print '%(name)-20s %(time)s' % archive.metadata
        return self.exit_code

    def do_verify(self, args):
        store = self.open_store(args.archive)
        keychain = Keychain(args.keychain)
        archive = Archive(store, keychain, args.archive.archive)
        for item in archive.get_items():
            if stat.S_ISREG(item['mode']) and not 'source' in item:
                self.print_verbose('%s ...', item['path'].decode('utf-8'), newline=False)
                if archive.verify_file(item):
                    self.print_verbose('OK')
                else:
                    self.print_verbose('ERROR')
                    self.print_error('%s: verification failed' % item['path'])
        return self.exit_code

    def do_info(self, args):
        store = self.open_store(args.archive)
        keychain = Keychain(args.keychain)
        archive = Archive(store, keychain, args.archive.archive)
        cache = Cache(store, keychain)
        osize, csize, usize = archive.stats(cache)
        print 'Name:', archive.metadata['name']
        print 'Hostname:', archive.metadata['hostname']
        print 'Username:', archive.metadata['username']
        print 'Time:', archive.metadata['time']
        print 'Command line:', ' '.join(archive.metadata['cmdline'])
        print 'Original size:', format_file_size(osize)
        print 'Compressed size:', format_file_size(csize)
        print 'Unique data:', format_file_size(usize)
        return self.exit_code

    def do_init_keychain(self, args):
        return Keychain.generate(args.keychain)

    def do_export_restricted(self, args):
        keychain = Keychain(args.keychain)
        keychain.restrict(args.output)
        return self.exit_code

    def do_keychain_chpass(self, args):
        return Keychain(args.keychain).chpass()

    def run(self, args=None):
        dot_path = os.path.join(os.path.expanduser('~'), '.darc')
        if not os.path.exists(dot_path):
            os.mkdir(dot_path)
        default_keychain = os.path.join(os.path.expanduser('~'),
                                        '.darc', 'keychain')
        parser = argparse.ArgumentParser(description='DARC - Deduplicating Archiver')
        parser.add_argument('-k', '--keychain', dest='keychain', type=str,
                            default=default_keychain,
                            help='Keychain to use')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose output')


        subparsers = parser.add_subparsers(title='Available subcommands')
        subparser = subparsers.add_parser('init-keychain')
        subparser.set_defaults(func=self.do_init_keychain)
        subparser = subparsers.add_parser('export-restricted')
        subparser.add_argument('output', metavar='OUTPUT', type=str,
                               help='Keychain to create')
        subparser.set_defaults(func=self.do_export_restricted)
        subparser = subparsers.add_parser('change-password')
        subparser.set_defaults(func=self.do_keychain_chpass)

        subparser = subparsers.add_parser('init')
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('store', metavar='STORE',
                               type=location_validator(archive=False),
                               help='Store to initialize')

        subparser = subparsers.add_parser('serve')
        subparser.set_defaults(func=self.do_serve)

        subparser = subparsers.add_parser('create')
        subparser.set_defaults(func=self.do_create)
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
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to verity integrity of')

        subparser= subparsers.add_parser('info')
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to display information about')

        args = parser.parse_args(args)
        self.verbose = args.verbose
        return args.func(args)

def main():
    archiver = Archiver()
    sys.exit(archiver.run())

if __name__ == '__main__':
    main()
