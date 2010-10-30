import argparse
from datetime import datetime
import os
import stat
import sys

from .archive import Archive
from .store import Store
from .cache import Cache
from .crypto import CryptoManager, KeyChain
from .helpers import location_validator, format_file_size, format_time, format_file_mode


class Archiver(object):

    def __init__(self):
        self.exit_code = 0

    def open_store(self, location):
        return Store(location.path)

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

    def _walk(self, path):
        st = os.lstat(path)
        yield path, st
        if stat.S_ISDIR(st.st_mode):
            for f in os.listdir(path):
                for x in self._walk(os.path.join(path, f)):
                    yield x

    def do_init(self, args):
        Store(args.store.path, create=True)
        return self.exit_code

    def do_create(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        try:
            Archive(store, crypto, args.archive.archive)
        except Archive.DoesNotExist:
            pass
        else:
            self.print_error('Archive already exists')
            return self.exit_code
        archive = Archive(store, crypto)
        cache = Cache(store, archive.crypto)
        for path in args.paths:
            for path, st in self._walk(unicode(path)):
                if stat.S_ISDIR(st.st_mode):
                    archive.process_dir(path, st)
                elif stat.S_ISLNK(st.st_mode):
                    archive.process_symlink(path, st)
                elif stat.S_ISREG(st.st_mode):
                    try:
                        archive.process_file(path, st, cache)
                    except IOError, e:
                        self.print_error('%s: %s', path, e)
                else:
                    self.print_error('Unknown file type: %s', path)
        archive.save(args.archive.archive)
        cache.save()
        return self.exit_code

    def do_extract(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        archive.get_items()
        for item in archive.items:
            self.print_verbose(item['path'])
            archive.extract_item(item, args.dest)
        return self.exit_code

    def do_delete(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        cache = Cache(store, archive.crypto)
        archive.delete(cache)
        return self.exit_code

    def do_list(self, args):
        store = self.open_store(args.src)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        if args.src.archive:
            tmap = {1: 'p', 2: 'c', 4: 'd', 6: 'b', 010: '-', 012: 'l', 014: 's'}
            archive = Archive(store, crypto, args.src.archive)
            archive.get_items()
            for item in archive.items:
                type = tmap.get(item['mode'] / 4096, '?')
                mode = format_file_mode(item['mode'])
                size = item.get('size', 0)
                mtime = format_time(datetime.fromtimestamp(item['mtime']))
                print '%s%s %-6s %-6s %8d %s %s' % (type, mode, item['user'],
                                                  item['group'], size, mtime, item['path'])
        else:
            for archive in Archive.list_archives(store, crypto):
                print '%(name)-20s %(time)s' % archive.metadata
        return self.exit_code

    def do_verify(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        archive.get_items()
        for item in archive.items:
            if stat.S_ISREG(item['mode']) and not 'source' in item:
                self.print_verbose('%s ...', item['path'], newline=False)
                if archive.verify_file(item):
                    self.print_verbose('OK')
                else:
                    self.print_verbose('ERROR')
                    self.print_error('%s: verification failed' % item['path'])
        return self.exit_code

    def do_info(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        cache = Cache(store, archive.crypto)
        osize, csize, usize = archive.stats(cache)
        print 'Name:', archive.metadata['name']
        print 'Hostname:', archive.metadata['hostname']
        print 'Username:', archive.metadata['username']
        print 'Time:', archive.metadata['time']
        print 'Command line:', ' '.join(archive.metadata['cmdline'])
        print 'Number of Files:', len(archive.items)
        print 'Original size:', format_file_size(osize)
        print 'Compressed size:', format_file_size(csize)
        print 'Unique data:', format_file_size(usize)
        return self.exit_code

    def do_keychain_generate(self, args):
        return KeyChain.generate(args.keychain)

    def do_keychain_restrict(self, args):
        return KeyChain(args.keychain).restrict(args.output)

    def do_keychain_chpass(self, args):
        return KeyChain(args.keychain).chpass()

    def run(self, args=None):
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
        subparser = subparsers.add_parser('keychain')
        subsubparsers = subparser.add_subparsers(title='Available subcommands')
        subparser = subsubparsers.add_parser('generate')
        subparser.set_defaults(func=self.do_keychain_generate)
        subparser = subsubparsers.add_parser('restrict')
        subparser.add_argument('output', metavar='OUTPUT', type=str,
                               help='Keychain to create')
        subparser.set_defaults(func=self.do_keychain_restrict)
        subparser = subsubparsers.add_parser('change-password')
        subparser.set_defaults(func=self.do_keychain_chpass)

        subparser = subparsers.add_parser('init')
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('store', metavar='STORE',
                               type=location_validator(archive=False),
                               help='Store to initialize')

        subparser = subparsers.add_parser('create')
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='Paths to add to archive')

        subparser = subparsers.add_parser('extract')
        subparser.set_defaults(func=self.do_extract)
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
