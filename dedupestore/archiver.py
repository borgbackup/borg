import argparse
import logging
import os
import sys

from .archive import Archive
from .bandstore import BandStore
from .cache import Cache
from .crypto import CryptoManager, KeyChain
from .helpers import location_validator, pretty_size, LevelFilter


class Archiver(object):

    def open_store(self, location):
        store = BandStore(location.path)
        return store

    def exit_code_from_logger(self):
        return 1 if self.level_filter.count.get('ERROR') else 0

    def do_create(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto)
        cache = Cache(store, archive.crypto)
        archive.create(args.archive.archive, args.paths, cache)
        return self.exit_code_from_logger()

    def do_extract(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        archive.extract(args.dest)
        return self.exit_code_from_logger()

    def do_delete(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        cache = Cache(store, archive.crypto)
        archive.delete(cache)
        return self.exit_code_from_logger()

    def do_list(self, args):
        store = self.open_store(args.src)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        if args.src.archive:
            archive = Archive(store, crypto, args.src.archive)
            archive.list()
        else:
            for archive in Archive.list_archives(store, crypto):
                print archive.metadata['name']
        return self.exit_code_from_logger()

    def do_verify(self, args):
        store = self.open_store(args.archive)
        keychain = KeyChain(args.keychain)
        crypto = CryptoManager(keychain)
        archive = Archive(store, crypto, args.archive.archive)
        archive.verify()
        return self.exit_code_from_logger()

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
        print 'Original size:', pretty_size(osize)
        print 'Compressed size:', pretty_size(csize)
        print 'Unique data:', pretty_size(usize)
        return self.exit_code_from_logger()

    def do_keychain_generate(self, args):
        return KeyChain.generate(args.keychain)

    def do_keychain_restrict(self, args):
        return KeyChain(args.keychain).restrict(args.output)

    def do_keychain_chpass(self, args):
        return KeyChain(args.keychain).chpass()

    def run(self, args=None):
        default_keychain = os.path.join(os.path.expanduser('~'),
                                        '.dedupestore', 'keychain')
        parser = argparse.ArgumentParser(description='Dedupestore')
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
        if args.verbose:
            logging.basicConfig(level=logging.INFO, format='%(message)s')
        else:
            logging.basicConfig(level=logging.WARNING, format='%(message)s')
        self.level_filter = LevelFilter()
        logging.getLogger('').addFilter(self.level_filter)
        return args.func(args)

def main():
    archiver = Archiver()
    sys.exit(archiver.run())

if __name__ == '__main__':
    main()
