import argparse
import collections
import faulthandler
import functools
import hashlib
import inspect
import logging
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import textwrap
import time
import traceback
from binascii import unhexlify
from datetime import datetime
from itertools import zip_longest

from .logger import create_logger, setup_logging
logger = create_logger()

from . import __version__
from . import helpers
from .archive import Archive, ArchiveChecker, ArchiveRecreater, Statistics, is_special
from .archive import BackupOSError
from .cache import Cache
from .constants import *  # NOQA
from .crc32 import crc32
from .helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from .helpers import Error, NoManifestError
from .helpers import location_validator, archivename_validator, ChunkerParams, CompressionSpec
from .helpers import PrefixSpec, SortBySpec, HUMAN_SORT_KEYS
from .helpers import BaseFormatter, ItemFormatter, ArchiveFormatter, format_time, format_file_size, format_archive
from .helpers import safe_encode, remove_surrogates, bin_to_hex
from .helpers import prune_within, prune_split
from .helpers import to_localtime, timestamp
from .helpers import get_cache_dir
from .helpers import Manifest
from .helpers import update_excludes, check_extension_modules
from .helpers import dir_is_tagged, is_slow_msgpack, yes, sysinfo
from .helpers import log_multi
from .helpers import parse_pattern, PatternMatcher, PathPrefixPattern
from .helpers import signal_handler, raising_signal_handler, SigHup, SigTerm
from .helpers import ErrorIgnoringTextIOWrapper
from .helpers import ProgressIndicatorPercent
from .item import Item
from .key import key_creator, tam_required_file, tam_required, RepoKey, PassphraseKey
from .keymanager import KeyManager
from .platform import get_flags, umount, get_process_id
from .remote import RepositoryServer, RemoteRepository, cache_if_remote
from .repository import Repository
from .selftest import selftest
from .upgrader import AtticRepositoryUpgrader, BorgRepositoryUpgrader


STATS_HEADER = "                       Original size      Compressed size    Deduplicated size"


def argument(args, str_or_bool):
    """If bool is passed, return it. If str is passed, retrieve named attribute from args."""
    if isinstance(str_or_bool, str):
        return getattr(args, str_or_bool)
    if isinstance(str_or_bool, (list, tuple)):
        return any(getattr(args, item) for item in str_or_bool)
    return str_or_bool


def with_repository(fake=False, invert_fake=False, create=False, lock=True, exclusive=False, manifest=True, cache=False):
    """
    Method decorator for subcommand-handling methods: do_XYZ(self, args, repository, …)

    If a parameter (where allowed) is a str the attribute named of args is used instead.
    :param fake: (str or bool) use None instead of repository, don't do anything else
    :param create: create repository
    :param lock: lock repository
    :param exclusive: (str or bool) lock repository exclusively (for writing)
    :param manifest: load manifest and key, pass them as keyword arguments
    :param cache: open cache, pass it as keyword argument (implies manifest)
    """
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, args, **kwargs):
            location = args.location  # note: 'location' must be always present in args
            append_only = getattr(args, 'append_only', False)
            if argument(args, fake) ^ invert_fake:
                return method(self, args, repository=None, **kwargs)
            elif location.proto == 'ssh':
                repository = RemoteRepository(location, create=create, exclusive=argument(args, exclusive),
                                              lock_wait=self.lock_wait, lock=lock, append_only=append_only, args=args)
            else:
                repository = Repository(location.path, create=create, exclusive=argument(args, exclusive),
                                        lock_wait=self.lock_wait, lock=lock,
                                        append_only=append_only)
            with repository:
                if manifest or cache:
                    kwargs['manifest'], kwargs['key'] = Manifest.load(repository)
                if cache:
                    with Cache(repository, kwargs['key'], kwargs['manifest'],
                               do_files=getattr(args, 'cache_files', False),
                               progress=getattr(args, 'progress', False), lock_wait=self.lock_wait) as cache_:
                        return method(self, args, repository=repository, cache=cache_, **kwargs)
                else:
                    return method(self, args, repository=repository, **kwargs)
        return wrapper
    return decorator


def with_archive(method):
    @functools.wraps(method)
    def wrapper(self, args, repository, key, manifest, **kwargs):
        archive = Archive(repository, key, manifest, args.location.archive,
                          numeric_owner=getattr(args, 'numeric_owner', False), cache=kwargs.get('cache'),
                          consider_part_files=args.consider_part_files)
        return method(self, args, repository=repository, manifest=manifest, key=key, archive=archive, **kwargs)
    return wrapper


class Archiver:

    def __init__(self, lock_wait=None, prog=None):
        self.exit_code = EXIT_SUCCESS
        self.lock_wait = lock_wait
        self.parser = self.build_parser(prog)

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_ERROR
        logger.error(msg)

    def print_warning(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_WARNING  # we do not terminate here, so it is a warning
        logger.warning(msg)

    def print_file_status(self, status, path):
        if self.output_list and (self.output_filter is None or status in self.output_filter):
            logging.getLogger('borg.output.list').info("%1s %s", status, remove_surrogates(path))

    @staticmethod
    def compare_chunk_contents(chunks1, chunks2):
        """Compare two chunk iterators (like returned by :meth:`.DownloadPipeline.fetch_many`)"""
        end = object()
        alen = ai = 0
        blen = bi = 0
        while True:
            if not alen - ai:
                a = next(chunks1, end)
                if a is end:
                    return not blen - bi and next(chunks2, end) is end
                a = memoryview(a.data)
                alen = len(a)
                ai = 0
            if not blen - bi:
                b = next(chunks2, end)
                if b is end:
                    return not alen - ai and next(chunks1, end) is end
                b = memoryview(b.data)
                blen = len(b)
                bi = 0
            slicelen = min(alen - ai, blen - bi)
            if a[ai:ai + slicelen] != b[bi:bi + slicelen]:
                return False
            ai += slicelen
            bi += slicelen

    @staticmethod
    def build_matcher(excludes, paths):
        matcher = PatternMatcher()
        if excludes:
            matcher.add(excludes, False)
        include_patterns = []
        if paths:
            include_patterns.extend(parse_pattern(i, PathPrefixPattern) for i in paths)
            matcher.add(include_patterns, True)
        matcher.fallback = not include_patterns
        return matcher, include_patterns

    def do_serve(self, args):
        """Start in server mode. This command is usually not used manually.
        """
        return RepositoryServer(restrict_to_paths=args.restrict_to_paths, append_only=args.append_only).serve()

    @with_repository(create=True, exclusive=True, manifest=False)
    def do_init(self, args, repository):
        """Initialize an empty repository"""
        path = args.location.canonical_path()
        logger.info('Initializing repository at "%s"' % path)
        try:
            key = key_creator(repository, args)
        except (EOFError, KeyboardInterrupt):
            repository.destroy()
            return EXIT_WARNING
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit()
        with Cache(repository, key, manifest, warn_if_unencrypted=False):
            pass
        if key.tam_required:
            tam_file = tam_required_file(repository)
            open(tam_file, 'w').close()
            logger.warning(
                '\n'
                'By default repositories initialized with this version will produce security\n'
                'errors if written to with an older version (up to and including Borg 1.0.8).\n'
                '\n'
                'If you want to use these older versions, you can disable the check by runnning:\n'
                'borg upgrade --disable-tam \'%s\'\n'
                '\n'
                'See https://borgbackup.readthedocs.io/en/stable/changes.html#pre-1-0-9-manifest-spoofing-vulnerability '
                'for details about the security implications.', path)
        return self.exit_code

    @with_repository(exclusive=True, manifest=False)
    def do_check(self, args, repository):
        """Check repository consistency"""
        if args.repair:
            msg = ("'check --repair' is an experimental feature that might result in data loss." +
                   "\n" +
                   "Type 'YES' if you understand this and want to continue: ")
            if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                       truish=('YES', ), retry=False,
                       env_var_override='BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'):
                return EXIT_ERROR
        if args.repo_only and any((args.verify_data, args.first, args.last, args.prefix)):
            self.print_error("--repository-only contradicts --first, --last, --prefix and --verify-data arguments.")
            return EXIT_ERROR
        if not args.archives_only:
            if not repository.check(repair=args.repair, save_space=args.save_space):
                return EXIT_WARNING
        if not args.repo_only and not ArchiveChecker().check(
                repository, repair=args.repair, archive=args.location.archive,
                first=args.first, last=args.last, sort_by=args.sort_by or 'ts', prefix=args.prefix,
                verify_data=args.verify_data, save_space=args.save_space):
            return EXIT_WARNING
        return EXIT_SUCCESS

    @with_repository()
    def do_change_passphrase(self, args, repository, manifest, key):
        """Change repository key file passphrase"""
        if not hasattr(key, 'change_passphrase'):
            print('This repository is not encrypted, cannot change the passphrase.')
            return EXIT_ERROR
        key.change_passphrase()
        logger.info('Key updated')
        if hasattr(key, 'find_key'):
            # print key location to make backing it up easier
            logger.info('Key location: %s', key.find_key())
        return EXIT_SUCCESS

    @with_repository(lock=False, exclusive=False, manifest=False, cache=False)
    def do_key_export(self, args, repository):
        """Export the repository key for backup"""
        manager = KeyManager(repository)
        manager.load_keyblob()
        if args.paper:
            manager.export_paperkey(args.path)
        else:
            if not args.path:
                self.print_error("output file to export key to expected")
                return EXIT_ERROR
            manager.export(args.path)
        return EXIT_SUCCESS

    @with_repository(lock=False, exclusive=False, manifest=False, cache=False)
    def do_key_import(self, args, repository):
        """Import the repository key from backup"""
        manager = KeyManager(repository)
        if args.paper:
            if args.path:
                self.print_error("with --paper import from file is not supported")
                return EXIT_ERROR
            manager.import_paperkey(args)
        else:
            if not args.path:
                self.print_error("input file to import key from expected")
                return EXIT_ERROR
            if not os.path.exists(args.path):
                self.print_error("input file does not exist: " + args.path)
                return EXIT_ERROR
            manager.import_keyfile(args)
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_migrate_to_repokey(self, args, repository):
        """Migrate passphrase -> repokey"""
        manifest_data = repository.get(Manifest.MANIFEST_ID)
        key_old = PassphraseKey.detect(repository, manifest_data)
        key_new = RepoKey(repository)
        key_new.target = repository
        key_new.repository_id = repository.id
        key_new.enc_key = key_old.enc_key
        key_new.enc_hmac_key = key_old.enc_hmac_key
        key_new.id_key = key_old.id_key
        key_new.chunk_seed = key_old.chunk_seed
        key_new.change_passphrase()  # option to change key protection passphrase, save
        logger.info('Key updated')
        return EXIT_SUCCESS

    @with_repository(fake='dry_run', exclusive=True)
    def do_create(self, args, repository, manifest=None, key=None):
        """Create new archive"""
        matcher = PatternMatcher(fallback=True)
        if args.excludes:
            matcher.add(args.excludes, False)

        def create_inner(archive, cache):
            # Add cache dir to inode_skip list
            skip_inodes = set()
            try:
                st = os.stat(get_cache_dir())
                skip_inodes.add((st.st_ino, st.st_dev))
            except OSError:
                pass
            # Add local repository dir to inode_skip list
            if not args.location.host:
                try:
                    st = os.stat(args.location.path)
                    skip_inodes.add((st.st_ino, st.st_dev))
                except OSError:
                    pass
            for path in args.paths:
                if path == '-':  # stdin
                    path = 'stdin'
                    if not dry_run:
                        try:
                            status = archive.process_stdin(path, cache)
                        except BackupOSError as e:
                            status = 'E'
                            self.print_warning('%s: %s', path, e)
                    else:
                        status = '-'
                    self.print_file_status(status, path)
                    continue
                path = os.path.normpath(path)
                try:
                    st = os.lstat(path)
                except OSError as e:
                    self.print_warning('%s: %s', path, e)
                    continue
                if args.one_file_system:
                    restrict_dev = st.st_dev
                else:
                    restrict_dev = None
                self._process(archive, cache, matcher, args.exclude_caches, args.exclude_if_present,
                              args.keep_tag_files, skip_inodes, path, restrict_dev,
                              read_special=args.read_special, dry_run=dry_run, st=st)
            if not dry_run:
                archive.save(comment=args.comment, timestamp=args.timestamp)
                if args.progress:
                    archive.stats.show_progress(final=True)
                if args.stats:
                    log_multi(DASHES,
                              str(archive),
                              DASHES,
                              STATS_HEADER,
                              str(archive.stats),
                              str(cache),
                              DASHES, logger=logging.getLogger('borg.output.stats'))

        self.output_filter = args.output_filter
        self.output_list = args.output_list
        self.ignore_inode = args.ignore_inode
        dry_run = args.dry_run
        t0 = datetime.utcnow()
        t0_monotonic = time.monotonic()
        if not dry_run:
            with Cache(repository, key, manifest, do_files=args.cache_files, progress=args.progress,
                       lock_wait=self.lock_wait) as cache:
                archive = Archive(repository, key, manifest, args.location.archive, cache=cache,
                                  create=True, checkpoint_interval=args.checkpoint_interval,
                                  numeric_owner=args.numeric_owner, noatime=args.noatime, noctime=args.noctime,
                                  progress=args.progress,
                                  chunker_params=args.chunker_params, start=t0, start_monotonic=t0_monotonic,
                                  compression=args.compression, compression_files=args.compression_files)
                create_inner(archive, cache)
        else:
            create_inner(None, None)
        return self.exit_code

    def _process(self, archive, cache, matcher, exclude_caches, exclude_if_present,
                 keep_tag_files, skip_inodes, path, restrict_dev,
                 read_special=False, dry_run=False, st=None):
        if not matcher.match(path):
            self.print_file_status('x', path)
            return
        if st is None:
            try:
                st = os.lstat(path)
            except OSError as e:
                self.print_warning('%s: stat: %s', path, e)
                return
        if (st.st_ino, st.st_dev) in skip_inodes:
            return
        # if restrict_dev is given, we do not want to recurse into a new filesystem,
        # but we WILL save the mountpoint directory (or more precise: the root
        # directory of the mounted filesystem that shadows the mountpoint dir).
        recurse = restrict_dev is None or st.st_dev == restrict_dev
        status = None
        # Ignore if nodump flag is set
        try:
            if get_flags(path, st) & stat.UF_NODUMP:
                self.print_file_status('x', path)
                return
        except OSError as e:
            self.print_warning('%s: flags: %s', path, e)
            return
        if stat.S_ISREG(st.st_mode):
            if not dry_run:
                try:
                    status = archive.process_file(path, st, cache, self.ignore_inode)
                except BackupOSError as e:
                    status = 'E'
                    self.print_warning('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            if recurse:
                tag_paths = dir_is_tagged(path, exclude_caches, exclude_if_present)
                if tag_paths:
                    if keep_tag_files and not dry_run:
                        archive.process_dir(path, st)
                        for tag_path in tag_paths:
                            self._process(archive, cache, matcher, exclude_caches, exclude_if_present,
                                          keep_tag_files, skip_inodes, tag_path, restrict_dev,
                                          read_special=read_special, dry_run=dry_run)
                    return
            if not dry_run:
                status = archive.process_dir(path, st)
            if recurse:
                try:
                    entries = helpers.scandir_inorder(path)
                except OSError as e:
                    status = 'E'
                    self.print_warning('%s: scandir: %s', path, e)
                else:
                    for dirent in entries:
                        normpath = os.path.normpath(dirent.path)
                        self._process(archive, cache, matcher, exclude_caches, exclude_if_present,
                                      keep_tag_files, skip_inodes, normpath, restrict_dev,
                                      read_special=read_special, dry_run=dry_run)
        elif stat.S_ISLNK(st.st_mode):
            if not dry_run:
                if not read_special:
                    status = archive.process_symlink(path, st)
                else:
                    try:
                        st_target = os.stat(path)
                    except OSError:
                        special = False
                    else:
                        special = is_special(st_target.st_mode)
                    if special:
                        status = archive.process_file(path, st_target, cache)
                    else:
                        status = archive.process_symlink(path, st)
        elif stat.S_ISFIFO(st.st_mode):
            if not dry_run:
                if not read_special:
                    status = archive.process_fifo(path, st)
                else:
                    status = archive.process_file(path, st, cache)
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            if not dry_run:
                if not read_special:
                    status = archive.process_dev(path, st)
                else:
                    status = archive.process_file(path, st, cache)
        elif stat.S_ISSOCK(st.st_mode):
            # Ignore unix sockets
            return
        elif stat.S_ISDOOR(st.st_mode):
            # Ignore Solaris doors
            return
        elif stat.S_ISPORT(st.st_mode):
            # Ignore Solaris event ports
            return
        else:
            self.print_warning('Unknown file type: %s', path)
            return
        # Status output
        if status is None:
            if not dry_run:
                status = '?'  # need to add a status code somewhere
            else:
                status = '-'  # dry run, item was not backed up
        self.print_file_status(status, path)

    @staticmethod
    def build_filter(matcher, peek_and_store_hardlink_masters, strip_components):
        if strip_components:
            def item_filter(item):
                matched = matcher.match(item.path) and os.sep.join(item.path.split(os.sep)[strip_components:])
                peek_and_store_hardlink_masters(item, matched)
                return matched
        else:
            def item_filter(item):
                matched = matcher.match(item.path)
                peek_and_store_hardlink_masters(item, matched)
                return matched
        return item_filter

    @with_repository()
    @with_archive
    def do_extract(self, args, repository, manifest, key, archive):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == 'ascii':
            logger.warning('Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.')
            if sys.platform.startswith(('linux', 'freebsd', 'netbsd', 'openbsd', 'darwin', )):
                logger.warning('Hint: You likely need to fix your locale setup. E.g. install locales and use: LANG=en_US.UTF-8')

        matcher, include_patterns = self.build_matcher(args.excludes, args.paths)

        progress = args.progress
        output_list = args.output_list
        dry_run = args.dry_run
        stdout = args.stdout
        sparse = args.sparse
        strip_components = args.strip_components
        dirs = []
        partial_extract = not matcher.empty() or strip_components
        hardlink_masters = {} if partial_extract else None

        def peek_and_store_hardlink_masters(item, matched):
            if (partial_extract and not matched and stat.S_ISREG(item.mode) and
                    item.get('hardlink_master', True) and 'source' not in item):
                hardlink_masters[item.get('path')] = (item.get('chunks'), None)

        filter = self.build_filter(matcher, peek_and_store_hardlink_masters, strip_components)
        if progress:
            pi = ProgressIndicatorPercent(msg='%5.1f%% Extracting: %s', step=0.1)
            pi.output('Calculating size')
            extracted_size = sum(item.file_size(hardlink_masters) for item in archive.iter_items(filter))
            pi.total = extracted_size
        else:
            pi = None

        for item in archive.iter_items(filter, preload=True):
            orig_path = item.path
            if strip_components:
                item.path = os.sep.join(orig_path.split(os.sep)[strip_components:])
            if not args.dry_run:
                while dirs and not item.path.startswith(dirs[-1].path):
                    dir_item = dirs.pop(-1)
                    try:
                        archive.extract_item(dir_item, stdout=stdout)
                    except BackupOSError as e:
                        self.print_warning('%s: %s', remove_surrogates(dir_item.path), e)
            if output_list:
                logging.getLogger('borg.output.list').info(remove_surrogates(orig_path))
            try:
                if dry_run:
                    archive.extract_item(item, dry_run=True, pi=pi)
                else:
                    if stat.S_ISDIR(item.mode):
                        dirs.append(item)
                        archive.extract_item(item, restore_attrs=False)
                    else:
                        archive.extract_item(item, stdout=stdout, sparse=sparse, hardlink_masters=hardlink_masters,
                                             stripped_components=strip_components, original_path=orig_path, pi=pi)
            except BackupOSError as e:
                self.print_warning('%s: %s', remove_surrogates(orig_path), e)

        if not args.dry_run:
            pi = ProgressIndicatorPercent(total=len(dirs), msg='Setting directory permissions %3.0f%%')
            while dirs:
                pi.show()
                dir_item = dirs.pop(-1)
                try:
                    archive.extract_item(dir_item)
                except BackupOSError as e:
                    self.print_warning('%s: %s', remove_surrogates(dir_item.path), e)
        for pattern in include_patterns:
            if pattern.match_count == 0:
                self.print_warning("Include pattern '%s' never matched.", pattern)
        if pi:
            # clear progress output
            pi.finish()
        return self.exit_code

    @with_repository()
    @with_archive
    def do_diff(self, args, repository, manifest, key, archive):
        """Diff contents of two archives"""
        def fetch_and_compare_chunks(chunk_ids1, chunk_ids2, archive1, archive2):
            chunks1 = archive1.pipeline.fetch_many(chunk_ids1)
            chunks2 = archive2.pipeline.fetch_many(chunk_ids2)
            return self.compare_chunk_contents(chunks1, chunks2)

        def sum_chunk_size(item, consider_ids=None):
            if item.get('deleted'):
                return None
            else:
                return sum(c.size for c in item.chunks
                           if consider_ids is None or c.id in consider_ids)

        def get_owner(item):
            if args.numeric_owner:
                return item.uid, item.gid
            else:
                return item.user, item.group

        def get_mode(item):
            if 'mode' in item:
                return stat.filemode(item.mode)
            else:
                return [None]

        def has_hardlink_master(item, hardlink_masters):
            return stat.S_ISREG(item.mode) and item.get('source') in hardlink_masters

        def compare_link(item1, item2):
            # These are the simple link cases. For special cases, e.g. if a
            # regular file is replaced with a link or vice versa, it is
            # indicated in compare_mode instead.
            if item1.get('deleted'):
                return 'added link'
            elif item2.get('deleted'):
                return 'removed link'
            elif 'source' in item1 and 'source' in item2 and item1.source != item2.source:
                return 'changed link'

        def contents_changed(item1, item2):
            if can_compare_chunk_ids:
                return item1.chunks != item2.chunks
            else:
                if sum_chunk_size(item1) != sum_chunk_size(item2):
                    return True
                else:
                    chunk_ids1 = [c.id for c in item1.chunks]
                    chunk_ids2 = [c.id for c in item2.chunks]
                    return not fetch_and_compare_chunks(chunk_ids1, chunk_ids2, archive1, archive2)

        def compare_content(path, item1, item2):
            if contents_changed(item1, item2):
                if item1.get('deleted'):
                    return ('added {:>13}'.format(format_file_size(sum_chunk_size(item2))))
                elif item2.get('deleted'):
                    return ('removed {:>11}'.format(format_file_size(sum_chunk_size(item1))))
                else:
                    chunk_ids1 = {c.id for c in item1.chunks}
                    chunk_ids2 = {c.id for c in item2.chunks}
                    added_ids = chunk_ids2 - chunk_ids1
                    removed_ids = chunk_ids1 - chunk_ids2
                    added = sum_chunk_size(item2, added_ids)
                    removed = sum_chunk_size(item1, removed_ids)
                    return ('{:>9} {:>9}'.format(format_file_size(added, precision=1, sign=True),
                                                 format_file_size(-removed, precision=1, sign=True)))

        def compare_directory(item1, item2):
            if item2.get('deleted') and not item1.get('deleted'):
                return 'removed directory'
            elif item1.get('deleted') and not item2.get('deleted'):
                return 'added directory'

        def compare_owner(item1, item2):
            user1, group1 = get_owner(item1)
            user2, group2 = get_owner(item2)
            if user1 != user2 or group1 != group2:
                return '[{}:{} -> {}:{}]'.format(user1, group1, user2, group2)

        def compare_mode(item1, item2):
            if item1.mode != item2.mode:
                return '[{} -> {}]'.format(get_mode(item1), get_mode(item2))

        def compare_items(output, path, item1, item2, hardlink_masters, deleted=False):
            """
            Compare two items with identical paths.
            :param deleted: Whether one of the items has been deleted
            """
            changes = []

            if has_hardlink_master(item1, hardlink_masters):
                item1 = hardlink_masters[item1.source][0]

            if has_hardlink_master(item2, hardlink_masters):
                item2 = hardlink_masters[item2.source][1]

            if get_mode(item1)[0] == 'l' or get_mode(item2)[0] == 'l':
                changes.append(compare_link(item1, item2))

            if 'chunks' in item1 and 'chunks' in item2:
                changes.append(compare_content(path, item1, item2))

            if get_mode(item1)[0] == 'd' or get_mode(item2)[0] == 'd':
                changes.append(compare_directory(item1, item2))

            if not deleted:
                changes.append(compare_owner(item1, item2))
                changes.append(compare_mode(item1, item2))

            changes = [x for x in changes if x]
            if changes:
                output_line = (remove_surrogates(path), ' '.join(changes))

                if args.sort:
                    output.append(output_line)
                else:
                    print_output(output_line)

        def print_output(line):
            print("{:<19} {}".format(line[1], line[0]))

        def compare_archives(archive1, archive2, matcher):
            def hardlink_master_seen(item):
                return 'source' not in item or not stat.S_ISREG(item.mode) or item.source in hardlink_masters

            def is_hardlink_master(item):
                return item.get('hardlink_master', True) and 'source' not in item

            def update_hardlink_masters(item1, item2):
                if is_hardlink_master(item1) or is_hardlink_master(item2):
                    hardlink_masters[item1.path] = (item1, item2)

            def compare_or_defer(item1, item2):
                update_hardlink_masters(item1, item2)
                if not hardlink_master_seen(item1) or not hardlink_master_seen(item2):
                    deferred.append((item1, item2))
                else:
                    compare_items(output, item1.path, item1, item2, hardlink_masters)

            orphans_archive1 = collections.OrderedDict()
            orphans_archive2 = collections.OrderedDict()
            deferred = []
            hardlink_masters = {}
            output = []

            for item1, item2 in zip_longest(
                    archive1.iter_items(lambda item: matcher.match(item.path)),
                    archive2.iter_items(lambda item: matcher.match(item.path)),
            ):
                if item1 and item2 and item1.path == item2.path:
                    compare_or_defer(item1, item2)
                    continue
                if item1:
                    matching_orphan = orphans_archive2.pop(item1.path, None)
                    if matching_orphan:
                        compare_or_defer(item1, matching_orphan)
                    else:
                        orphans_archive1[item1.path] = item1
                if item2:
                    matching_orphan = orphans_archive1.pop(item2.path, None)
                    if matching_orphan:
                        compare_or_defer(matching_orphan, item2)
                    else:
                        orphans_archive2[item2.path] = item2
            # At this point orphans_* contain items that had no matching partner in the other archive
            deleted_item = Item(
                deleted=True,
                chunks=[],
                mode=0,
            )
            for added in orphans_archive2.values():
                path = added.path
                deleted_item.path = path
                update_hardlink_masters(deleted_item, added)
                compare_items(output, path, deleted_item, added, hardlink_masters, deleted=True)
            for deleted in orphans_archive1.values():
                path = deleted.path
                deleted_item.path = path
                update_hardlink_masters(deleted, deleted_item)
                compare_items(output, path, deleted, deleted_item, hardlink_masters, deleted=True)
            for item1, item2 in deferred:
                assert hardlink_master_seen(item1)
                assert hardlink_master_seen(item2)
                compare_items(output, item1.path, item1, item2, hardlink_masters)

            for line in sorted(output):
                print_output(line)

        archive1 = archive
        archive2 = Archive(repository, key, manifest, args.archive2,
                           consider_part_files=args.consider_part_files)

        can_compare_chunk_ids = archive1.metadata.get('chunker_params', False) == archive2.metadata.get(
            'chunker_params', True) or args.same_chunker_params
        if not can_compare_chunk_ids:
            self.print_warning('--chunker-params might be different between archives, diff will be slow.\n'
                               'If you know for certain that they are the same, pass --same-chunker-params '
                               'to override this check.')

        matcher, include_patterns = self.build_matcher(args.excludes, args.paths)

        compare_archives(archive1, archive2, matcher)

        for pattern in include_patterns:
            if pattern.match_count == 0:
                self.print_warning("Include pattern '%s' never matched.", pattern)
        return self.exit_code

    @with_repository(exclusive=True, cache=True)
    @with_archive
    def do_rename(self, args, repository, manifest, key, cache, archive):
        """Rename an existing archive"""
        archive.rename(args.name)
        manifest.write()
        repository.commit()
        cache.commit()
        return self.exit_code

    @with_repository(exclusive=True, manifest=False)
    def do_delete(self, args, repository):
        """Delete an existing repository or archives"""
        if any((args.location.archive, args.first, args.last, args.prefix)):
            return self._delete_archives(args, repository)
        else:
            return self._delete_repository(args, repository)

    def _delete_archives(self, args, repository):
        """Delete archives"""
        manifest, key = Manifest.load(repository)

        if args.location.archive:
            archive_names = (args.location.archive,)
        else:
            archive_names = tuple(x.name for x in manifest.archives.list_considering(args))
            if not archive_names:
                return self.exit_code

        stats_logger = logging.getLogger('borg.output.stats')
        if args.stats:
            log_multi(DASHES, STATS_HEADER, logger=stats_logger)

        with Cache(repository, key, manifest, progress=args.progress, lock_wait=self.lock_wait) as cache:
            for i, archive_name in enumerate(archive_names, 1):
                logger.info('Deleting {} ({}/{}):'.format(archive_name, i, len(archive_names)))
                archive = Archive(repository, key, manifest, archive_name, cache=cache)
                stats = Statistics()
                archive.delete(stats, progress=args.progress, forced=args.forced)
                manifest.write()
                repository.commit(save_space=args.save_space)
                cache.commit()
                logger.info("Archive deleted.")
                if args.stats:
                    log_multi(stats.summary.format(label='Deleted data:', stats=stats),
                              DASHES, logger=stats_logger)
                if not args.forced and self.exit_code:
                    break
            if args.stats:
                stats_logger.info(str(cache))

        return self.exit_code

    def _delete_repository(self, args, repository):
        """Delete a repository"""
        if not args.cache_only:
            msg = []
            try:
                manifest, key = Manifest.load(repository)
            except NoManifestError:
                msg.append("You requested to completely DELETE the repository *including* all archives it may "
                           "contain.")
                msg.append("This repository seems to have no manifest, so we can't tell anything about its "
                           "contents.")
            else:
                msg.append("You requested to completely DELETE the repository *including* all archives it "
                           "contains:")
                for archive_info in manifest.archives.list(sort_by=['ts']):
                    msg.append(format_archive(archive_info))
            msg.append("Type 'YES' if you understand this and want to continue: ")
            msg = '\n'.join(msg)
            if not yes(msg, false_msg="Aborting.", invalid_msg='Invalid answer, aborting.', truish=('YES',),
                       retry=False, env_var_override='BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'):
                self.exit_code = EXIT_ERROR
                return self.exit_code
            repository.destroy()
            logger.info("Repository deleted.")
        Cache.destroy(repository)
        logger.info("Cache deleted.")
        return self.exit_code

    @with_repository()
    def do_mount(self, args, repository, manifest, key):
        """Mount archive or an entire repository as a FUSE filesystem"""
        try:
            from .fuse import FuseOperations
        except ImportError as e:
            self.print_error('Loading fuse support failed [ImportError: %s]' % str(e))
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error('%s: Mountpoint must be a writable directory' % args.mountpoint)
            return self.exit_code

        with cache_if_remote(repository) as cached_repo:
            operations = FuseOperations(key, repository, manifest, args, cached_repo)
            logger.info("Mounting filesystem")
            try:
                operations.mount(args.mountpoint, args.options, args.foreground)
            except RuntimeError:
                # Relevant error message already printed to stderr by fuse
                self.exit_code = EXIT_ERROR
        return self.exit_code

    def do_umount(self, args):
        """un-mount the FUSE filesystem"""
        return umount(args.mountpoint)

    @with_repository()
    def do_list(self, args, repository, manifest, key):
        """List archive or repository contents"""
        if not hasattr(sys.stdout, 'buffer'):
            # This is a shim for supporting unit tests replacing sys.stdout with e.g. StringIO,
            # which doesn't have an underlying buffer (= lower file object).
            def write(bytestring):
                sys.stdout.write(bytestring.decode('utf-8', errors='replace'))
        else:
            write = sys.stdout.buffer.write

        if args.location.archive:
            return self._list_archive(args, repository, manifest, key, write)
        else:
            return self._list_repository(args, manifest, write)

    def _list_archive(self, args, repository, manifest, key, write):
        matcher, _ = self.build_matcher(args.excludes, args.paths)
        with Cache(repository, key, manifest, lock_wait=self.lock_wait) as cache:
            archive = Archive(repository, key, manifest, args.location.archive, cache=cache,
                              consider_part_files=args.consider_part_files)
            if args.format is not None:
                format = args.format
            elif args.short:
                format = "{path}{NL}"
            else:
                format = "{mode} {user:6} {group:6} {size:8} {isomtime} {path}{extra}{NL}"
            formatter = ItemFormatter(archive, format)

            for item in archive.iter_items(lambda item: matcher.match(item.path)):
                write(safe_encode(formatter.format_item(item)))
        return self.exit_code

    def _list_repository(self, args, manifest, write):
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}{NL}"
        else:
            format = "{archive:<36} {time} [{id}]{NL}"
        formatter = ArchiveFormatter(format)

        for archive_info in manifest.archives.list_considering(args):
            write(safe_encode(formatter.format_item(archive_info)))

        return self.exit_code

    @with_repository(cache=True)
    def do_info(self, args, repository, manifest, key, cache):
        """Show archive details such as disk space used"""
        if any((args.location.archive, args.first, args.last, args.prefix)):
            return self._info_archives(args, repository, manifest, key, cache)
        else:
            return self._info_repository(repository, key, cache)

    def _info_archives(self, args, repository, manifest, key, cache):
        def format_cmdline(cmdline):
            return remove_surrogates(' '.join(shlex.quote(x) for x in cmdline))

        if args.location.archive:
            archive_names = (args.location.archive,)
        else:
            archive_names = tuple(x.name for x in manifest.archives.list_considering(args))
            if not archive_names:
                return self.exit_code

        for i, archive_name in enumerate(archive_names, 1):
            archive = Archive(repository, key, manifest, archive_name, cache=cache,
                              consider_part_files=args.consider_part_files)
            stats = archive.calc_stats(cache)
            print('Archive name: %s' % archive.name)
            print('Archive fingerprint: %s' % archive.fpr)
            print('Comment: %s' % archive.metadata.get('comment', ''))
            print('Hostname: %s' % archive.metadata.hostname)
            print('Username: %s' % archive.metadata.username)
            print('Time (start): %s' % format_time(to_localtime(archive.ts)))
            print('Time (end):   %s' % format_time(to_localtime(archive.ts_end)))
            print('Duration: %s' % archive.duration_from_meta)
            print('Number of files: %d' % stats.nfiles)
            print('Command line: %s' % format_cmdline(archive.metadata.cmdline))
            print(DASHES)
            print(STATS_HEADER)
            print(str(stats))
            print(str(cache))
            if self.exit_code:
                break
            if len(archive_names) - i:
                print()
        return self.exit_code

    def _info_repository(self, repository, key, cache):
        print('Repository ID: %s' % bin_to_hex(repository.id))
        if key.NAME == 'plaintext':
            encrypted = 'No'
        else:
            encrypted = 'Yes (%s)' % key.NAME
        print('Encrypted: %s' % encrypted)
        if key.NAME.startswith('key file'):
            print('Key file: %s' % key.find_key())
        print('Cache: %s' % cache.path)
        print('Security dir: %s' % cache.security_manager.dir)
        print(DASHES)
        print(STATS_HEADER)
        print(str(cache))
        return self.exit_code

    @with_repository(exclusive=True)
    def do_prune(self, args, repository, manifest, key):
        """Prune repository archives according to specified rules"""
        if not any((args.secondly, args.minutely, args.hourly, args.daily,
                    args.weekly, args.monthly, args.yearly, args.within)):
            self.print_error('At least one of the "keep-within", "keep-last", '
                             '"keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", '
                             '"keep-weekly", "keep-monthly" or "keep-yearly" settings must be specified.')
            return self.exit_code
        archives_checkpoints = manifest.archives.list(sort_by=['ts'], reverse=True)  # just a ArchiveInfo list
        if args.prefix:
            archives_checkpoints = [arch for arch in archives_checkpoints if arch.name.startswith(args.prefix)]
        is_checkpoint = re.compile(r'\.checkpoint(\.\d+)?$').search
        checkpoints = [arch for arch in archives_checkpoints if is_checkpoint(arch.name)]
        # keep the latest checkpoint, if there is no later non-checkpoint archive
        if archives_checkpoints and checkpoints and archives_checkpoints[0] is checkpoints[0]:
            keep_checkpoints = checkpoints[:1]
        else:
            keep_checkpoints = []
        checkpoints = set(checkpoints)
        # ignore all checkpoint archives to avoid keeping one (which is an incomplete backup)
        # that is newer than a successfully completed backup - and killing the successful backup.
        archives = [arch for arch in archives_checkpoints if arch not in checkpoints]
        keep = []
        if args.within:
            keep += prune_within(archives, args.within)
        if args.secondly:
            keep += prune_split(archives, '%Y-%m-%d %H:%M:%S', args.secondly, keep)
        if args.minutely:
            keep += prune_split(archives, '%Y-%m-%d %H:%M', args.minutely, keep)
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
        to_delete = (set(archives) | checkpoints) - (set(keep) | set(keep_checkpoints))
        stats = Statistics()
        with Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait) as cache:
            list_logger = logging.getLogger('borg.output.list')
            if args.output_list:
                # set up counters for the progress display
                to_delete_len = len(to_delete)
                archives_deleted = 0
            for archive in archives_checkpoints:
                if archive in to_delete:
                    if args.dry_run:
                        if args.output_list:
                            list_logger.info('Would prune:     %s' % format_archive(archive))
                    else:
                        if args.output_list:
                            archives_deleted += 1
                            list_logger.info('Pruning archive: %s (%d/%d)' % (format_archive(archive),
                                                                              archives_deleted, to_delete_len))
                        Archive(repository, key, manifest, archive.name, cache,
                                progress=args.progress).delete(stats, forced=args.forced)
                else:
                    if args.output_list:
                        list_logger.info('Keeping archive: %s' % format_archive(archive))
            if to_delete and not args.dry_run:
                manifest.write()
                repository.commit(save_space=args.save_space)
                cache.commit()
            if args.stats:
                log_multi(DASHES,
                          STATS_HEADER,
                          stats.summary.format(label='Deleted data:', stats=stats),
                          str(cache),
                          DASHES, logger=logging.getLogger('borg.output.stats'))
        return self.exit_code

    @with_repository(fake=('tam', 'disable_tam'), invert_fake=True, manifest=False, exclusive=True)
    def do_upgrade(self, args, repository, manifest=None, key=None):
        """upgrade a repository from a previous version"""
        if args.tam:
            manifest, key = Manifest.load(repository, force_tam_not_required=args.force)

            if not hasattr(key, 'change_passphrase'):
                print('This repository is not encrypted, cannot enable TAM.')
                return EXIT_ERROR

            if not manifest.tam_verified or not manifest.config.get(b'tam_required', False):
                # The standard archive listing doesn't include the archive ID like in borg 1.1.x
                print('Manifest contents:')
                for archive_info in manifest.archives.list(sort_by=['ts']):
                    print(format_archive(archive_info), '[%s]' % bin_to_hex(archive_info.id))
                manifest.config[b'tam_required'] = True
                manifest.write()
                repository.commit()
            if not key.tam_required:
                key.tam_required = True
                key.change_passphrase(key._passphrase)
                print('Key updated')
                if hasattr(key, 'find_key'):
                    print('Key location:', key.find_key())
            if not tam_required(repository):
                tam_file = tam_required_file(repository)
                open(tam_file, 'w').close()
                print('Updated security database')
        elif args.disable_tam:
            manifest, key = Manifest.load(repository, force_tam_not_required=True)
            if tam_required(repository):
                os.unlink(tam_required_file(repository))
            if key.tam_required:
                key.tam_required = False
                key.change_passphrase(key._passphrase)
                print('Key updated')
                if hasattr(key, 'find_key'):
                    print('Key location:', key.find_key())
            manifest.config[b'tam_required'] = False
            manifest.write()
            repository.commit()
        else:
            # mainly for upgrades from Attic repositories,
            # but also supports borg 0.xx -> 1.0 upgrade.

            repo = AtticRepositoryUpgrader(args.location.path, create=False)
            try:
                repo.upgrade(args.dry_run, inplace=args.inplace, progress=args.progress)
            except NotImplementedError as e:
                print("warning: %s" % e)
            repo = BorgRepositoryUpgrader(args.location.path, create=False)
            try:
                repo.upgrade(args.dry_run, inplace=args.inplace, progress=args.progress)
            except NotImplementedError as e:
                print("warning: %s" % e)
        return self.exit_code

    @with_repository(cache=True, exclusive=True)
    def do_recreate(self, args, repository, manifest, key, cache):
        """Re-create archives"""
        msg = ("recreate is an experimental feature.\n"
               "Type 'YES' if you understand this and want to continue: ")
        if not yes(msg, false_msg="Aborting.", truish=('YES',),
                   env_var_override='BORG_RECREATE_I_KNOW_WHAT_I_AM_DOING'):
            return EXIT_ERROR

        matcher, include_patterns = self.build_matcher(args.excludes, args.paths)
        self.output_list = args.output_list
        self.output_filter = args.output_filter

        recreater = ArchiveRecreater(repository, manifest, key, cache, matcher,
                                     exclude_caches=args.exclude_caches, exclude_if_present=args.exclude_if_present,
                                     keep_tag_files=args.keep_tag_files, chunker_params=args.chunker_params,
                                     compression=args.compression, compression_files=args.compression_files,
                                     always_recompress=args.always_recompress,
                                     progress=args.progress, stats=args.stats,
                                     file_status_printer=self.print_file_status,
                                     checkpoint_interval=args.checkpoint_interval,
                                     dry_run=args.dry_run)

        if args.location.archive:
            name = args.location.archive
            if recreater.is_temporary_archive(name):
                self.print_error('Refusing to work on temporary archive of prior recreate: %s', name)
                return self.exit_code
            recreater.recreate(name, args.comment, args.target)
        else:
            if args.target is not None:
                self.print_error('--target: Need to specify single archive')
                return self.exit_code
            for archive in manifest.archives.list(sort_by=['ts']):
                name = archive.name
                if recreater.is_temporary_archive(name):
                    continue
                print('Processing', name)
                recreater.recreate(name, args.comment)
        if not args.dry_run:
            manifest.write()
            repository.commit()
            cache.commit()
        return self.exit_code

    @with_repository(manifest=False, exclusive=True)
    def do_with_lock(self, args, repository):
        """run a user specified command with the repository lock held"""
        # for a new server, this will immediately take an exclusive lock.
        # to support old servers, that do not have "exclusive" arg in open()
        # RPC API, we also do it the old way:
        # re-write manifest to start a repository transaction - this causes a
        # lock upgrade to exclusive for remote (and also for local) repositories.
        # by using manifest=False in the decorator, we avoid having to require
        # the encryption key (and can operate just with encrypted data).
        data = repository.get(Manifest.MANIFEST_ID)
        repository.put(Manifest.MANIFEST_ID, data)
        try:
            # we exit with the return code we get from the subprocess
            return subprocess.call([args.command] + args.args)
        finally:
            repository.rollback()

    def do_debug_info(self, args):
        """display system information for debugging / bug reports"""
        print(sysinfo())

        # Additional debug information
        print('CRC implementation:', crc32.__name__)
        print('Process ID:', get_process_id())
        return EXIT_SUCCESS

    @with_repository()
    def do_debug_dump_archive_items(self, args, repository, manifest, key):
        """dump (decrypted, decompressed) archive items metadata (not: data)"""
        archive = Archive(repository, key, manifest, args.location.archive,
                          consider_part_files=args.consider_part_files)
        for i, item_id in enumerate(archive.metadata.items):
            _, data = key.decrypt(item_id, repository.get(item_id))
            filename = '%06d_%s.items' % (i, bin_to_hex(item_id))
            print('Dumping', filename)
            with open(filename, 'wb') as fd:
                fd.write(data)
        print('Done.')
        return EXIT_SUCCESS

    @with_repository()
    def do_debug_dump_repo_objs(self, args, repository, manifest, key):
        """dump (decrypted, decompressed) repo objects"""
        marker = None
        i = 0
        while True:
            result = repository.list(limit=10000, marker=marker)
            if not result:
                break
            marker = result[-1]
            for id in result:
                cdata = repository.get(id)
                give_id = id if id != Manifest.MANIFEST_ID else None
                _, data = key.decrypt(give_id, cdata)
                filename = '%06d_%s.obj' % (i, bin_to_hex(id))
                print('Dumping', filename)
                with open(filename, 'wb') as fd:
                    fd.write(data)
                i += 1
        print('Done.')
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_debug_get_obj(self, args, repository):
        """get object contents from the repository and write it into file"""
        hex_id = args.id
        try:
            id = unhexlify(hex_id)
        except ValueError:
            print("object id %s is invalid." % hex_id)
        else:
            try:
                data = repository.get(id)
            except Repository.ObjectNotFound:
                print("object %s not found." % hex_id)
            else:
                with open(args.path, "wb") as f:
                    f.write(data)
                print("object %s fetched." % hex_id)
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True)
    def do_debug_put_obj(self, args, repository):
        """put file(s) contents into the repository"""
        for path in args.paths:
            with open(path, "rb") as f:
                data = f.read()
            h = hashlib.sha256(data)  # XXX hardcoded
            repository.put(h.digest(), data)
            print("object %s put." % h.hexdigest())
        repository.commit()
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True)
    def do_debug_delete_obj(self, args, repository):
        """delete the objects with the given IDs from the repo"""
        modified = False
        for hex_id in args.ids:
            try:
                id = unhexlify(hex_id)
            except ValueError:
                print("object id %s is invalid." % hex_id)
            else:
                try:
                    repository.delete(id)
                    modified = True
                    print("object %s deleted." % hex_id)
                except Repository.ObjectNotFound:
                    print("object %s not found." % hex_id)
        if modified:
            repository.commit()
        print('Done.')
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True, cache=True)
    def do_debug_refcount_obj(self, args, repository, manifest, key, cache):
        """display refcounts for the objects with the given IDs"""
        for hex_id in args.ids:
            try:
                id = unhexlify(hex_id)
            except ValueError:
                print("object id %s is invalid." % hex_id)
            else:
                try:
                    refcount = cache.chunks[id][0]
                    print("object %s has %d referrers [info from chunks cache]." % (hex_id, refcount))
                except KeyError:
                    print("object %s not found [info from chunks cache]." % hex_id)
        return EXIT_SUCCESS

    @with_repository(lock=False, manifest=False)
    def do_break_lock(self, args, repository):
        """Break the repository lock (e.g. in case it was left by a dead borg."""
        repository.break_lock()
        Cache.break_lock(repository)
        return self.exit_code

    helptext = collections.OrderedDict()
    helptext['patterns'] = textwrap.dedent('''
        Exclusion patterns support four separate styles, fnmatch, shell, regular
        expressions and path prefixes. By default, fnmatch is used. If followed
        by a colon (':') the first two characters of a pattern are used as a
        style selector. Explicit style selection is necessary when a
        non-default style is desired or when the desired pattern starts with
        two alphanumeric characters followed by a colon (i.e. `aa:something/*`).

        `Fnmatch <https://docs.python.org/3/library/fnmatch.html>`_, selector `fm:`

            This is the default style.  These patterns use a variant of shell
            pattern syntax, with '*' matching any number of characters, '?'
            matching any single character, '[...]' matching any single
            character specified, including ranges, and '[!...]' matching any
            character not specified. For the purpose of these patterns, the
            path separator ('\\' for Windows and '/' on other systems) is not
            treated specially. Wrap meta-characters in brackets for a literal
            match (i.e. `[?]` to match the literal character `?`). For a path
            to match a pattern, it must completely match from start to end, or
            must match from the start to just before a path separator. Except
            for the root path, paths will never end in the path separator when
            matching is attempted.  Thus, if a given pattern ends in a path
            separator, a '*' is appended before matching is attempted.

        Shell-style patterns, selector `sh:`

            Like fnmatch patterns these are similar to shell patterns. The difference
            is that the pattern may include `**/` for matching zero or more directory
            levels, `*` for matching zero or more arbitrary characters with the
            exception of any path separator.

        Regular expressions, selector `re:`

            Regular expressions similar to those found in Perl are supported. Unlike
            shell patterns regular expressions are not required to match the complete
            path and any substring match is sufficient. It is strongly recommended to
            anchor patterns to the start ('^'), to the end ('$') or both. Path
            separators ('\\' for Windows and '/' on other systems) in paths are
            always normalized to a forward slash ('/') before applying a pattern. The
            regular expression syntax is described in the `Python documentation for
            the re module <https://docs.python.org/3/library/re.html>`_.

        Prefix path, selector `pp:`

            This pattern style is useful to match whole sub-directories. The pattern
            `pp:/data/bar` matches `/data/bar` and everything therein.

        Exclusions can be passed via the command line option `--exclude`. When used
        from within a shell the patterns should be quoted to protect them from
        expansion.

        The `--exclude-from` option permits loading exclusion patterns from a text
        file with one pattern per line. Lines empty or starting with the number sign
        ('#') after removing whitespace on both ends are ignored. The optional style
        selector prefix is also supported for patterns loaded from a file. Due to
        whitespace removal paths with whitespace at the beginning or end can only be
        excluded using regular expressions.

        Examples::

            # Exclude '/home/user/file.o' but not '/home/user/file.odt':
            $ borg create -e '*.o' backup /

            # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
            # not '/home/user/importantjunk' or '/etc/junk':
            $ borg create -e '/home/*/junk' backup /

            # Exclude the contents of '/home/user/cache' but not the directory itself:
            $ borg create -e /home/user/cache/ backup /

            # The file '/home/user/cache/important' is *not* backed up:
            $ borg create -e /home/user/cache/ backup / /home/user/cache/important

            # The contents of directories in '/home' are not backed up when their name
            # ends in '.tmp'
            $ borg create --exclude 're:^/home/[^/]+\.tmp/' backup /

            # Load exclusions from file
            $ cat >exclude.txt <<EOF
            # Comment line
            /home/*/junk
            *.tmp
            fm:aa:something/*
            re:^/home/[^/]\.tmp/
            sh:/home/*/.thumbnails
            EOF
            $ borg create --exclude-from exclude.txt backup /\n\n''')
    helptext['placeholders'] = textwrap.dedent('''
        Repository (or Archive) URLs, --prefix and --remote-path values support these
        placeholders:

        {hostname}

            The (short) hostname of the machine.

        {fqdn}

            The full name of the machine.

        {now}

            The current local date and time, by default in ISO-8601 format.
            You can also supply your own `format string <https://docs.python.org/3.4/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {now:%Y-%m-%d_%H:%M:%S}

        {utcnow}

            The current UTC date and time, by default in ISO-8601 format.
            You can also supply your own `format string <https://docs.python.org/3.4/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {utcnow:%Y-%m-%d_%H:%M:%S}

        {user}

            The user name (or UID, if no name is available) of the user running borg.

        {pid}

            The current process ID.

        {borgversion}

            The version of borg, e.g.: 1.0.8rc1

        {borgmajor}

            The version of borg, only the major version, e.g.: 1

        {borgminor}

            The version of borg, only major and minor version, e.g.: 1.0

        {borgpatch}

            The version of borg, only major, minor and patch version, e.g.: 1.0.8

        Examples::

            borg create /path/to/repo::{hostname}-{user}-{utcnow} ...
            borg create /path/to/repo::{hostname}-{now:%Y-%m-%d_%H:%M:%S} ...
            borg prune --prefix '{hostname}-' ...\n\n''')
    helptext['compression'] = textwrap.dedent('''
        Compression is off by default, if you want some, you have to specify what you want.

        Valid compression specifiers are:

        none

            Do not compress. (default)

        lz4

            Use lz4 compression. High speed, low compression.

        zlib[,L]

            Use zlib ("gz") compression. Medium speed, medium compression.
            If you do not explicitely give the compression level L (ranging from 0
            to 9), it will use level 6.
            Giving level 0 (means "no compression", but still has zlib protocol
            overhead) is usually pointless, you better use "none" compression.

        lzma[,L]

            Use lzma ("xz") compression. Low speed, high compression.
            If you do not explicitely give the compression level L (ranging from 0
            to 9), it will use level 6.
            Giving levels above 6 is pointless and counterproductive because it does
            not compress better due to the buffer size used by borg - but it wastes
            lots of CPU cycles and RAM.

        auto,C[,L]

            Use a built-in heuristic to decide per chunk whether to compress or not.
            The heuristic tries with lz4 whether the data is compressible.
            For incompressible data, it will not use compression (uses "none").
            For compressible data, it uses the given C[,L] compression - with C[,L]
            being any valid compression specifier.

        The decision about which compression to use is done by borg like this:

        1. find a compression specifier (per file):
           match the path/filename against all patterns in all --compression-from
           files (if any). If a pattern matches, use the compression spec given for
           that pattern. If no pattern matches (and also if you do not give any
           --compression-from option), default to the compression spec given by
           --compression. See docs/misc/compression.conf for an example config.

        2. if the found compression spec is not "auto", the decision is taken:
           use the found compression spec.

        3. if the found compression spec is "auto", test compressibility of each
           chunk using lz4.
           If it is compressible, use the C,[L] compression spec given within the
           "auto" specifier. If it is not compressible, use no compression.

        Examples::

            borg create --compression lz4 REPO::ARCHIVE data
            borg create --compression zlib REPO::ARCHIVE data
            borg create --compression zlib,1 REPO::ARCHIVE data
            borg create --compression auto,lzma,6 REPO::ARCHIVE data
            borg create --compression-from compression.conf --compression auto,lzma ...

        compression.conf has entries like::

            # example config file for --compression-from option
            #
            # Format of non-comment / non-empty lines:
            # <compression-spec>:<path/filename pattern>
            # compression-spec is same format as for --compression option
            # path/filename pattern is same format as for --exclude option
            none:*.gz
            none:*.zip
            none:*.mp3
            none:*.ogg

        General remarks:

        It is no problem to mix different compression methods in one repo,
        deduplication is done on the source data chunks (not on the compressed
        or encrypted data).

        If some specific chunk was once compressed and stored into the repo, creating
        another backup that also uses this chunk will not change the stored chunk.
        So if you use different compression specs for the backups, whichever stores a
        chunk first determines its compression. See also borg recreate.\n\n''')

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

    def do_subcommand_help(self, parser, args):
        """display infos about subcommand"""
        parser.print_help()
        return EXIT_SUCCESS

    def preprocess_args(self, args):
        deprecations = [
            # ('--old', '--new', 'Warning: "--old" has been deprecated. Use "--new" instead.'),
            ('--list-format', '--format', 'Warning: "--list-format" has been deprecated. Use "--format" instead.'),
        ]
        for i, arg in enumerate(args[:]):
            for old_name, new_name, warning in deprecations:
                if arg.startswith(old_name):
                    args[i] = arg.replace(old_name, new_name)
                    print(warning, file=sys.stderr)
        return args

    def build_parser(self, prog=None):
        common_parser = argparse.ArgumentParser(add_help=False, prog=prog)

        common_group = common_parser.add_argument_group('Common options')
        common_group.add_argument('-h', '--help', action='help', help='show this help message and exit')
        common_group.add_argument('--critical', dest='log_level',
                                  action='store_const', const='critical', default='warning',
                                  help='work on log level CRITICAL')
        common_group.add_argument('--error', dest='log_level',
                                  action='store_const', const='error', default='warning',
                                  help='work on log level ERROR')
        common_group.add_argument('--warning', dest='log_level',
                                  action='store_const', const='warning', default='warning',
                                  help='work on log level WARNING (default)')
        common_group.add_argument('--info', '-v', '--verbose', dest='log_level',
                                  action='store_const', const='info', default='warning',
                                  help='work on log level INFO')
        common_group.add_argument('--debug', dest='log_level',
                                  action='store_const', const='debug', default='warning',
                                  help='enable debug output, work on log level DEBUG')
        common_group.add_argument('--debug-topic', dest='debug_topics',
                                  action='append', metavar='TOPIC', default=[],
                                  help='enable TOPIC debugging (can be specified multiple times). '
                                       'The logger path is borg.debug.<TOPIC> if TOPIC is not fully qualified.')
        common_group.add_argument('--lock-wait', dest='lock_wait', type=int, metavar='N', default=1,
                                  help='wait for the lock, but max. N seconds (default: %(default)d).')
        common_group.add_argument('--show-version', dest='show_version', action='store_true', default=False,
                                  help='show/log the borg version')
        common_group.add_argument('--show-rc', dest='show_rc', action='store_true', default=False,
                                  help='show/log the return code (rc)')
        common_group.add_argument('--no-files-cache', dest='cache_files', action='store_false',
                                  help='do not load/update the file metadata cache used to detect unchanged files')
        common_group.add_argument('--umask', dest='umask', type=lambda s: int(s, 8), default=UMASK_DEFAULT, metavar='M',
                                  help='set umask to M (local and remote, default: %(default)04o)')
        common_group.add_argument('--remote-path', dest='remote_path', metavar='PATH',
                                  help='set remote path to executable (default: "borg")')
        common_group.add_argument('--remote-ratelimit', dest='remote_ratelimit', type=int, metavar='rate',
                                  help='set remote network upload rate limit in kiByte/s (default: 0=unlimited)')
        common_group.add_argument('--consider-part-files', dest='consider_part_files',
                                  action='store_true', default=False,
                                  help='treat part files like normal files (e.g. to list/extract them)')

        parser = argparse.ArgumentParser(prog=prog, description='Borg - Deduplicated Backups')
        parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__,
                            help='show version number and exit')
        subparsers = parser.add_subparsers(title='required arguments', metavar='<command>')

        serve_epilog = textwrap.dedent("""
        This command starts a repository server process. This command is usually not used manually.
        """)
        subparser = subparsers.add_parser('serve', parents=[common_parser], add_help=False,
                                          description=self.do_serve.__doc__, epilog=serve_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='start repository server process')
        subparser.set_defaults(func=self.do_serve)
        subparser.add_argument('--restrict-to-path', dest='restrict_to_paths', action='append',
                               metavar='PATH', help='restrict repository access to PATH. '
                                                    'Can be specified multiple times to allow the client access to several directories. '
                                                    'Access to all sub-directories is granted implicitly; PATH doesn\'t need to directly point to a repository.')
        subparser.add_argument('--append-only', dest='append_only', action='store_true',
                               help='only allow appending to repository segment files')

        init_epilog = textwrap.dedent("""
        This command initializes an empty repository. A repository is a filesystem
        directory containing the deduplicated data from zero or more archives.

        Encryption can be enabled at repository init time.

        It is not recommended to work without encryption. Repository encryption protects
        you e.g. against the case that an attacker has access to your backup repository.

        But be careful with the key / the passphrase:

        If you want "passphrase-only" security, use one of the repokey modes. The
        key will be stored inside the repository (in its "config" file). In above
        mentioned attack scenario, the attacker will have the key (but not the
        passphrase).

        If you want "passphrase and having-the-key" security, use one of the keyfile
        modes. The key will be stored in your home directory (in .config/borg/keys).
        In the attack scenario, the attacker who has just access to your repo won't
        have the key (and also not the passphrase).

        Make a backup copy of the key file (keyfile mode) or repo config file
        (repokey mode) and keep it at a safe place, so you still have the key in
        case it gets corrupted or lost. Also keep the passphrase at a safe place.
        The backup that is encrypted with that key won't help you with that, of course.

        Make sure you use a good passphrase. Not too short, not too simple. The real
        encryption / decryption key is encrypted with / locked by your passphrase.
        If an attacker gets your key, he can't unlock and use it without knowing the
        passphrase.

        Be careful with special or non-ascii characters in your passphrase:

        - Borg processes the passphrase as unicode (and encodes it as utf-8),
          so it does not have problems dealing with even the strangest characters.
        - BUT: that does not necessarily apply to your OS / VM / keyboard configuration.

        So better use a long passphrase made from simple ascii chars than one that
        includes non-ascii stuff or characters that are hard/impossible to enter on
        a different keyboard layout.

        You can change your passphrase for existing repos at any time, it won't affect
        the encryption/decryption key or other secrets.

        Encryption modes
        ++++++++++++++++

        repokey and keyfile use AES-CTR-256 for encryption and HMAC-SHA256 for
        authentication in an encrypt-then-MAC (EtM) construction. The chunk ID hash
        is HMAC-SHA256 as well (with a separate key).
        These modes are compatible with borg 1.0.x.

        repokey-blake2 and keyfile-blake2 are also authenticated encryption modes,
        but use BLAKE2b-256 instead of HMAC-SHA256 for authentication. The chunk ID
        hash is a keyed BLAKE2b-256 hash.
        These modes are new and not compatible with borg 1.0.x.

        "authenticated" mode uses no encryption, but authenticates repository contents
        through the same keyed BLAKE2b-256 hash as the other blake2 modes (it uses it
        as chunk ID hash). The key is stored like repokey.
        This mode is new and not compatible with borg 1.0.x.

        "none" mode uses no encryption and no authentication. It uses sha256 as chunk
        ID hash. Not recommended, rather consider using an authenticated or
        authenticated/encrypted mode.
        This mode is compatible with borg 1.0.x.

        Hardware acceleration will be used automatically.

        On modern Intel/AMD CPUs (except very cheap ones), AES is usually hw
        accelerated. BLAKE2b is faster than sha256 on Intel/AMD 64bit CPUs.

        On modern ARM CPUs, NEON provides hw acceleration for sha256 making it faster
        than BLAKE2b-256 there.
        """)
        subparser = subparsers.add_parser('init', parents=[common_parser], add_help=False,
                                          description=self.do_init.__doc__, epilog=init_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='initialize empty repository')
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to create')
        subparser.add_argument('-e', '--encryption', dest='encryption',
                               choices=('none', 'keyfile', 'repokey', 'keyfile-blake2', 'repokey-blake2', 'authenticated'),
                               default=None,
                               help='select encryption key mode (default: "%(default)s")')
        subparser.add_argument('-a', '--append-only', dest='append_only', action='store_true',
                               help='create an append-only mode repository')

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
          files, check if chunk is present.
          If a chunk is not present and we are in repair mode, replace it with a same-size
          replacement chunk of zeros.
          If a previously lost chunk reappears (e.g. via a later backup) and we are in
          repair mode, the all-zero replacement chunk will be replaced by the correct chunk.
          This requires reading of archive and file metadata, but not data.
        - If we are in repair mode and we checked all the archives: delete orphaned
          chunks from the repo.
        - if you use a remote repo server via ssh:, the archive check is executed on
          the client machine (because if encryption is enabled, the checks will require
          decryption and this is always done client-side, because key access will be
          required).
        - The archive checks can be time consuming, they can be skipped using the
          --repository-only option.

        The --verify-data option will perform a full integrity verification (as opposed to
        checking the CRC32 of the segment) of data, which means reading the data from the
        repository, decrypting and decompressing it. This is a cryptographic verification,
        which will detect (accidental) corruption. For encrypted repositories it is
        tamper-resistant as well, unless the attacker has access to the keys.

        It is also very slow.
        """)
        subparser = subparsers.add_parser('check', parents=[common_parser], add_help=False,
                                          description=self.do_check.__doc__,
                                          epilog=check_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='verify repository')
        subparser.set_defaults(func=self.do_check)
        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
                               help='repository or archive to check consistency of')
        subparser.add_argument('--repository-only', dest='repo_only', action='store_true',
                               default=False,
                               help='only perform repository checks')
        subparser.add_argument('--archives-only', dest='archives_only', action='store_true',
                               default=False,
                               help='only perform archives checks')
        subparser.add_argument('--verify-data', dest='verify_data', action='store_true',
                               default=False,
                               help='perform cryptographic archive data integrity verification '
                                    '(conflicts with --repository-only)')
        subparser.add_argument('--repair', dest='repair', action='store_true',
                               default=False,
                               help='attempt to repair any inconsistencies found')
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help="""show progress display while checking""")
        self.add_archives_filters_args(subparser)

        change_passphrase_epilog = textwrap.dedent("""
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.
        """)
        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser], add_help=False,
                                          description=self.do_change_passphrase.__doc__,
                                          epilog=change_passphrase_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='change repository passphrase')
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))

        subparser = subparsers.add_parser('key', parents=[common_parser], add_help=False,
                                          description="Manage a keyfile or repokey of a repository",
                                          epilog="",
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='manage repository key')

        key_parsers = subparser.add_subparsers(title='required arguments', metavar='<command>')
        subparser.set_defaults(fallback_func=functools.partial(self.do_subcommand_help, subparser))

        key_export_epilog = textwrap.dedent("""
        If repository encryption is used, the repository is inaccessible
        without the key. This command allows to backup this essential key.

        There are two backup formats. The normal backup format is suitable for
        digital storage as a file. The ``--paper`` backup format is optimized
        for printing and typing in while importing, with per line checks to
        reduce problems with manual input.

        For repositories using keyfile encryption the key is saved locally
        on the system that is capable of doing backups. To guard against loss
        of this key, the key needs to be backed up independently of the main
        data backup.

        For repositories using the repokey encryption the key is saved in the
        repository in the config file. A backup is thus not strictly needed,
        but guards against the repository becoming inaccessible if the file
        is damaged for some reason.
        """)
        subparser = key_parsers.add_parser('export', parents=[common_parser], add_help=False,
                                          description=self.do_key_export.__doc__,
                                          epilog=key_export_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='export repository key for backup')
        subparser.set_defaults(func=self.do_key_export)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))
        subparser.add_argument('path', metavar='PATH', nargs='?', type=str,
                               help='where to store the backup')
        subparser.add_argument('--paper', dest='paper', action='store_true',
                               default=False,
                               help='Create an export suitable for printing and later type-in')

        key_import_epilog = textwrap.dedent("""
        This command allows to restore a key previously backed up with the
        export command.

        If the ``--paper`` option is given, the import will be an interactive
        process in which each line is checked for plausibility before
        proceeding to the next line. For this format PATH must not be given.
        """)
        subparser = key_parsers.add_parser('import', parents=[common_parser], add_help=False,
                                          description=self.do_key_import.__doc__,
                                          epilog=key_import_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='import repository key from backup')
        subparser.set_defaults(func=self.do_key_import)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))
        subparser.add_argument('path', metavar='PATH', nargs='?', type=str,
                               help='path to the backup')
        subparser.add_argument('--paper', dest='paper', action='store_true',
                               default=False,
                               help='interactively import from a backup done with --paper')

        migrate_to_repokey_epilog = textwrap.dedent("""
        This command migrates a repository from passphrase mode (not supported any
        more) to repokey mode.

        You will be first asked for the repository passphrase (to open it in passphrase
        mode). This is the same passphrase as you used to use for this repo before 1.0.

        It will then derive the different secrets from this passphrase.

        Then you will be asked for a new passphrase (twice, for safety). This
        passphrase will be used to protect the repokey (which contains these same
        secrets in encrypted form). You may use the same passphrase as you used to
        use, but you may also use a different one.

        After migrating to repokey mode, you can change the passphrase at any time.
        But please note: the secrets will always stay the same and they could always
        be derived from your (old) passphrase-mode passphrase.
        """)
        subparser = subparsers.add_parser('migrate-to-repokey', parents=[common_parser], add_help=False,
                                          description=self.do_migrate_to_repokey.__doc__,
                                          epilog=migrate_to_repokey_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='migrate passphrase-mode repository to repokey')
        subparser.set_defaults(func=self.do_migrate_to_repokey)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))

        create_epilog = textwrap.dedent("""
        This command creates a backup archive containing all files found while recursively
        traversing all paths specified. When giving '-' as path, borg will read data
        from standard input and create a file 'stdin' in the created archive from that
        data.

        The archive will consume almost no disk space for files or parts of files that
        have already been stored in other archives.

        The archive name needs to be unique. It must not end in '.checkpoint' or
        '.checkpoint.N' (with N being a number), because these names are used for
        checkpoints and treated in special ways.

        In the archive name, you may use the following placeholders:
        {now}, {utcnow}, {fqdn}, {hostname}, {user} and some others.

        To speed up pulling backups over sshfs and similar network file systems which do
        not provide correct inode information the --ignore-inode flag can be used. This
        potentially decreases reliability of change detection, while avoiding always reading
        all files on these file systems.

        See the output of the "borg help patterns" command for more help on exclude patterns.
        See the output of the "borg help placeholders" command for more help on placeholders.
        """)

        subparser = subparsers.add_parser('create', parents=[common_parser], add_help=False,
                                          description=self.do_create.__doc__,
                                          epilog=create_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='create backup')
        subparser.set_defaults(func=self.do_create)

        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               action='store_true', default=False,
                               help='do not create a backup archive')

        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the created archive')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help='show progress display while creating the archive, showing Original, '
                                    'Compressed and Deduplicated sizes, followed by the Number of files seen '
                                    'and the path being processed, default: %(default)s')
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of items (files, dirs, ...)')
        subparser.add_argument('--filter', dest='output_filter', metavar='STATUSCHARS',
                               help='only display items with the given status characters')

        exclude_group = subparser.add_argument_group('Exclusion options')
        exclude_group.add_argument('-e', '--exclude', dest='excludes',
                                   type=parse_pattern, action='append',
                                   metavar="PATTERN", help='exclude paths matching PATTERN')
        exclude_group.add_argument('--exclude-from', dest='exclude_files',
                                   type=argparse.FileType('r'), action='append',
                                   metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        exclude_group.add_argument('--exclude-caches', dest='exclude_caches',
                                   action='store_true', default=False,
                                   help='exclude directories that contain a CACHEDIR.TAG file ('
                                        'http://www.brynosaurus.com/cachedir/spec.html)')
        exclude_group.add_argument('--exclude-if-present', dest='exclude_if_present',
                                   metavar='FILENAME', action='append', type=str,
                                   help='exclude directories that contain the specified file')
        exclude_group.add_argument('--keep-tag-files', dest='keep_tag_files',
                                   action='store_true', default=False,
                                   help='keep tag files of excluded caches/directories')

        fs_group = subparser.add_argument_group('Filesystem options')
        fs_group.add_argument('-x', '--one-file-system', dest='one_file_system',
                              action='store_true', default=False,
                              help='stay in same file system, do not cross mount points')
        fs_group.add_argument('--numeric-owner', dest='numeric_owner',
                              action='store_true', default=False,
                              help='only store numeric user and group identifiers')
        fs_group.add_argument('--noatime', dest='noatime',
                              action='store_true', default=False,
                              help='do not store atime into archive')
        fs_group.add_argument('--noctime', dest='noctime',
                              action='store_true', default=False,
                              help='do not store ctime into archive')
        fs_group.add_argument('--ignore-inode', dest='ignore_inode',
                              action='store_true', default=False,
                              help='ignore inode data in the file metadata cache used to detect unchanged files.')
        fs_group.add_argument('--read-special', dest='read_special',
                              action='store_true', default=False,
                              help='open and read block and char device files as well as FIFOs as if they were '
                                   'regular files. Also follows symlinks pointing to these kinds of files.')

        archive_group = subparser.add_argument_group('Archive options')
        archive_group.add_argument('--comment', dest='comment', metavar='COMMENT', default='',
                                   help='add a comment text to the archive')
        archive_group.add_argument('--timestamp', dest='timestamp',
                                   type=timestamp, default=None,
                                   metavar='yyyy-mm-ddThh:mm:ss',
                                   help='manually specify the archive creation date/time (UTC). '
                                        'alternatively, give a reference file/directory.')
        archive_group.add_argument('-c', '--checkpoint-interval', dest='checkpoint_interval',
                                   type=int, default=1800, metavar='SECONDS',
                                   help='write checkpoint every SECONDS seconds (Default: 1800)')
        archive_group.add_argument('--chunker-params', dest='chunker_params',
                                   type=ChunkerParams, default=CHUNKER_PARAMS,
                                   metavar='CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE',
                                   help='specify the chunker parameters. default: %d,%d,%d,%d' % CHUNKER_PARAMS)
        archive_group.add_argument('-C', '--compression', dest='compression',
                                   type=CompressionSpec, default=dict(name='none'), metavar='COMPRESSION',
                                   help='select compression algorithm, see the output of the '
                                        '"borg help compression" command for details.')
        archive_group.add_argument('--compression-from', dest='compression_files',
                                   type=argparse.FileType('r'), action='append',
                                   metavar='COMPRESSIONCONFIG',
                                   help='read compression patterns from COMPRESSIONCONFIG, see the output of the '
                                        '"borg help compression" command for details.')

        subparser.add_argument('location', metavar='ARCHIVE',
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

        By using ``--dry-run``, you can do all extraction steps except actually writing the
        output data: reading metadata and data chunks from the repo, checking the hash/hmac,
        decrypting, decompressing.
        """)
        subparser = subparsers.add_parser('extract', parents=[common_parser], add_help=False,
                                          description=self.do_extract.__doc__,
                                          epilog=extract_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='extract archive contents')
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help='show progress while extracting (may be slower)')
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of items (files, dirs, ...)')
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not actually change any files')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=parse_pattern, action='append',
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
        subparser.add_argument('location', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to extract')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to extract; patterns are supported')

        diff_epilog = textwrap.dedent("""
            This command finds differences (file contents, user/group/mode) between archives.

            A repository location and an archive name must be specified for REPO_ARCHIVE1.
            ARCHIVE2 is just another archive name in same repository (no repository location
            allowed).

            For archives created with Borg 1.1 or newer diff automatically detects whether
            the archives are created with the same chunker params. If so, only chunk IDs
            are compared, which is very fast.

            For archives prior to Borg 1.1 chunk contents are compared by default.
            If you did not create the archives with different chunker params,
            pass --same-chunker-params.
            Note that the chunker params changed from Borg 0.xx to 1.0.

            See the output of the "borg help patterns" command for more help on exclude patterns.
            """)
        subparser = subparsers.add_parser('diff', parents=[common_parser], add_help=False,
                                          description=self.do_diff.__doc__,
                                          epilog=diff_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='find differences in archive contents')
        subparser.set_defaults(func=self.do_diff)
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=parse_pattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--exclude-from', dest='exclude_files',
                               type=argparse.FileType('r'), action='append',
                               metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        subparser.add_argument('--numeric-owner', dest='numeric_owner',
                               action='store_true', default=False,
                               help='only consider numeric user and group identifiers')
        subparser.add_argument('--same-chunker-params', dest='same_chunker_params',
                               action='store_true', default=False,
                               help='Override check of chunker parameters.')
        subparser.add_argument('--sort', dest='sort',
                               action='store_true', default=False,
                               help='Sort the output lines by file path.')
        subparser.add_argument('location', metavar='REPO_ARCHIVE1',
                               type=location_validator(archive=True),
                               help='repository location and ARCHIVE1 name')
        subparser.add_argument('archive2', metavar='ARCHIVE2',
                               type=archivename_validator(),
                               help='ARCHIVE2 name (no repository location allowed)')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths of items inside the archives to compare; patterns are supported')

        rename_epilog = textwrap.dedent("""
        This command renames an archive in the repository.

        This results in a different archive ID.
        """)
        subparser = subparsers.add_parser('rename', parents=[common_parser], add_help=False,
                                          description=self.do_rename.__doc__,
                                          epilog=rename_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='rename archive')
        subparser.set_defaults(func=self.do_rename)
        subparser.add_argument('location', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to rename')
        subparser.add_argument('name', metavar='NEWNAME',
                               type=archivename_validator(),
                               help='the new archive name to use')

        delete_epilog = textwrap.dedent("""
        This command deletes an archive from the repository or the complete repository.
        Disk space is reclaimed accordingly. If you delete the complete repository, the
        local cache for it (if any) is also deleted.
        """)
        subparser = subparsers.add_parser('delete', parents=[common_parser], add_help=False,
                                          description=self.do_delete.__doc__,
                                          epilog=delete_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='delete archive')
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help="""show progress display while deleting a single archive""")
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('-c', '--cache-only', dest='cache_only',
                               action='store_true', default=False,
                               help='delete only the local cache for the given repository')
        subparser.add_argument('--force', dest='forced',
                               action='store_true', default=False,
                               help='force deletion of corrupted archives')
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('location', metavar='TARGET', nargs='?', default='',
                               type=location_validator(),
                               help='archive or repository to delete')
        self.add_archives_filters_args(subparser)

        list_epilog = textwrap.dedent("""
        This command lists the contents of a repository or an archive.

        See the "borg help patterns" command for more help on exclude patterns.

        The following keys are available for --format:
        """) + BaseFormatter.keys_help() + textwrap.dedent("""

        -- Keys for listing repository archives:
        """) + ArchiveFormatter.keys_help() + textwrap.dedent("""

        -- Keys for listing archive files:
        """) + ItemFormatter.keys_help()
        subparser = subparsers.add_parser('list', parents=[common_parser], add_help=False,
                                          description=self.do_list.__doc__,
                                          epilog=list_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='list archive or repository contents')
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('--short', dest='short',
                               action='store_true', default=False,
                               help='only print file/directory names, nothing else')
        subparser.add_argument('--format', '--list-format', dest='format', type=str,
                               help="""specify format for file listing
                                (default: "{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NL}")""")
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=parse_pattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--exclude-from', dest='exclude_files',
                               type=argparse.FileType('r'), action='append',
                               metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
                               help='repository/archive to list contents of')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to list; patterns are supported')
        self.add_archives_filters_args(subparser)

        mount_epilog = textwrap.dedent("""
        This command mounts an archive as a FUSE filesystem. This can be useful for
        browsing an archive or restoring individual files. Unless the ``--foreground``
        option is given the command will run in the background until the filesystem
        is ``umounted``.

        The command ``borgfs`` provides a wrapper for ``borg mount``. This can also be
        used in fstab entries:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0``

        To allow a regular user to use fstab entries, add the ``user`` option:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto,user 0 0``

        For mount options, see the fuse(8) manual page. Additional mount options
        supported by borg:

        - versions: when used with a repository mount, this gives a merged, versioned
          view of the files in the archives. EXPERIMENTAL, layout may change in future.
        - allow_damaged_files: by default damaged files (where missing chunks were
          replaced with runs of zeros by borg check --repair) are not readable and
          return EIO (I/O error). Set this option to read such files.

        The BORG_MOUNT_DATA_CACHE_ENTRIES environment variable is meant for advanced users
        to tweak the performance. It sets the number of cached data chunks; additional
        memory usage can be up to ~8 MiB times this number. The default is the number
        of CPU cores.
        """)
        subparser = subparsers.add_parser('mount', parents=[common_parser], add_help=False,
                                          description=self.do_mount.__doc__,
                                          epilog=mount_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='mount repository')
        subparser.set_defaults(func=self.do_mount)
        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', type=location_validator(),
                               help='repository/archive to mount')
        subparser.add_argument('mountpoint', metavar='MOUNTPOINT', type=str,
                               help='where to mount filesystem')
        subparser.add_argument('-f', '--foreground', dest='foreground',
                               action='store_true', default=False,
                               help='stay in foreground, do not daemonize')
        subparser.add_argument('-o', dest='options', type=str,
                               help='Extra mount options')
        self.add_archives_filters_args(subparser)

        umount_epilog = textwrap.dedent("""
        This command un-mounts a FUSE filesystem that was mounted with ``borg mount``.

        This is a convenience wrapper that just calls the platform-specific shell
        command - usually this is either umount or fusermount -u.
        """)
        subparser = subparsers.add_parser('umount', parents=[common_parser], add_help=False,
                                          description=self.do_umount.__doc__,
                                          epilog=umount_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='umount repository')
        subparser.set_defaults(func=self.do_umount)
        subparser.add_argument('mountpoint', metavar='MOUNTPOINT', type=str,
                               help='mountpoint of the filesystem to umount')

        info_epilog = textwrap.dedent("""
        This command displays detailed information about the specified archive or repository.

        Please note that the deduplicated sizes of the individual archives do not add
        up to the deduplicated size of the repository ("all archives"), because the two
        are meaning different things:

        This archive / deduplicated size = amount of data stored ONLY for this archive
                                         = unique chunks of this archive.
        All archives / deduplicated size = amount of data stored in the repo
                                         = all chunks in the repository.
        """)
        subparser = subparsers.add_parser('info', parents=[common_parser], add_help=False,
                                          description=self.do_info.__doc__,
                                          epilog=info_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='show repository or archive information')
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
                               help='archive or repository to display information about')
        self.add_archives_filters_args(subparser)

        break_lock_epilog = textwrap.dedent("""
        This command breaks the repository and cache locks.
        Please use carefully and only while no borg process (on any machine) is
        trying to access the Cache or the Repository.
        """)
        subparser = subparsers.add_parser('break-lock', parents=[common_parser], add_help=False,
                                          description=self.do_break_lock.__doc__,
                                          epilog=break_lock_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='break repository and cache locks')
        subparser.set_defaults(func=self.do_break_lock)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository for which to break the locks')

        prune_epilog = textwrap.dedent("""
        The prune command prunes a repository by deleting all archives not matching
        any of the specified retention options. This command is normally used by
        automated backup scripts wanting to keep a certain number of historic backups.

        Also, prune automatically removes checkpoint archives (incomplete archives left
        behind by interrupted backup runs) except if the checkpoint is the latest
        archive (and thus still needed). Checkpoint archives are not considered when
        comparing archive counts against the retention limits (--keep-*).

        If a prefix is set with -P, then only archives that start with the prefix are
        considered for deletion and only those archives count towards the totals
        specified by the rules.
        Otherwise, *all* archives in the repository are candidates for deletion!
        There is no automatic distinction between archives representing different
        contents. These need to be distinguished by specifying matching prefixes.

        If you have multiple sequences of archives with different data sets (e.g.
        from different machines) in one shared repository, use one prune call per
        data set that matches only the respective archives using the -P option.

        The "--keep-within" option takes an argument of the form "<int><char>",
        where char is "H", "d", "w", "m", "y". For example, "--keep-within 2d" means
        to keep all archives that were created within the past 48 hours.
        "1m" is taken to mean "31d". The archives kept with this option do not
        count towards the totals specified by any other options.

        A good procedure is to thin out more and more the older your backups get.
        As an example, "--keep-daily 7" means to keep the latest backup on each day,
        up to 7 most recent days with backups (days without backups do not count).
        The rules are applied from secondly to yearly, and backups selected by previous
        rules do not count towards those of later rules. The time that each backup
        starts is used for pruning purposes. Dates and times are interpreted in
        the local timezone, and weeks go from Monday to Sunday. Specifying a
        negative number of archives to keep means that there is no limit.

        The "--keep-last N" option is doing the same as "--keep-secondly N" (and it will
        keep the last N archives under the assumption that you do not create more than one
        backup archive in the same second).
        """)
        subparser = subparsers.add_parser('prune', parents=[common_parser], add_help=False,
                                          description=self.do_prune.__doc__,
                                          epilog=prune_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='prune archives')
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not change repository')
        subparser.add_argument('--force', dest='forced',
                               action='store_true', default=False,
                               help='force pruning of corrupted archives')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help='show progress display while deleting archives')
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of archives it keeps/prunes')
        subparser.add_argument('--keep-within', dest='within', type=str, metavar='WITHIN',
                               help='keep all archives within this time interval')
        subparser.add_argument('--keep-last', '--keep-secondly', dest='secondly', type=int, default=0,
                               help='number of secondly archives to keep')
        subparser.add_argument('--keep-minutely', dest='minutely', type=int, default=0,
                               help='number of minutely archives to keep')
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
        subparser.add_argument('-P', '--prefix', dest='prefix', type=PrefixSpec,
                               help='only consider archive names starting with this prefix')
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to prune')

        upgrade_epilog = textwrap.dedent("""
        Upgrade an existing Borg repository.

        Borg 1.x.y upgrades
        +++++++++++++++++++

        Use ``borg upgrade --tam REPO`` to require manifest authentication
        introduced with Borg 1.0.9 to address security issues. This means
        that modifying the repository after doing this with a version prior
        to 1.0.9 will raise a validation error, so only perform this upgrade
        after updating all clients using the repository to 1.0.9 or newer.

        This upgrade should be done on each client for safety reasons.

        If a repository is accidentally modified with a pre-1.0.9 client after
        this upgrade, use ``borg upgrade --tam --force REPO`` to remedy it.

        If you routinely do this you might not want to enable this upgrade
        (which will leave you exposed to the security issue). You can
        reverse the upgrade by issuing ``borg upgrade --disable-tam REPO``.

        See
        https://borgbackup.readthedocs.io/en/stable/changes.html#pre-1-0-9-manifest-spoofing-vulnerability
        for details.

        Attic and Borg 0.xx to Borg 1.x
        +++++++++++++++++++++++++++++++

        This currently supports converting an Attic repository to Borg and also
        helps with converting Borg 0.xx to 1.0.

        Currently, only LOCAL repositories can be upgraded (issue #465).

        It will change the magic strings in the repository's segments
        to match the new Borg magic strings. The keyfiles found in
        $ATTIC_KEYS_DIR or ~/.attic/keys/ will also be converted and
        copied to $BORG_KEYS_DIR or ~/.config/borg/keys.

        The cache files are converted, from $ATTIC_CACHE_DIR or
        ~/.cache/attic to $BORG_CACHE_DIR or ~/.cache/borg, but the
        cache layout between Borg and Attic changed, so it is possible
        the first backup after the conversion takes longer than expected
        due to the cache resync.

        Upgrade should be able to resume if interrupted, although it
        will still iterate over all segments. If you want to start
        from scratch, use `borg delete` over the copied repository to
        make sure the cache files are also removed:

            borg delete borg

        Unless ``--inplace`` is specified, the upgrade process first
        creates a backup copy of the repository, in
        REPOSITORY.upgrade-DATETIME, using hardlinks. This takes
        longer than in place upgrades, but is much safer and gives
        progress information (as opposed to ``cp -al``). Once you are
        satisfied with the conversion, you can safely destroy the
        backup copy.

        WARNING: Running the upgrade in place will make the current
        copy unusable with older version, with no way of going back
        to previous versions. This can PERMANENTLY DAMAGE YOUR
        REPOSITORY!  Attic CAN NOT READ BORG REPOSITORIES, as the
        magic strings have changed. You have been warned.""")
        subparser = subparsers.add_parser('upgrade', parents=[common_parser], add_help=False,
                                          description=self.do_upgrade.__doc__,
                                          epilog=upgrade_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='upgrade repository format')
        subparser.set_defaults(func=self.do_upgrade)
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help="""show progress display while upgrading the repository""")
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not change repository')
        subparser.add_argument('-i', '--inplace', dest='inplace',
                               default=False, action='store_true',
                               help="""rewrite repository in place, with no chance of going back to older
                               versions of the repository.""")
        subparser.add_argument('--force', dest='force', action='store_true',
                               help="""Force upgrade""")
        subparser.add_argument('--tam', dest='tam', action='store_true',
                               help="""Enable manifest authentication (in key and cache) (Borg 1.0.9 and later)""")
        subparser.add_argument('--disable-tam', dest='disable_tam', action='store_true',
                               help="""Disable manifest authentication (in key and cache)""")
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='path to the repository to be upgraded')

        recreate_epilog = textwrap.dedent("""
        Recreate the contents of existing archives.

        This is an *experimental* feature. Do *not* use this on your only backup.

        --exclude, --exclude-from and PATH have the exact same semantics
        as in "borg create". If PATHs are specified the resulting archive
        will only contain files from these PATHs.

        Note that all paths in an archive are relative, therefore absolute patterns/paths
        will *not* match (--exclude, --exclude-from, --compression-from, PATHs).

        --compression: all chunks seen will be stored using the given method.
        Due to how Borg stores compressed size information this might display
        incorrect information for archives that were not recreated at the same time.
        There is no risk of data loss by this.

        --chunker-params will re-chunk all files in the archive, this can be
        used to have upgraded Borg 0.xx or Attic archives deduplicate with
        Borg 1.x archives.

        USE WITH CAUTION.
        Depending on the PATHs and patterns given, recreate can be used to permanently
        delete files from archives.
        When in doubt, use "--dry-run --verbose --list" to see how patterns/PATHS are
        interpreted.

        The archive being recreated is only removed after the operation completes. The
        archive that is built during the operation exists at the same time at
        "<ARCHIVE>.recreate". The new archive will have a different archive ID.

        With --target the original archive is not replaced, instead a new archive is created.

        When rechunking space usage can be substantial, expect at least the entire
        deduplicated size of the archives using the previous chunker params.
        When recompressing expect approx. (throughput / checkpoint-interval) in space usage,
        assuming all chunks are recompressed.
        """)
        subparser = subparsers.add_parser('recreate', parents=[common_parser], add_help=False,
                                          description=self.do_recreate.__doc__,
                                          epilog=recreate_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help=self.do_recreate.__doc__)
        subparser.set_defaults(func=self.do_recreate)
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of items (files, dirs, ...)')
        subparser.add_argument('--filter', dest='output_filter', metavar='STATUSCHARS',
                               help='only display items with the given status characters')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help='show progress display while recreating archives')
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               action='store_true', default=False,
                               help='do not change anything')
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics at end')

        exclude_group = subparser.add_argument_group('Exclusion options')
        exclude_group.add_argument('-e', '--exclude', dest='excludes',
                                   type=parse_pattern, action='append',
                                   metavar="PATTERN", help='exclude paths matching PATTERN')
        exclude_group.add_argument('--exclude-from', dest='exclude_files',
                                   type=argparse.FileType('r'), action='append',
                                   metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        exclude_group.add_argument('--exclude-caches', dest='exclude_caches',
                                   action='store_true', default=False,
                                   help='exclude directories that contain a CACHEDIR.TAG file ('
                                        'http://www.brynosaurus.com/cachedir/spec.html)')
        exclude_group.add_argument('--exclude-if-present', dest='exclude_if_present',
                                   metavar='FILENAME', action='append', type=str,
                                   help='exclude directories that contain the specified file')
        exclude_group.add_argument('--keep-tag-files', dest='keep_tag_files',
                                   action='store_true', default=False,
                                   help='keep tag files of excluded caches/directories')

        archive_group = subparser.add_argument_group('Archive options')
        archive_group.add_argument('--target', dest='target', metavar='TARGET', default=None,
                                   type=archivename_validator(),
                                   help='create a new archive with the name ARCHIVE, do not replace existing archive '
                                        '(only applies for a single archive)')
        archive_group.add_argument('-c', '--checkpoint-interval', dest='checkpoint_interval',
                                   type=int, default=1800, metavar='SECONDS',
                                   help='write checkpoint every SECONDS seconds (Default: 1800)')
        archive_group.add_argument('--comment', dest='comment', metavar='COMMENT', default=None,
                                   help='add a comment text to the archive')
        archive_group.add_argument('--timestamp', dest='timestamp',
                                   type=timestamp, default=None,
                                   metavar='yyyy-mm-ddThh:mm:ss',
                                   help='manually specify the archive creation date/time (UTC). '
                                        'alternatively, give a reference file/directory.')
        archive_group.add_argument('-C', '--compression', dest='compression',
                                   type=CompressionSpec, default=None, metavar='COMPRESSION',
                                   help='select compression algorithm, see the output of the '
                                        '"borg help compression" command for details.')
        archive_group.add_argument('--always-recompress', dest='always_recompress', action='store_true',
                                   help='always recompress chunks, don\'t skip chunks already compressed with the same '
                                        'algorithm.')
        archive_group.add_argument('--compression-from', dest='compression_files',
                                   type=argparse.FileType('r'), action='append',
                                   metavar='COMPRESSIONCONFIG',
                                   help='read compression patterns from COMPRESSIONCONFIG, see the output of the '
                                        '"borg help compression" command for details.')
        archive_group.add_argument('--chunker-params', dest='chunker_params',
                                   type=ChunkerParams, default=None,
                                   metavar='CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE',
                                   help='specify the chunker parameters (or "default").')

        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
                               type=location_validator(),
                               help='repository/archive to recreate')
        subparser.add_argument('paths', metavar='PATH', nargs='*', type=str,
                               help='paths to recreate; patterns are supported')

        with_lock_epilog = textwrap.dedent("""
        This command runs a user-specified command while the repository lock is held.

        It will first try to acquire the lock (make sure that no other operation is
        running in the repo), then execute the given command as a subprocess and wait
        for its termination, release the lock and return the user command's return
        code as borg's return code.

        Note: if you copy a repository with the lock held, the lock will be present in
              the copy, obviously. Thus, before using borg on the copy, you need to
              use "borg break-lock" on it.
        """)
        subparser = subparsers.add_parser('with-lock', parents=[common_parser], add_help=False,
                                          description=self.do_with_lock.__doc__,
                                          epilog=with_lock_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='run user command with lock held')
        subparser.set_defaults(func=self.do_with_lock)
        subparser.add_argument('location', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository to lock')
        subparser.add_argument('command', metavar='COMMAND',
                               help='command to run')
        subparser.add_argument('args', metavar='ARGS', nargs=argparse.REMAINDER,
                               help='command arguments')

        subparser = subparsers.add_parser('help', parents=[common_parser], add_help=False,
                                          description='Extra help')
        subparser.add_argument('--epilog-only', dest='epilog_only',
                               action='store_true', default=False)
        subparser.add_argument('--usage-only', dest='usage_only',
                               action='store_true', default=False)
        subparser.set_defaults(func=functools.partial(self.do_help, parser, subparsers.choices))
        subparser.add_argument('topic', metavar='TOPIC', type=str, nargs='?',
                               help='additional help on TOPIC')

        debug_epilog = textwrap.dedent("""
        These commands are not intended for normal use and potentially very
        dangerous if used incorrectly.

        They exist to improve debugging capabilities without direct system access, e.g.
        in case you ever run into some severe malfunction. Use them only if you know
        what you are doing or if a trusted developer tells you what to do.""")

        subparser = subparsers.add_parser('debug', parents=[common_parser], add_help=False,
                                          description='debugging command (not intended for normal use)',
                                          epilog=debug_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='debugging command (not intended for normal use)')

        debug_parsers = subparser.add_subparsers(title='required arguments', metavar='<command>')
        subparser.set_defaults(fallback_func=functools.partial(self.do_subcommand_help, subparser))

        debug_info_epilog = textwrap.dedent("""
        This command displays some system information that might be useful for bug
        reports and debugging problems. If a traceback happens, this information is
        already appended at the end of the traceback.
        """)
        subparser = debug_parsers.add_parser('info', parents=[common_parser], add_help=False,
                                          description=self.do_debug_info.__doc__,
                                          epilog=debug_info_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='show system infos for debugging / bug reports (debug)')
        subparser.set_defaults(func=self.do_debug_info)

        debug_dump_archive_items_epilog = textwrap.dedent("""
        This command dumps raw (but decrypted and decompressed) archive items (only metadata) to files.
        """)
        subparser = debug_parsers.add_parser('dump-archive-items', parents=[common_parser], add_help=False,
                                          description=self.do_debug_dump_archive_items.__doc__,
                                          epilog=debug_dump_archive_items_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='dump archive items (metadata) (debug)')
        subparser.set_defaults(func=self.do_debug_dump_archive_items)
        subparser.add_argument('location', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to dump')

        debug_dump_repo_objs_epilog = textwrap.dedent("""
        This command dumps raw (but decrypted and decompressed) repo objects to files.
        """)
        subparser = debug_parsers.add_parser('dump-repo-objs', parents=[common_parser], add_help=False,
                                          description=self.do_debug_dump_repo_objs.__doc__,
                                          epilog=debug_dump_repo_objs_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='dump repo objects (debug)')
        subparser.set_defaults(func=self.do_debug_dump_repo_objs)
        subparser.add_argument('location', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repo to dump')

        debug_get_obj_epilog = textwrap.dedent("""
        This command gets an object from the repository.
        """)
        subparser = debug_parsers.add_parser('get-obj', parents=[common_parser], add_help=False,
                                          description=self.do_debug_get_obj.__doc__,
                                          epilog=debug_get_obj_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='get object from repository (debug)')
        subparser.set_defaults(func=self.do_debug_get_obj)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to use')
        subparser.add_argument('id', metavar='ID', type=str,
                               help='hex object ID to get from the repo')
        subparser.add_argument('path', metavar='PATH', type=str,
                               help='file to write object data into')

        debug_put_obj_epilog = textwrap.dedent("""
        This command puts objects into the repository.
        """)
        subparser = debug_parsers.add_parser('put-obj', parents=[common_parser], add_help=False,
                                          description=self.do_debug_put_obj.__doc__,
                                          epilog=debug_put_obj_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='put object to repository (debug)')
        subparser.set_defaults(func=self.do_debug_put_obj)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to use')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='file(s) to read and create object(s) from')

        debug_delete_obj_epilog = textwrap.dedent("""
        This command deletes objects from the repository.
        """)
        subparser = debug_parsers.add_parser('delete-obj', parents=[common_parser], add_help=False,
                                          description=self.do_debug_delete_obj.__doc__,
                                          epilog=debug_delete_obj_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='delete object from repository (debug)')
        subparser.set_defaults(func=self.do_debug_delete_obj)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to use')
        subparser.add_argument('ids', metavar='IDs', nargs='+', type=str,
                               help='hex object ID(s) to delete from the repo')

        debug_refcount_obj_epilog = textwrap.dedent("""
        This command displays the reference count for objects from the repository.
        """)
        subparser = debug_parsers.add_parser('refcount-obj', parents=[common_parser], add_help=False,
                                          description=self.do_debug_refcount_obj.__doc__,
                                          epilog=debug_refcount_obj_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='show refcount for object from repository (debug)')
        subparser.set_defaults(func=self.do_debug_refcount_obj)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to use')
        subparser.add_argument('ids', metavar='IDs', nargs='+', type=str,
                               help='hex object ID(s) to show refcounts for')

        return parser

    @staticmethod
    def add_archives_filters_args(subparser):
        filters_group = subparser.add_argument_group('filters', 'Archive filters can be applied to repository targets.')
        filters_group.add_argument('-P', '--prefix', dest='prefix', type=PrefixSpec, default='',
                                   help='only consider archive names starting with this prefix')

        sort_by_default = 'timestamp'
        filters_group.add_argument('--sort-by', dest='sort_by', type=SortBySpec, default=sort_by_default,
                                   help='Comma-separated list of sorting keys; valid keys are: {}; default is: {}'
                                   .format(', '.join(HUMAN_SORT_KEYS), sort_by_default))

        group = filters_group.add_mutually_exclusive_group()
        group.add_argument('--first', dest='first', metavar='N', default=0, type=int,
                           help='consider first N archives after other filters were applied')
        group.add_argument('--last', dest='last', metavar='N', default=0, type=int,
                           help='consider last N archives after other filters were applied')

    def get_args(self, argv, cmd):
        """usually, just returns argv, except if we deal with a ssh forced command for borg serve."""
        result = self.parse_args(argv[1:])
        if cmd is not None and result.func == self.do_serve:
            forced_result = result
            argv = shlex.split(cmd)
            result = self.parse_args(argv[1:])
            if result.func != forced_result.func:
                # someone is trying to execute a different borg subcommand, don't do that!
                return forced_result
            # we only take specific options from the forced "borg serve" command:
            result.restrict_to_paths = forced_result.restrict_to_paths
            result.append_only = forced_result.append_only
        return result

    def parse_args(self, args=None):
        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)
        args = self.parser.parse_args(args or ['-h'])
        update_excludes(args)
        return args

    def prerun_checks(self, logger):
        check_extension_modules()
        selftest(logger)

    def _setup_implied_logging(self, args):
        """ turn on INFO level logging for args that imply that they will produce output """
        # map of option name to name of logger for that option
        option_logger = {
                'output_list': 'borg.output.list',
                'show_version': 'borg.output.show-version',
                'show_rc': 'borg.output.show-rc',
                'stats': 'borg.output.stats',
                'progress': 'borg.output.progress',
                }
        for option, logger_name in option_logger.items():
            if args.get(option, False):
                logging.getLogger(logger_name).setLevel('INFO')

    def _setup_topic_debugging(self, args):
        """Turn on DEBUG level logging for specified --debug-topics."""
        for topic in args.debug_topics:
            if '.' not in topic:
                topic = 'borg.debug.' + topic
            logger.debug('Enabling debug topic %s', topic)
            logging.getLogger(topic).setLevel('DEBUG')

    def run(self, args):
        os.umask(args.umask)  # early, before opening files
        self.lock_wait = args.lock_wait
        # This works around http://bugs.python.org/issue9351
        func = getattr(args, 'func', None) or getattr(args, 'fallback_func')
        setup_logging(level=args.log_level, is_serve=func == self.do_serve)  # do not use loggers before this!
        self._setup_implied_logging(vars(args))
        self._setup_topic_debugging(args)
        if args.show_version:
            logging.getLogger('borg.output.show-version').info('borgbackup version %s' % __version__)
        self.prerun_checks(logger)
        if is_slow_msgpack():
            logger.warning("Using a pure-python msgpack! This will result in lower performance.")
        return func(args)


def sig_info_handler(sig_no, stack):  # pragma: no cover
    """search the stack for infos about the currently processed file and print them"""
    with signal_handler(sig_no, signal.SIG_IGN):
        for frame in inspect.getouterframes(stack):
            func, loc = frame[3], frame[0].f_locals
            if func in ('process_file', '_process', ):  # create op
                path = loc['path']
                try:
                    pos = loc['fd'].tell()
                    total = loc['st'].st_size
                except Exception:
                    pos, total = 0, 0
                logger.info("{0} {1}/{2}".format(path, format_file_size(pos), format_file_size(total)))
                break
            if func in ('extract_item', ):  # extract op
                path = loc['item'].path
                try:
                    pos = loc['fd'].tell()
                except Exception:
                    pos = 0
                logger.info("{0} {1}/???".format(path, format_file_size(pos)))
                break


def sig_trace_handler(sig_no, stack):  # pragma: no cover
    print('\nReceived SIGUSR2 at %s, dumping trace...' % datetime.now().replace(microsecond=0), file=sys.stderr)
    faulthandler.dump_traceback()


def main():  # pragma: no cover
    # provide 'borg mount' behaviour when the main script/executable is named borgfs
    if os.path.basename(sys.argv[0]) == "borgfs":
        sys.argv.insert(1, "mount")

    # Make sure stdout and stderr have errors='replace' to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = ErrorIgnoringTextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, 'replace', line_buffering=True)
    sys.stderr = ErrorIgnoringTextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, 'replace', line_buffering=True)

    # If we receive SIGINT (ctrl-c), SIGTERM (kill) or SIGHUP (kill -HUP),
    # catch them and raise a proper exception that can be handled for an
    # orderly exit.
    # SIGHUP is important especially for systemd systems, where logind
    # sends it when a session exits, in addition to any traditional use.
    # Output some info if we receive SIGUSR1 or SIGINFO (ctrl-t).

    # Register fault handler for SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL.
    faulthandler.enable()
    with signal_handler('SIGINT', raising_signal_handler(KeyboardInterrupt)), \
         signal_handler('SIGHUP', raising_signal_handler(SigHup)), \
         signal_handler('SIGTERM', raising_signal_handler(SigTerm)), \
         signal_handler('SIGUSR1', sig_info_handler), \
         signal_handler('SIGUSR2', sig_trace_handler), \
         signal_handler('SIGINFO', sig_info_handler):
        archiver = Archiver()
        msg = tb = None
        tb_log_level = logging.ERROR
        try:
            args = archiver.get_args(sys.argv, os.environ.get('SSH_ORIGINAL_COMMAND'))
        except Error as e:
            msg = e.get_message()
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = '%s\n%s' % (traceback.format_exc(), sysinfo())
            # we might not have logging setup yet, so get out quickly
            print(msg, file=sys.stderr)
            if tb_log_level == logging.ERROR:
                print(tb, file=sys.stderr)
            sys.exit(e.exit_code)
        try:
            exit_code = archiver.run(args)
        except Error as e:
            msg = e.get_message()
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = "%s\n%s" % (traceback.format_exc(), sysinfo())
            exit_code = e.exit_code
        except RemoteRepository.RPCError as e:
            important = e.exception_class not in ('LockTimeout', )
            tb_log_level = logging.ERROR if important else logging.DEBUG
            if important:
                msg = e.exception_full
            else:
                msg = e.get_message()
            tb = '\n'.join('Borg server: ' + l for l in e.sysinfo.splitlines())
            tb += "\n" + sysinfo()
            exit_code = EXIT_ERROR
        except Exception:
            msg = 'Local Exception'
            tb_log_level = logging.ERROR
            tb = '%s\n%s' % (traceback.format_exc(), sysinfo())
            exit_code = EXIT_ERROR
        except KeyboardInterrupt:
            msg = 'Keyboard interrupt'
            tb_log_level = logging.DEBUG
            tb = '%s\n%s' % (traceback.format_exc(), sysinfo())
            exit_code = EXIT_ERROR
        except SigTerm:
            msg = 'Received SIGTERM'
            tb_log_level = logging.DEBUG
            tb = '%s\n%s' % (traceback.format_exc(), sysinfo())
            exit_code = EXIT_ERROR
        except SigHup:
            msg = 'Received SIGHUP.'
            exit_code = EXIT_ERROR
        if msg:
            logger.error(msg)
        if tb:
            logger.log(tb_log_level, tb)
        if args.show_rc:
            rc_logger = logging.getLogger('borg.output.show-rc')
            exit_msg = 'terminating with %s status, rc %d'
            if exit_code == EXIT_SUCCESS:
                rc_logger.info(exit_msg % ('success', exit_code))
            elif exit_code == EXIT_WARNING:
                rc_logger.warning(exit_msg % ('warning', exit_code))
            elif exit_code == EXIT_ERROR:
                rc_logger.error(exit_msg % ('error', exit_code))
            else:
                rc_logger.error(exit_msg % ('abnormal', exit_code or 666))
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
