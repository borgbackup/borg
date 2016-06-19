from binascii import hexlify, unhexlify
from datetime import datetime
from hashlib import sha256
from operator import attrgetter
import argparse
import errno
import functools
import inspect
import io
import os
import re
import shlex
import signal
import stat
import sys
import textwrap
import traceback

from . import __version__
from .helpers import Error, location_validator, archivename_validator, format_line, format_time, format_file_size, \
    parse_pattern, PathPrefixPattern, to_localtime, timestamp, safe_timestamp, \
    get_cache_dir, prune_within, prune_split, \
    Manifest, NoManifestError, remove_surrogates, update_excludes, format_archive, check_extension_modules, Statistics, \
    dir_is_tagged, bigint_to_int, ChunkerParams, CompressionSpec, is_slow_msgpack, yes, sysinfo, \
    EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR, log_multi, PatternMatcher
from .logger import create_logger, setup_logging
logger = create_logger()
from .compress import Compressor, COMPR_BUFFER
from .upgrader import AtticRepositoryUpgrader, BorgRepositoryUpgrader
from .repository import Repository
from .cache import Cache
from .key import key_creator, RepoKey, PassphraseKey
from .archive import Archive, ArchiveChecker, CHUNKER_PARAMS
from .remote import RepositoryServer, RemoteRepository, cache_if_remote

has_lchflags = hasattr(os, 'lchflags')

# default umask, overriden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077

DASHES = '-' * 78


def argument(args, str_or_bool):
    """If bool is passed, return it. If str is passed, retrieve named attribute from args."""
    if isinstance(str_or_bool, str):
        return getattr(args, str_or_bool)
    return str_or_bool


def with_repository(fake=False, create=False, lock=True, exclusive=False, manifest=True, cache=False):
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
            if argument(args, fake):
                return method(self, args, repository=None, **kwargs)
            elif location.proto == 'ssh':
                repository = RemoteRepository(location, create=create, lock_wait=self.lock_wait, lock=lock, args=args)
            else:
                repository = Repository(location.path, create=create, exclusive=argument(args, exclusive),
                                        lock_wait=self.lock_wait, lock=lock)
            with repository:
                if manifest or cache:
                    kwargs['manifest'], kwargs['key'] = Manifest.load(repository)
                if cache:
                    with Cache(repository, kwargs['key'], kwargs['manifest'],
                               do_files=getattr(args, 'cache_files', False), lock_wait=self.lock_wait) as cache_:
                        return method(self, args, repository=repository, cache=cache_, **kwargs)
                else:
                    return method(self, args, repository=repository, **kwargs)
        return wrapper
    return decorator


def with_archive(method):
    @functools.wraps(method)
    def wrapper(self, args, repository, key, manifest, **kwargs):
        archive = Archive(repository, key, manifest, args.location.archive,
                          numeric_owner=getattr(args, 'numeric_owner', False), cache=kwargs.get('cache'))
        return method(self, args, repository=repository, manifest=manifest, key=key, archive=archive, **kwargs)
    return wrapper


class Archiver:

    def __init__(self, lock_wait=None):
        self.exit_code = EXIT_SUCCESS
        self.lock_wait = lock_wait

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
            logger.info("%1s %s", status, remove_surrogates(path))

    def do_serve(self, args):
        """Start in server mode. This command is usually not used manually.
        """
        return RepositoryServer(restrict_to_paths=args.restrict_to_paths).serve()

    @with_repository(create=True, exclusive=True, manifest=False)
    def do_init(self, args, repository):
        """Initialize an empty repository"""
        logger.info('Initializing repository at "%s"' % args.location.canonical_path())
        key = key_creator(repository, args)
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit()
        with Cache(repository, key, manifest, warn_if_unencrypted=False):
            pass
        return self.exit_code

    @with_repository(exclusive='repair', manifest=False)
    def do_check(self, args, repository):
        """Check repository consistency"""
        if args.repair:
            msg = ("'check --repair' is an experimental feature that might result in data loss." +
                   "\n" +
                   "Type 'YES' if you understand this and want to continue: ")
            if not yes(msg, false_msg="Aborting.", truish=('YES', ),
                       env_var_override='BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'):
                return EXIT_ERROR
        if not args.archives_only:
            if not repository.check(repair=args.repair, save_space=args.save_space):
                return EXIT_WARNING
        if not args.repo_only and not ArchiveChecker().check(
                repository, repair=args.repair, archive=args.location.archive,
                last=args.last, prefix=args.prefix, save_space=args.save_space):
            return EXIT_WARNING
        return EXIT_SUCCESS

    @with_repository()
    def do_change_passphrase(self, args, repository, manifest, key):
        """Change repository key file passphrase"""
        key.change_passphrase()
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
        return EXIT_SUCCESS

    @with_repository(fake='dry_run')
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
                        except OSError as e:
                            status = 'E'
                            self.print_warning('%s: %s', path, e)
                    else:
                        status = '-'
                    self.print_file_status(status, path)
                    continue
                path = os.path.normpath(path)
                if args.one_file_system:
                    try:
                        restrict_dev = os.lstat(path).st_dev
                    except OSError as e:
                        self.print_warning('%s: %s', path, e)
                        continue
                else:
                    restrict_dev = None
                if self._process(archive, cache, matcher, args.exclude_caches, args.exclude_if_present,
                              args.keep_tag_files, skip_inodes, path, restrict_dev,
                              read_special=args.read_special, dry_run=dry_run):
                              return
            if not dry_run:
                archive.save(timestamp=args.timestamp)
                if args.progress:
                    archive.stats.show_progress(final=True)
                if args.stats:
                    archive.end = datetime.utcnow()
                    log_multi(DASHES,
                              str(archive),
                              DASHES,
                              str(archive.stats),
                              str(cache),
                              DASHES)

        self.output_filter = args.output_filter
        self.output_list = args.output_list
        self.ignore_inode = args.ignore_inode
        dry_run = args.dry_run
        t0 = datetime.utcnow()
        if not dry_run:
            compr_args = dict(buffer=COMPR_BUFFER)
            compr_args.update(args.compression)
            key.compressor = Compressor(**compr_args)
            with Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait) as cache:
                archive = Archive(repository, key, manifest, args.location.archive, cache=cache,
                                  create=True, checkpoint_interval=args.checkpoint_interval,
                                  numeric_owner=args.numeric_owner, progress=args.progress,
                                  chunker_params=args.chunker_params, start=t0)
                create_inner(archive, cache)
        else:
            create_inner(None, None)
        return self.exit_code

    def _process(self, archive, cache, matcher, exclude_caches, exclude_if_present,
                 keep_tag_files, skip_inodes, path, restrict_dev,
                 read_special=False, dry_run=False):
        if not matcher.match(path):
            return

        try:
            st = os.lstat(path)
        except OSError as e:
            self.print_warning('%s: %s', path, e)
            return
        if (st.st_ino, st.st_dev) in skip_inodes:
            return
        # Entering a new filesystem?
        if restrict_dev is not None and st.st_dev != restrict_dev:
            return
        status = None
        # Ignore if nodump flag is set
        if has_lchflags and (st.st_flags & stat.UF_NODUMP):
            return
        if stat.S_ISREG(st.st_mode) or read_special and not stat.S_ISDIR(st.st_mode):
            if not dry_run:
                try:
                    status = archive.process_file(path, st, cache, self.ignore_inode)
                except OSError as e:
                    if e.errno == errno.EIO:
                        return e.errno
                    status = 'E'
                    self.print_warning('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            tag_paths = dir_is_tagged(path, exclude_caches, exclude_if_present)
            if tag_paths:
                if keep_tag_files and not dry_run:
                    archive.process_dir(path, st)
                    for tag_path in tag_paths:
                        if self._process(archive, cache, matcher, exclude_caches, exclude_if_present,
                                      keep_tag_files, skip_inodes, tag_path, restrict_dev,
                                      read_special=read_special, dry_run=dry_run):
                                      return errno.EIO
                return
            if not dry_run:
                try:
                    status = archive.process_dir(path, st)
                except OSError as e:
                    if e.errno == errno.EIO:
                        return e.errno
            try:
                entries = os.listdir(path)
            except OSError as e:
                status = 'E'
                self.print_warning('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    entry_path = os.path.normpath(os.path.join(path, filename))
                    if self._process(archive, cache, matcher, exclude_caches, exclude_if_present,
                                  keep_tag_files, skip_inodes, entry_path, restrict_dev,
                                  read_special=read_special, dry_run=dry_run):
                                  return errno.EIO
        elif stat.S_ISLNK(st.st_mode):
            if not dry_run:
                try:
                    status = archive.process_symlink(path, st)
                except OSError as e:
                    if e.errno == errno.EIO:
                        return e.errno
        elif stat.S_ISFIFO(st.st_mode):
            if not dry_run:
                try:
                    status = archive.process_fifo(path, st)
                except OSError as e:
                    if e.errno == errno.EIO:
                        return e.errno
        elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
            if not dry_run:
                try:
                    status = archive.process_dev(path, st)
                except OSError as e:
                    if e.errno == errno.EIO:
                        return e.errno
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

    @with_repository()
    @with_archive
    def do_extract(self, args, repository, manifest, key, archive):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == 'ascii':
            logger.warning('Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.')
            if sys.platform.startswith(('linux', 'freebsd', 'netbsd', 'openbsd', 'darwin', )):
                logger.warning('Hint: You likely need to fix your locale setup. E.g. install locales and use: LANG=en_US.UTF-8')

        matcher = PatternMatcher()
        if args.excludes:
            matcher.add(args.excludes, False)

        include_patterns = []

        if args.paths:
            include_patterns.extend(parse_pattern(i, PathPrefixPattern) for i in args.paths)
            matcher.add(include_patterns, True)

        matcher.fallback = not include_patterns

        output_list = args.output_list
        dry_run = args.dry_run
        stdout = args.stdout
        sparse = args.sparse
        strip_components = args.strip_components
        dirs = []
        for item in archive.iter_items(lambda item: matcher.match(item[b'path']), preload=True):
            orig_path = item[b'path']
            if strip_components:
                item[b'path'] = os.sep.join(orig_path.split(os.sep)[strip_components:])
                if not item[b'path']:
                    continue
            if not args.dry_run:
                while dirs and not item[b'path'].startswith(dirs[-1][b'path']):
                    archive.extract_item(dirs.pop(-1), stdout=stdout)
            if output_list:
                logger.info(remove_surrogates(orig_path))
            try:
                if dry_run:
                    archive.extract_item(item, dry_run=True)
                else:
                    if stat.S_ISDIR(item[b'mode']):
                        dirs.append(item)
                        archive.extract_item(item, restore_attrs=False)
                    else:
                        archive.extract_item(item, stdout=stdout, sparse=sparse)
            except OSError as e:
                self.print_warning('%s: %s', remove_surrogates(orig_path), e)

        if not args.dry_run:
            while dirs:
                archive.extract_item(dirs.pop(-1))
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
        """Delete an existing repository or archive"""
        if args.location.archive:
            manifest, key = Manifest.load(repository)
            with Cache(repository, key, manifest, lock_wait=self.lock_wait) as cache:
                archive = Archive(repository, key, manifest, args.location.archive, cache=cache)
                stats = Statistics()
                archive.delete(stats, progress=args.progress)
                manifest.write()
                repository.commit(save_space=args.save_space)
                cache.commit()
                logger.info("Archive deleted.")
                if args.stats:
                    log_multi(DASHES,
                              stats.summary.format(label='Deleted data:', stats=stats),
                              str(cache),
                              DASHES)
        else:
            if not args.cache_only:
                msg = []
                try:
                    manifest, key = Manifest.load(repository)
                except NoManifestError:
                    msg.append("You requested to completely DELETE the repository *including* all archives it may contain.")
                    msg.append("This repository seems to have no manifest, so we can't tell anything about its contents.")
                else:
                    msg.append("You requested to completely DELETE the repository *including* all archives it contains:")
                    for archive_info in manifest.list_archive_infos(sort_by='ts'):
                        msg.append(format_archive(archive_info))
                msg.append("Type 'YES' if you understand this and want to continue: ")
                msg = '\n'.join(msg)
                if not yes(msg, false_msg="Aborting.", truish=('YES', ),
                           env_var_override='BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'):
                    self.exit_code = EXIT_ERROR
                    return self.exit_code
                repository.destroy()
                logger.info("Repository deleted.")
            Cache.destroy(repository)
            logger.info("Cache deleted.")
        return self.exit_code

    @with_repository()
    def do_mount(self, args, repository, manifest, key):
        """Mount archive or an entire repository as a FUSE fileystem"""
        try:
            from .fuse import FuseOperations
        except ImportError as e:
            self.print_error('Loading fuse support failed [ImportError: %s]' % str(e))
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error('%s: Mountpoint must be a writable directory' % args.mountpoint)
            return self.exit_code

        with cache_if_remote(repository) as cached_repo:
            if args.location.archive:
                archive = Archive(repository, key, manifest, args.location.archive)
            else:
                archive = None
            operations = FuseOperations(key, repository, manifest, archive, cached_repo)
            logger.info("Mounting filesystem")
            try:
                operations.mount(args.mountpoint, args.options, args.foreground)
            except RuntimeError:
                # Relevant error message already printed to stderr by fuse
                self.exit_code = EXIT_ERROR
        return self.exit_code

    @with_repository()
    def do_list(self, args, repository, manifest, key):
        """List archive or repository contents"""
        if args.location.archive:
            archive = Archive(repository, key, manifest, args.location.archive)
            """use_user_format flag is used to speed up default listing.
            When user issues format options, listing is a bit slower, but more keys are available and
            precalculated.
            """
            use_user_format = args.listformat is not None
            if use_user_format:
                list_format = args.listformat
            elif args.short:
                list_format = "{path}{LF}"
            else:
                list_format = "{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{LF}"

            for item in archive.iter_items():
                mode = stat.filemode(item[b'mode'])
                type = mode[0]
                size = 0
                if type == '-':
                    try:
                        size = sum(size for _, size, _ in item[b'chunks'])
                    except KeyError:
                        pass

                mtime = safe_timestamp(item[b'mtime'])
                if use_user_format:
                    atime = safe_timestamp(item.get(b'atime') or item[b'mtime'])
                    ctime = safe_timestamp(item.get(b'ctime') or item[b'mtime'])

                if b'source' in item:
                    source = item[b'source']
                    if type == 'l':
                        extra = ' -> %s' % item[b'source']
                    else:
                        mode = 'h' + mode[1:]
                        extra = ' link to %s' % item[b'source']
                else:
                    extra = ''
                    source = ''

                item_data = {
                        'mode': mode,
                        'user': item[b'user'] or item[b'uid'],
                        'group': item[b'group'] or item[b'gid'],
                        'size': size,
                        'isomtime': format_time(mtime),
                        'path': remove_surrogates(item[b'path']),
                        'extra': extra,
                        'LF': '\n',
                        }
                if use_user_format:
                    item_data_advanced = {
                        'bmode': item[b'mode'],
                        'type': type,
                        'source': source,
                        'linktarget': source,
                        'uid': item[b'uid'],
                        'gid': item[b'gid'],
                        'mtime': mtime,
                        'isoctime': format_time(ctime),
                        'ctime': ctime,
                        'isoatime': format_time(atime),
                        'atime': atime,
                        'archivename': archive.name,
                        'SPACE': ' ',
                        'TAB': '\t',
                        'CR': '\r',
                        'NEWLINE': os.linesep,
                        }
                    item_data.update(item_data_advanced)
                item_data['formatkeys'] = list(item_data.keys())

                print(format_line(list_format, item_data), end='')
        else:
            for archive_info in manifest.list_archive_infos(sort_by='ts'):
                if args.prefix and not archive_info.name.startswith(args.prefix):
                    continue
                if args.short:
                    print(archive_info.name)
                else:
                    print(format_archive(archive_info))
        return self.exit_code

    @with_repository(cache=True)
    @with_archive
    def do_info(self, args, repository, manifest, key, archive, cache):
        """Show archive details such as disk space used"""
        stats = archive.calc_stats(cache)
        print('Name:', archive.name)
        print('Fingerprint: %s' % hexlify(archive.id).decode('ascii'))
        print('Hostname:', archive.metadata[b'hostname'])
        print('Username:', archive.metadata[b'username'])
        print('Time (start): %s' % format_time(to_localtime(archive.ts)))
        print('Time (end):   %s' % format_time(to_localtime(archive.ts_end)))
        print('Command line:', remove_surrogates(' '.join(archive.metadata[b'cmdline'])))
        print('Number of files: %d' % stats.nfiles)
        print()
        print(str(stats))
        print(str(cache))
        return self.exit_code

    @with_repository()
    def do_prune(self, args, repository, manifest, key):
        """Prune repository archives according to specified rules"""
        if not any((args.hourly, args.daily,
                    args.weekly, args.monthly, args.yearly, args.within)):
            self.print_error('At least one of the "keep-within", "keep-last", '
                             '"keep-hourly", "keep-daily", '
                             '"keep-weekly", "keep-monthly" or "keep-yearly" settings must be specified.')
            return self.exit_code
        archives = manifest.list_archive_infos(sort_by='ts', reverse=True)  # just a ArchiveInfo list
        if args.prefix:
            archives = [archive for archive in archives if archive.name.startswith(args.prefix)]
        # ignore all checkpoint archives to avoid keeping one (which is an incomplete backup)
        # that is newer than a successfully completed backup - and killing the successful backup.
        is_checkpoint = re.compile(r'\.checkpoint(\.\d+)?$').search
        archives = [archive for archive in archives if not is_checkpoint(archive.name)]
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
        with Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait) as cache:
            for archive in keep:
                if args.output_list:
                    logger.info('Keeping archive: %s' % format_archive(archive))
            for archive in to_delete:
                if args.dry_run:
                    if args.output_list:
                        logger.info('Would prune:     %s' % format_archive(archive))
                else:
                    if args.output_list:
                        logger.info('Pruning archive: %s' % format_archive(archive))
                    Archive(repository, key, manifest, archive.name, cache).delete(stats)
            if to_delete and not args.dry_run:
                manifest.write()
                repository.commit(save_space=args.save_space)
                cache.commit()
            if args.stats:
                log_multi(DASHES,
                          stats.summary.format(label='Deleted data:', stats=stats),
                          str(cache),
                          DASHES)
        return self.exit_code

    def do_upgrade(self, args):
        """upgrade a repository from a previous version"""
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

    @with_repository()
    def do_debug_dump_archive_items(self, args, repository, manifest, key):
        """dump (decrypted, decompressed) archive items metadata (not: data)"""
        archive = Archive(repository, key, manifest, args.location.archive)
        for i, item_id in enumerate(archive.metadata[b'items']):
            data = key.decrypt(item_id, repository.get(item_id))
            filename = '%06d_%s.items' % (i, hexlify(item_id).decode('ascii'))
            print('Dumping', filename)
            with open(filename, 'wb') as fd:
                fd.write(data)
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
            except repository.ObjectNotFound:
                print("object %s not found." % hex_id)
            else:
                with open(args.path, "wb") as f:
                    f.write(data)
                print("object %s fetched." % hex_id)
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_debug_put_obj(self, args, repository):
        """put file(s) contents into the repository"""
        for path in args.paths:
            with open(path, "rb") as f:
                data = f.read()
            h = sha256(data)  # XXX hardcoded
            repository.put(h.digest(), data)
            print("object %s put." % h.hexdigest())
        repository.commit()
        return EXIT_SUCCESS

    @with_repository(manifest=False)
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
                except repository.ObjectNotFound:
                    print("object %s not found." % hex_id)
        if modified:
            repository.commit()
        print('Done.')
        return EXIT_SUCCESS

    @with_repository(lock=False, manifest=False)
    def do_break_lock(self, args, repository):
        """Break the repository lock (e.g. in case it was left by a dead borg."""
        repository.break_lock()
        Cache.break_lock(repository)
        return self.exit_code

    helptext = {}
    helptext['patterns'] = textwrap.dedent('''
        Exclusion patterns support four separate styles, fnmatch, shell, regular
        expressions and path prefixes. If followed by a colon (':') the first two
        characters of a pattern are used as a style selector. Explicit style
        selection is necessary when a non-default style is desired or when the
        desired pattern starts with two alphanumeric characters followed by a colon
        (i.e. `aa:something/*`).

        `Fnmatch <https://docs.python.org/3/library/fnmatch.html>`_, selector `fm:`

            These patterns use a variant of shell pattern syntax, with '*' matching
            any number of characters, '?' matching any single character, '[...]'
            matching any single character specified, including ranges, and '[!...]'
            matching any character not specified. For the purpose of these patterns,
            the path separator ('\\' for Windows and '/' on other systems) is not
            treated specially. Wrap meta-characters in brackets for a literal match
            (i.e. `[?]` to match the literal character `?`). For a path to match
            a pattern, it must completely match from start to end, or must match from
            the start to just before a path separator. Except for the root path,
            paths will never end in the path separator when matching is attempted.
            Thus, if a given pattern ends in a path separator, a '*' is appended
            before matching is attempted.

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
        $ borg create --exclude-from exclude.txt backup /
        ''')

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
            # ('--old', '--new', 'Warning: "--old" has been deprecated. Use "--new" instead.'),
        ]
        for i, arg in enumerate(args[:]):
            for old_name, new_name, warning in deprecations:
                if arg.startswith(old_name):
                    args[i] = arg.replace(old_name, new_name)
                    print(warning)
        return args

    def build_parser(self, args=None, prog=None):
        common_parser = argparse.ArgumentParser(add_help=False, prog=prog)
        common_parser.add_argument('--critical', dest='log_level',
                                   action='store_const', const='critical', default='warning',
                                   help='work on log level CRITICAL')
        common_parser.add_argument('--error', dest='log_level',
                                   action='store_const', const='error', default='warning',
                                   help='work on log level ERROR')
        common_parser.add_argument('--warning', dest='log_level',
                                   action='store_const', const='warning', default='warning',
                                   help='work on log level WARNING (default)')
        common_parser.add_argument('--info', '-v', '--verbose', dest='log_level',
                                   action='store_const', const='info', default='warning',
                                   help='work on log level INFO')
        common_parser.add_argument('--debug', dest='log_level',
                                   action='store_const', const='debug', default='warning',
                                   help='work on log level DEBUG')
        common_parser.add_argument('--lock-wait', dest='lock_wait', type=int, metavar='N', default=1,
                                   help='wait for the lock, but max. N seconds (default: %(default)d).')
        common_parser.add_argument('--show-rc', dest='show_rc', action='store_true', default=False,
                                   help='show/log the return code (rc)')
        common_parser.add_argument('--no-files-cache', dest='cache_files', action='store_false',
                                   help='do not load/update the file metadata cache used to detect unchanged files')
        common_parser.add_argument('--umask', dest='umask', type=lambda s: int(s, 8), default=UMASK_DEFAULT, metavar='M',
                                   help='set umask to M (local and remote, default: %(default)04o)')
        common_parser.add_argument('--remote-path', dest='remote_path', default='borg', metavar='PATH',
                                   help='set remote path to executable (default: "%(default)s")')

        parser = argparse.ArgumentParser(prog=prog, description='Borg - Deduplicated Backups')
        parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__,
                                   help='show version number and exit')
        subparsers = parser.add_subparsers(title='required arguments', metavar='<command>')

        serve_epilog = textwrap.dedent("""
        This command starts a repository server process. This command is usually not used manually.
        """)
        subparser = subparsers.add_parser('serve', parents=[common_parser],
                                          description=self.do_serve.__doc__, epilog=serve_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='start repository server process')
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='initialize empty repository')
        subparser.set_defaults(func=self.do_init)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to create')
        subparser.add_argument('-e', '--encryption', dest='encryption',
                               choices=('none', 'keyfile', 'repokey'), default='repokey',
                               help='select encryption key mode (default: "%(default)s")')

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
        subparser.add_argument('--repair', dest='repair', action='store_true',
                               default=False,
                               help='attempt to repair any inconsistencies found')
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('--last', dest='last',
                               type=int, default=None, metavar='N',
                               help='only check last N archives (Default: all)')
        subparser.add_argument('-P', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')

        change_passphrase_epilog = textwrap.dedent("""
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.
        """)
        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser],
                                          description=self.do_change_passphrase.__doc__,
                                          epilog=change_passphrase_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='change repository passphrase')
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))

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
        subparser = subparsers.add_parser('migrate-to-repokey', parents=[common_parser],
                                          description=self.do_migrate_to_repokey.__doc__,
                                          epilog=migrate_to_repokey_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='migrate passphrase-mode repository to repokey')
        subparser.set_defaults(func=self.do_migrate_to_repokey)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False))

        create_epilog = textwrap.dedent("""
        This command creates a backup archive containing all files found while recursively
        traversing all paths specified. The archive will consume almost no disk space for
        files or parts of files that have already been stored in other archives.

        The archive name needs to be unique. It must not end in '.checkpoint' or
        '.checkpoint.N' (with N being a number), because these names are used for
        checkpoints and treated in special ways.

        In the archive name, you may use the following format tags:
        {now}, {utcnow}, {fqdn}, {hostname}, {user}, {pid}

        To speed up pulling backups over sshfs and similar network file systems which do
        not provide correct inode information the --ignore-inode flag can be used. This
        potentially decreases reliability of change detection, while avoiding always reading
        all files on these file systems.

        See the output of the "borg help patterns" command for more help on exclude patterns.
        """)

        subparser = subparsers.add_parser('create', parents=[common_parser],
                                          description=self.do_create.__doc__,
                                          epilog=create_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='create backup')
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the created archive')
        subparser.add_argument('-p', '--progress', dest='progress',
                               action='store_true', default=False,
                               help="""show progress display while creating the archive, showing Original,
                               Compressed and Deduplicated sizes, followed by the Number of files seen
                               and the path being processed, default: %(default)s""")
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of items (files, dirs, ...)')
        subparser.add_argument('--filter', dest='output_filter', metavar='STATUSCHARS',
                               help='only display items with the given status characters')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=parse_pattern, action='append',
                               metavar="PATTERN", help='exclude paths matching PATTERN')
        subparser.add_argument('--exclude-from', dest='exclude_files',
                               type=argparse.FileType('r'), action='append',
                               metavar='EXCLUDEFILE', help='read exclude patterns from EXCLUDEFILE, one per line')
        subparser.add_argument('--exclude-caches', dest='exclude_caches',
                               action='store_true', default=False,
                               help='exclude directories that contain a CACHEDIR.TAG file (http://www.brynosaurus.com/cachedir/spec.html)')
        subparser.add_argument('--exclude-if-present', dest='exclude_if_present',
                               metavar='FILENAME', action='append', type=str,
                               help='exclude directories that contain the specified file')
        subparser.add_argument('--keep-tag-files', dest='keep_tag_files',
                               action='store_true', default=False,
                               help='keep tag files of excluded caches/directories')
        subparser.add_argument('-c', '--checkpoint-interval', dest='checkpoint_interval',
                               type=int, default=300, metavar='SECONDS',
                               help='write checkpoint every SECONDS seconds (Default: 300)')
        subparser.add_argument('-x', '--one-file-system', dest='one_file_system',
                               action='store_true', default=False,
                               help='stay in same file system, do not cross mount points')
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
        subparser.add_argument('--ignore-inode', dest='ignore_inode',
                               action='store_true', default=False,
                               help='ignore inode data in the file metadata cache used to detect unchanged files.')
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
        """)
        subparser = subparsers.add_parser('extract', parents=[common_parser],
                                          description=self.do_extract.__doc__,
                                          epilog=extract_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='extract archive contents')
        subparser.set_defaults(func=self.do_extract)
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

        rename_epilog = textwrap.dedent("""
        This command renames an archive in the repository.
        """)
        subparser = subparsers.add_parser('rename', parents=[common_parser],
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
        subparser = subparsers.add_parser('delete', parents=[common_parser],
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
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('location', metavar='TARGET', nargs='?', default='',
                               type=location_validator(),
                               help='archive or repository to delete')

        list_epilog = textwrap.dedent("""
        This command lists the contents of a repository or an archive.
        """)
        subparser = subparsers.add_parser('list', parents=[common_parser],
                                          description=self.do_list.__doc__,
                                          epilog=list_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='list archive or repository contents')
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('--short', dest='short',
                               action='store_true', default=False,
                               help='only print file/directory names, nothing else')
        subparser.add_argument('--list-format', dest='listformat', type=str,
                               help="""specify format for archive file listing
                                (default: "{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}")
                                Special "{formatkeys}" exists to list available keys""")
        subparser.add_argument('-P', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')
        subparser.add_argument('location', metavar='REPOSITORY_OR_ARCHIVE', nargs='?', default='',
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

        info_epilog = textwrap.dedent("""
        This command displays some detailed information about the specified archive.
        """)
        subparser = subparsers.add_parser('info', parents=[common_parser],
                                          description=self.do_info.__doc__,
                                          epilog=info_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='show archive information')
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('location', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to display information about')

        break_lock_epilog = textwrap.dedent("""
        This command breaks the repository and cache locks.
        Please use carefully and only while no borg process (on any machine) is
        trying to access the Cache or the Repository.
        """)
        subparser = subparsers.add_parser('break-lock', parents=[common_parser],
                                          description=self.do_break_lock.__doc__,
                                          epilog=break_lock_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='break repository and cache locks')
        subparser.set_defaults(func=self.do_break_lock)
        subparser.add_argument('location', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository for which to break the locks')

        prune_epilog = textwrap.dedent("""
        The prune command prunes a repository by deleting all archives not matching
        any of the specified retention options. This command is normally used by
        automated backup scripts wanting to keep a certain number of historic backups.

        As an example, "-d 7" means to keep the latest backup on each day, up to 7
        most recent days with backups (days without backups do not count).
        The rules are applied from hourly to yearly, and backups selected by previous
        rules do not count towards those of later rules. The time that each backup
        starts is used for pruning purposes. Dates and times are interpreted in
        the local timezone, and weeks go from Monday to Sunday. Specifying a
        negative number of archives to keep means that there is no limit.

        The "--keep-within" option takes an argument of the form "<int><char>",
        where char is "H", "d", "w", "m", "y". For example, "--keep-within 2d" means
        to keep all archives that were created within the past 48 hours.
        "1m" is taken to mean "31d". The archives kept with this option do not
        count towards the totals specified by any other options.

        If a prefix is set with -P, then only archives that start with the prefix are
        considered for deletion and only those archives count towards the totals
        specified by the rules.
        Otherwise, *all* archives in the repository are candidates for deletion!
        """)
        subparser = subparsers.add_parser('prune', parents=[common_parser],
                                          description=self.do_prune.__doc__,
                                          epilog=prune_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='prune archives')
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument('-n', '--dry-run', dest='dry_run',
                               default=False, action='store_true',
                               help='do not change repository')
        subparser.add_argument('-s', '--stats', dest='stats',
                               action='store_true', default=False,
                               help='print statistics for the deleted archive')
        subparser.add_argument('--list', dest='output_list',
                               action='store_true', default=False,
                               help='output verbose list of archives it keeps/prunes')
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
        subparser.add_argument('-P', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to prune')

        upgrade_epilog = textwrap.dedent("""
        Upgrade an existing Borg repository.
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
        subparser = subparsers.add_parser('upgrade', parents=[common_parser],
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
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='path to the repository to be upgraded')

        subparser = subparsers.add_parser('help', parents=[common_parser],
                                          description='Extra help')
        subparser.add_argument('--epilog-only', dest='epilog_only',
                               action='store_true', default=False)
        subparser.add_argument('--usage-only', dest='usage_only',
                               action='store_true', default=False)
        subparser.set_defaults(func=functools.partial(self.do_help, parser, subparsers.choices))
        subparser.add_argument('topic', metavar='TOPIC', type=str, nargs='?',
                               help='additional help on TOPIC')

        debug_dump_archive_items_epilog = textwrap.dedent("""
        This command dumps raw (but decrypted and decompressed) archive items (only metadata) to files.
        """)
        subparser = subparsers.add_parser('debug-dump-archive-items', parents=[common_parser],
                                          description=self.do_debug_dump_archive_items.__doc__,
                                          epilog=debug_dump_archive_items_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          help='dump archive items (metadata) (debug)')
        subparser.set_defaults(func=self.do_debug_dump_archive_items)
        subparser.add_argument('location', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='archive to dump')

        debug_get_obj_epilog = textwrap.dedent("""
        This command gets an object from the repository.
        """)
        subparser = subparsers.add_parser('debug-get-obj', parents=[common_parser],
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
        subparser = subparsers.add_parser('debug-put-obj', parents=[common_parser],
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
        subparser = subparsers.add_parser('debug-delete-obj', parents=[common_parser],
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
        return parser

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
            # the only thing we take from the forced "borg serve" ssh command is --restrict-to-path
            result.restrict_to_paths = forced_result.restrict_to_paths
        return result

    def parse_args(self, args=None):
        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)
        parser = self.build_parser(args)
        args = parser.parse_args(args or ['-h'])
        update_excludes(args)
        return args

    def run(self, args):
        os.umask(args.umask)  # early, before opening files
        self.lock_wait = args.lock_wait
        setup_logging(level=args.log_level, is_serve=args.func == self.do_serve)  # do not use loggers before this!
        check_extension_modules()
        if is_slow_msgpack():
            logger.warning("Using a pure-python msgpack! This will result in lower performance.")
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
            logger.info("{0} {1}/{2}".format(path, format_file_size(pos), format_file_size(total)))
            break
        if func in ('extract_item', ):  # extract op
            path = loc['item'][b'path']
            try:
                pos = loc['fd'].tell()
            except Exception:
                pos = 0
            logger.info("{0} {1}/???".format(path, format_file_size(pos)))
            break


class SIGTERMReceived(BaseException):
    pass


def sig_term_handler(signum, stack):
    raise SIGTERMReceived


def setup_signal_handlers():  # pragma: no cover
    sigs = []
    if hasattr(signal, 'SIGUSR1'):
        sigs.append(signal.SIGUSR1)  # kill -USR1 pid
    if hasattr(signal, 'SIGINFO'):
        sigs.append(signal.SIGINFO)  # kill -INFO pid (or ctrl-t)
    for sig in sigs:
        signal.signal(sig, sig_info_handler)
    signal.signal(signal.SIGTERM, sig_term_handler)


def main():  # pragma: no cover
    # Make sure stdout and stderr have errors='replace') to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, 'replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, 'replace', line_buffering=True)
    setup_signal_handlers()
    archiver = Archiver()
    msg = None
    args = archiver.get_args(sys.argv, os.environ.get('SSH_ORIGINAL_COMMAND'))
    try:
        exit_code = archiver.run(args)
    except Error as e:
        msg = e.get_message()
        if e.traceback:
            msg += "\n%s\n%s" % (traceback.format_exc(), sysinfo())
        exit_code = e.exit_code
    except RemoteRepository.RPCError as e:
        msg = '%s\n%s' % (str(e), sysinfo())
        exit_code = EXIT_ERROR
    except OSError as e:
        msg = '%s\n%s' % (str(e), sysinfo())
        exit_code = EXIT_ERROR
    except Exception:
        msg = 'Local Exception.\n%s\n%s' % (traceback.format_exc(), sysinfo())
        exit_code = EXIT_ERROR
    except KeyboardInterrupt:
        msg = 'Keyboard interrupt.\n%s\n%s' % (traceback.format_exc(), sysinfo())
        exit_code = EXIT_ERROR
    except SIGTERMReceived:
        msg = 'Received SIGTERM.'
        exit_code = EXIT_ERROR
    if msg:
        logger.error(msg)
    if args.show_rc:
        exit_msg = 'terminating with %s status, rc %d'
        if exit_code == EXIT_SUCCESS:
            logger.info(exit_msg % ('success', exit_code))
        elif exit_code == EXIT_WARNING:
            logger.warning(exit_msg % ('warning', exit_code))
        elif exit_code == EXIT_ERROR:
            logger.error(exit_msg % ('error', exit_code))
        else:
            # if you see 666 in output, it usually means exit_code was None
            logger.error(exit_msg % ('abnormal', exit_code or 666))
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
