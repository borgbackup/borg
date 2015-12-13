from .support import argparse  # see support/__init__.py docstring
                               # DEPRECATED - remove after requiring py 3.4

from binascii import hexlify
from datetime import datetime
from hashlib import sha256
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
from .helpers import Error, location_validator, format_time, format_file_size, \
    format_file_mode, ExcludePattern, IncludePattern, exclude_path, adjust_patterns, to_localtime, timestamp, \
    get_cache_dir, get_keys_dir, prune_within, prune_split, unhexlify, \
    Manifest, remove_surrogates, update_excludes, format_archive, check_extension_modules, Statistics, \
    dir_is_tagged, bigint_to_int, ChunkerParams, CompressionSpec, is_slow_msgpack, yes, sysinfo, \
    EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from .logger import create_logger, setup_logging
logger = create_logger()
from .compress import Compressor, COMPR_BUFFER
from .upgrader import AtticRepositoryUpgrader
from .repository import Repository
from .cache import Cache
from .key import key_creator
from .archive import Archive, ArchiveChecker, CHUNKER_PARAMS
from .remote import RepositoryServer, RemoteRepository

has_lchflags = hasattr(os, 'lchflags')

# default umask, overriden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077


class ToggleAction(argparse.Action):
    """argparse action to handle "toggle" flags easily

    toggle flags are in the form of ``--foo``, ``--no-foo``.

    the ``--no-foo`` argument still needs to be passed to the
    ``add_argument()`` call, but it simplifies the ``--no``
    detection.
    """
    def __call__(self, parser, ns, values, option):
        """set the given flag to true unless ``--no`` is passed"""
        setattr(ns, self.dest, not option.startswith('--no-'))


class Archiver:

    def __init__(self, lock_wait=None):
        self.exit_code = EXIT_SUCCESS
        self.lock_wait = lock_wait

    def open_repository(self, args, create=False, exclusive=False, lock=True):
        location = args.location  # note: 'location' must be always present in args
        if location.proto == 'ssh':
            repository = RemoteRepository(location, create=create, lock_wait=self.lock_wait, lock=lock, args=args)
        else:
            repository = Repository(location.path, create=create, exclusive=exclusive, lock_wait=self.lock_wait, lock=lock)
        repository._location = location
        return repository

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_ERROR
        logger.error(msg)

    def print_warning(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_WARNING  # we do not terminate here, so it is a warning
        logger.warning(msg)

    def print_file_status(self, status, path):
        if self.output_filter is None or status in self.output_filter:
            logger.info("%1s %s", status, remove_surrogates(path))

    def do_serve(self, args):
        """Start in server mode. This command is usually not used manually.
        """
        return RepositoryServer(restrict_to_paths=args.restrict_to_paths).serve()

    def do_init(self, args):
        """Initialize an empty repository"""
        logger.info('Initializing repository at "%s"' % args.location.canonical_path())
        repository = self.open_repository(args, create=True, exclusive=True)
        key = key_creator(repository, args)
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit()
        Cache(repository, key, manifest, warn_if_unencrypted=False)
        return self.exit_code

    def do_check(self, args):
        """Check repository consistency"""
        repository = self.open_repository(args, exclusive=args.repair)
        if args.repair:
            msg = ("'check --repair' is an experimental feature that might result in data loss." +
                   "\n" +
                   "Type 'YES' if you understand this and want to continue: ")
            if not yes(msg, false_msg="Aborting.", default_notty=False,
                       env_var_override='BORG_CHECK_I_KNOW_WHAT_I_AM_DOING', truish=('YES', )):
                return EXIT_ERROR
        if not args.archives_only:
            if not repository.check(repair=args.repair, save_space=args.save_space):
                return EXIT_WARNING
        if not args.repo_only and not ArchiveChecker().check(
                repository, repair=args.repair, archive=args.location.archive,
                last=args.last, prefix=args.prefix, save_space=args.save_space):
            return EXIT_WARNING
        return EXIT_SUCCESS

    def do_change_passphrase(self, args):
        """Change repository key file passphrase"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        key.change_passphrase()
        return EXIT_SUCCESS

    def do_create(self, args):
        """Create new archive"""
        self.output_filter = args.output_filter
        dry_run = args.dry_run
        t0 = datetime.now()
        if not dry_run:
            repository = self.open_repository(args, exclusive=True)
            manifest, key = Manifest.load(repository)
            compr_args = dict(buffer=COMPR_BUFFER)
            compr_args.update(args.compression)
            key.compressor = Compressor(**compr_args)
            cache = Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait)
            archive = Archive(repository, key, manifest, args.location.archive, cache=cache,
                              create=True, checkpoint_interval=args.checkpoint_interval,
                              numeric_owner=args.numeric_owner, progress=args.progress,
                              chunker_params=args.chunker_params, start=t0)
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
        if not args.location.host:
            try:
                st = os.stat(args.location.path)
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
            self._process(archive, cache, args.excludes, args.exclude_caches, args.exclude_if_present,
                          args.keep_tag_files, skip_inodes, path, restrict_dev,
                          read_special=args.read_special, dry_run=dry_run)
        if not dry_run:
            archive.save(timestamp=args.timestamp)
            if args.progress:
                archive.stats.show_progress(final=True)
            if args.stats:
                archive.end = datetime.now()
                print('-' * 78)
                print(str(archive))
                print()
                print(str(archive.stats))
                print(str(cache))
                print('-' * 78)
        return self.exit_code

    def _process(self, archive, cache, excludes, exclude_caches, exclude_if_present,
                 keep_tag_files, skip_inodes, path, restrict_dev,
                 read_special=False, dry_run=False):
        if exclude_path(path, excludes):
            return
        try:
            st = os.lstat(path)
        except OSError as e:
            self.print_warning('%s: %s', path, e)
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
                    status = 'E'
                    self.print_warning('%s: %s', path, e)
        elif stat.S_ISDIR(st.st_mode):
            tag_paths = dir_is_tagged(path, exclude_caches, exclude_if_present)
            if tag_paths:
                if keep_tag_files:
                    archive.process_dir(path, st)
                    for tag_path in tag_paths:
                        self._process(archive, cache, excludes, exclude_caches, exclude_if_present,
                                      keep_tag_files, skip_inodes, tag_path, restrict_dev,
                                      read_special=read_special, dry_run=dry_run)
                return
            if not dry_run:
                status = archive.process_dir(path, st)
            try:
                entries = os.listdir(path)
            except OSError as e:
                status = 'E'
                self.print_warning('%s: %s', path, e)
            else:
                for filename in sorted(entries):
                    entry_path = os.path.normpath(os.path.join(path, filename))
                    self._process(archive, cache, excludes, exclude_caches, exclude_if_present,
                                  keep_tag_files, skip_inodes, entry_path, restrict_dev,
                                  read_special=read_special, dry_run=dry_run)
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
            self.print_warning('Unknown file type: %s', path)
            return
        # Status output
        if status is None:
            if not dry_run:
                status = '?'  # need to add a status code somewhere
            else:
                status = '-'  # dry run, item was not backed up
        self.print_file_status(status, path)

    def do_extract(self, args):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == 'ascii':
            logger.warning('Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.')
            if sys.platform.startswith(('linux', 'freebsd', 'netbsd', 'openbsd', 'darwin', )):
                logger.warning('Hint: You likely need to fix your locale setup. E.g. install locales and use: LANG=en_US.UTF-8')
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.location.archive,
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
            except IOError as e:
                self.print_warning('%s: %s', remove_surrogates(orig_path), e)

        if not args.dry_run:
            while dirs:
                archive.extract_item(dirs.pop(-1))
        for pattern in (patterns or []):
            if isinstance(pattern, IncludePattern) and  pattern.match_count == 0:
                self.print_warning("Include pattern '%s' never matched.", pattern)
        return self.exit_code

    def do_rename(self, args):
        """Rename an existing archive"""
        repository = self.open_repository(args, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, lock_wait=self.lock_wait)
        archive = Archive(repository, key, manifest, args.location.archive, cache=cache)
        archive.rename(args.name)
        manifest.write()
        repository.commit()
        cache.commit()
        return self.exit_code

    def do_delete(self, args):
        """Delete an existing repository or archive"""
        repository = self.open_repository(args, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait)
        if args.location.archive:
            archive = Archive(repository, key, manifest, args.location.archive, cache=cache)
            stats = Statistics()
            archive.delete(stats)
            manifest.write()
            repository.commit(save_space=args.save_space)
            cache.commit()
            if args.stats:
                logger.info(stats.summary.format(label='Deleted data:', stats=stats))
                logger.info(str(cache))
        else:
            if not args.cache_only:
                msg = []
                msg.append("You requested to completely DELETE the repository *including* all archives it contains:")
                for archive_info in manifest.list_archive_infos(sort_by='ts'):
                    msg.append(format_archive(archive_info))
                msg.append("Type 'YES' if you understand this and want to continue: ")
                msg = '\n'.join(msg)
                if not yes(msg, false_msg="Aborting.", default_notty=False,
                           env_var_override='BORG_CHECK_I_KNOW_WHAT_I_AM_DOING', truish=('YES', )):
                    self.exit_code = EXIT_ERROR
                    return self.exit_code
                repository.destroy()
                logger.info("Repository deleted.")
            cache.destroy()
            logger.info("Cache deleted.")
        return self.exit_code

    def do_mount(self, args):
        """Mount archive or an entire repository as a FUSE fileystem"""
        try:
            from .fuse import FuseOperations
        except ImportError as e:
            self.print_error('Loading fuse support failed [ImportError: %s]' % str(e))
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error('%s: Mountpoint must be a writable directory' % args.mountpoint)
            return self.exit_code

        repository = self.open_repository(args)
        try:
            manifest, key = Manifest.load(repository)
            if args.location.archive:
                archive = Archive(repository, key, manifest, args.location.archive)
            else:
                archive = None
            operations = FuseOperations(key, repository, manifest, archive)
            logger.info("Mounting filesystem")
            try:
                operations.mount(args.mountpoint, args.options, args.foreground)
            except RuntimeError:
                # Relevant error message already printed to stderr by fuse
                self.exit_code = EXIT_ERROR
        finally:
            repository.close()
        return self.exit_code

    def do_list(self, args):
        """List archive or repository contents"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        if args.location.archive:
            archive = Archive(repository, key, manifest, args.location.archive)
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
                if args.prefix and not archive_info.name.startswith(args.prefix):
                    continue
                print(format_archive(archive_info))
        return self.exit_code

    def do_info(self, args):
        """Show archive details such as disk space used"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait)
        archive = Archive(repository, key, manifest, args.location.archive, cache=cache)
        stats = archive.calc_stats(cache)
        print('Name:', archive.name)
        print('Fingerprint: %s' % hexlify(archive.id).decode('ascii'))
        print('Hostname:', archive.metadata[b'hostname'])
        print('Username:', archive.metadata[b'username'])
        print('Time: %s' % format_time(to_localtime(archive.ts)))
        print('Command line:', remove_surrogates(' '.join(archive.metadata[b'cmdline'])))
        print('Number of files: %d' % stats.nfiles)
        print()
        print(str(stats))
        print(str(cache))
        return self.exit_code

    def do_prune(self, args):
        """Prune repository archives according to specified rules"""
        repository = self.open_repository(args, exclusive=True)
        manifest, key = Manifest.load(repository)
        cache = Cache(repository, key, manifest, do_files=args.cache_files, lock_wait=self.lock_wait)
        archives = manifest.list_archive_infos(sort_by='ts', reverse=True)  # just a ArchiveInfo list
        if args.hourly + args.daily + args.weekly + args.monthly + args.yearly == 0 and args.within is None:
            self.print_error('At least one of the "within", "keep-hourly", "keep-daily", "keep-weekly", '
                             '"keep-monthly" or "keep-yearly" settings must be specified')
            return self.exit_code
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
            logger.info('Keeping archive: %s' % format_archive(archive))
        for archive in to_delete:
            if args.dry_run:
                logger.info('Would prune:     %s' % format_archive(archive))
            else:
                logger.info('Pruning archive: %s' % format_archive(archive))
                Archive(repository, key, manifest, archive.name, cache).delete(stats)
        if to_delete and not args.dry_run:
            manifest.write()
            repository.commit(save_space=args.save_space)
            cache.commit()
        if args.stats:
            logger.info(stats.summary.format(label='Deleted data:', stats=stats))
            logger.info(str(cache))
        return self.exit_code

    def do_upgrade(self, args):
        """upgrade a repository from a previous version"""
        # XXX: currently only upgrades from Attic repositories, but may
        # eventually be extended to deal with major upgrades for borg
        # itself.
        #
        # in this case, it should auto-detect the current repository
        # format and fire up necessary upgrade mechanism. this remains
        # to be implemented.

        # XXX: should auto-detect if it is an attic repository here
        repo = AtticRepositoryUpgrader(args.location.path, create=False)
        try:
            repo.upgrade(args.dry_run, inplace=args.inplace)
        except NotImplementedError as e:
            print("warning: %s" % e)
        return self.exit_code

    def do_debug_dump_archive_items(self, args):
        """dump (decrypted, decompressed) archive items metadata (not: data)"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, args.location.archive)
        for i, item_id in enumerate(archive.metadata[b'items']):
            data = key.decrypt(item_id, repository.get(item_id))
            filename = '%06d_%s.items' %(i, hexlify(item_id).decode('ascii'))
            print('Dumping', filename)
            with open(filename, 'wb') as fd:
                fd.write(data)
        print('Done.')
        return EXIT_SUCCESS

    def do_debug_get_obj(self, args):
        """get object contents from the repository and write it into file"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        hex_id = args.id
        try:
            id = unhexlify(hex_id)
        except ValueError:
            print("object id %s is invalid." % hex_id)
        else:
            try:
                data =repository.get(id)
            except repository.ObjectNotFound:
                print("object %s not found." % hex_id)
            else:
                with open(args.path, "wb") as f:
                    f.write(data)
                print("object %s fetched." % hex_id)
        return EXIT_SUCCESS

    def do_debug_put_obj(self, args):
        """put file(s) contents into the repository"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
        for path in args.paths:
            with open(path, "rb") as f:
                data = f.read()
            h = sha256(data)  # XXX hardcoded
            repository.put(h.digest(), data)
            print("object %s put." % h.hexdigest())
        repository.commit()
        return EXIT_SUCCESS

    def do_debug_delete_obj(self, args):
        """delete the objects with the given IDs from the repo"""
        repository = self.open_repository(args)
        manifest, key = Manifest.load(repository)
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

    def do_break_lock(self, args):
        """Break the repository lock (e.g. in case it was left by a dead borg."""
        repository = self.open_repository(args, lock=False)
        try:
            repository.break_lock()
            Cache.break_lock(repository)
        finally:
            repository.close()
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
            ('--yearly', '--keep-yearly', 'Warning: "--yearly" has been deprecated. Use "--keep-yearly" instead.'),
            ('--do-not-cross-mountpoints', '--one-file-system',
             'Warning:  "--do-no-cross-mountpoints" has been deprecated. Use "--one-file-system" instead.'),
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

    def build_parser(self, args=None, prog=None):
        common_parser = argparse.ArgumentParser(add_help=False, prog=prog)
        common_parser.add_argument('-v', '--verbose', '--info', dest='log_level',
                                   action='store_const', const='info', default='warning',
                                   help='enable informative (verbose) output, work on log level INFO')
        common_parser.add_argument('--debug', dest='log_level',
                                   action='store_const', const='debug', default='warning',
                                   help='enable debug output, work on log level DEBUG')
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
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
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
        subparser.add_argument('-p', '--prefix', dest='prefix', type=str,
                               help='only consider archive names starting with this prefix')

        change_passphrase_epilog = textwrap.dedent("""
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.
        """)
        subparser = subparsers.add_parser('change-passphrase', parents=[common_parser],
                                          description=self.do_change_passphrase.__doc__,
                                          epilog=change_passphrase_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_change_passphrase)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
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
                               help="""show progress display while creating the archive, showing Original,
                               Compressed and Deduplicated sizes, followed by the Number of files seen
                               and the path being processed, default: %(default)s""")
        subparser.add_argument('--filter', dest='output_filter', metavar='STATUSCHARS',
                               help='only display items with the given status characters')
        subparser.add_argument('-e', '--exclude', dest='excludes',
                               type=ExcludePattern, action='append',
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
        subparser.add_argument('location', metavar='ARCHIVE',
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
        subparser.add_argument('location', metavar='ARCHIVE',
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('--short', dest='short',
                               action='store_true', default=False,
                               help='only print file/directory names, nothing else')
        subparser.add_argument('-p', '--prefix', dest='prefix', type=str,
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_break_lock)
        subparser.add_argument('location', metavar='REPOSITORY',
                               type=location_validator(archive=False),
                               help='repository for which to break the locks')

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
        subparser.add_argument('--save-space', dest='save_space', action='store_true',
                               default=False,
                               help='work slower, but using less space')
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to prune')

        upgrade_epilog = textwrap.dedent("""
        upgrade an existing Borg repository. this currently
        only support converting an Attic repository, but may
        eventually be extended to cover major Borg upgrades as well.

        it will change the magic strings in the repository's segments
        to match the new Borg magic strings. the keyfiles found in
        $ATTIC_KEYS_DIR or ~/.attic/keys/ will also be converted and
        copied to $BORG_KEYS_DIR or ~/.borg/keys.

        the cache files are converted, from $ATTIC_CACHE_DIR or
        ~/.cache/attic to $BORG_CACHE_DIR or ~/.cache/borg, but the
        cache layout between Borg and Attic changed, so it is possible
        the first backup after the conversion takes longer than expected
        due to the cache resync.

        upgrade should be able to resume if interrupted, although it
        will still iterate over all segments. if you want to start
        from scratch, use `borg delete` over the copied repository to
        make sure the cache files are also removed:

            borg delete borg

        unless ``--inplace`` is specified, the upgrade process first
        creates a backup copy of the repository, in
        REPOSITORY.upgrade-DATETIME, using hardlinks. this takes
        longer than in place upgrades, but is much safer and gives
        progress information (as opposed to ``cp -al``). once you are
        satisfied with the conversion, you can safely destroy the
        backup copy.

        WARNING: running the upgrade in place will make the current
        copy unusable with older version, with no way of going back
        to previous versions. this can PERMANENTLY DAMAGE YOUR
        REPOSITORY!  Attic CAN NOT READ BORG REPOSITORIES, as the
        magic strings have changed. you have been warned.""")
        subparser = subparsers.add_parser('upgrade', parents=[common_parser],
                                          description=self.do_upgrade.__doc__,
                                          epilog=upgrade_epilog,
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_upgrade)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
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
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=self.do_debug_delete_obj)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                               type=location_validator(archive=False),
                               help='repository to use')
        subparser.add_argument('ids', metavar='IDs', nargs='+', type=str,
                               help='hex object ID(s) to delete from the repo')
        return parser

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
    msg = None
    args = archiver.parse_args(sys.argv[1:])
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
    except Exception:
        msg = 'Local Exception.\n%s\n%s' % (traceback.format_exc(), sysinfo())
        exit_code = EXIT_ERROR
    except KeyboardInterrupt:
        msg = 'Keyboard interrupt.\n%s\n%s' % (traceback.format_exc(), sysinfo())
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
