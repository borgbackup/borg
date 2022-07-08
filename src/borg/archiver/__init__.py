# borg cli interface / toplevel archiver code

import sys
import traceback

try:
    import argparse
    import faulthandler
    import functools
    import inspect
    import itertools
    import json
    import logging
    import os
    import shlex
    import signal
    import stat
    import subprocess
    import textwrap
    import time
    from datetime import datetime, timedelta
    from io import TextIOWrapper

    from ..logger import create_logger, setup_logging

    logger = create_logger()

    from .common import with_repository, with_archive, Highlander
    from .. import __version__
    from .. import helpers
    from ..archive import Archive, ArchiveRecreater, Statistics, is_special
    from ..archive import BackupError, BackupOSError, backup_io, OsOpen, stat_update_check
    from ..archive import FilesystemObjectProcessors, MetadataCollector, ChunksProcessor
    from ..cache import Cache
    from ..constants import *  # NOQA
    from ..compress import CompressionSpec
    from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR, EXIT_SIGNAL_BASE
    from ..helpers import Error, set_ec
    from ..helpers import location_validator, archivename_validator, ChunkerParams, Location
    from ..helpers import NameSpec, CommentSpec, FilesCacheMode
    from ..helpers import BaseFormatter, ItemFormatter, ArchiveFormatter
    from ..helpers import format_timedelta, format_file_size, format_archive
    from ..helpers import remove_surrogates, bin_to_hex, eval_escapes
    from ..helpers import timestamp
    from ..helpers import get_cache_dir, os_stat
    from ..helpers import Manifest
    from ..helpers import HardLinkManager
    from ..helpers import check_python, check_extension_modules
    from ..helpers import dir_is_tagged, is_slow_msgpack, is_supported_msgpack, sysinfo
    from ..helpers import log_multi
    from ..helpers import signal_handler, raising_signal_handler, SigHup, SigTerm
    from ..helpers import ErrorIgnoringTextIOWrapper
    from ..helpers import ProgressIndicatorPercent
    from ..helpers import basic_json_data, json_print
    from ..helpers import flags_root, flags_dir, flags_special_follow, flags_special
    from ..helpers import msgpack
    from ..helpers import sig_int
    from ..helpers import iter_separated
    from ..patterns import PatternMatcher
    from ..platform import get_flags
    from ..platform import uid2user, gid2group
    from ..remote import RemoteRepository
    from ..selftest import selftest
except BaseException:
    # an unhandled exception in the try-block would cause the borg cli command to exit with rc 1 due to python's
    # default behavior, see issue #4424.
    # as borg defines rc 1 as WARNING, this would be a mismatch, because a crash should be an ERROR (rc 2).
    traceback.print_exc()
    sys.exit(2)  # == EXIT_ERROR

assert EXIT_ERROR == 2, "EXIT_ERROR is not 2, as expected - fix assert AND exception handler right above this line."


STATS_HEADER = "                       Original size    Deduplicated size"

PURE_PYTHON_MSGPACK_WARNING = "Using a pure-python msgpack! This will result in lower performance."


def get_func(args):
    # This works around https://bugs.python.org/issue9351
    # func is used at the leaf parsers of the argparse parser tree,
    # fallback_func at next level towards the root,
    # fallback2_func at the 2nd next level (which is root in our case).
    for name in "func", "fallback_func", "fallback2_func":
        func = getattr(args, name, None)
        if func is not None:
            return func
    raise Exception("expected func attributes not found")


from .benchmarks import BenchmarkMixIn
from .check import CheckMixIn
from .compact import CompactMixIn
from .config import ConfigMixIn
from .debug import DebugMixIn
from .diff import DiffMixIn
from .help import HelpMixIn
from .keys import KeysMixIn
from .locks import LocksMixIn
from .mount import MountMixIn
from .prune import PruneMixIn
from .rcreate import RCreateMixIn
from .rdelete import RDeleteMixIn
from .serve import ServeMixIn
from .tar import TarMixIn
from .transfer import TransferMixIn


class Archiver(
    CheckMixIn,
    ConfigMixIn,
    CompactMixIn,
    DebugMixIn,
    DiffMixIn,
    TarMixIn,
    BenchmarkMixIn,
    KeysMixIn,
    LocksMixIn,
    MountMixIn,
    PruneMixIn,
    HelpMixIn,
    RCreateMixIn,
    RDeleteMixIn,
    ServeMixIn,
    TransferMixIn,
):
    def __init__(self, lock_wait=None, prog=None):
        self.exit_code = EXIT_SUCCESS
        self.lock_wait = lock_wait
        self.prog = prog

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_ERROR
        logger.error(msg)

    def print_warning(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_WARNING  # we do not terminate here, so it is a warning
        logger.warning(msg)

    def print_file_status(self, status, path):
        # if we get called with status == None, the final file status was already printed
        if self.output_list and status is not None and (self.output_filter is None or status in self.output_filter):
            if self.log_json:
                print(
                    json.dumps({"type": "file_status", "status": status, "path": remove_surrogates(path)}),
                    file=sys.stderr,
                )
            else:
                logging.getLogger("borg.output.list").info("%1s %s", status, remove_surrogates(path))

    @staticmethod
    def build_matcher(inclexcl_patterns, include_paths):
        matcher = PatternMatcher()
        matcher.add_inclexcl(inclexcl_patterns)
        matcher.add_includepaths(include_paths)
        return matcher

    @with_repository(fake="dry_run", exclusive=True, compatibility=(Manifest.Operation.WRITE,))
    def do_create(self, args, repository, manifest=None, key=None):
        """Create new archive"""
        matcher = PatternMatcher(fallback=True)
        matcher.add_inclexcl(args.patterns)

        def create_inner(archive, cache, fso):
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
            logger.debug("Processing files ...")
            if args.content_from_command:
                path = args.stdin_name
                mode = args.stdin_mode
                user = args.stdin_user
                group = args.stdin_group
                if not dry_run:
                    try:
                        try:
                            proc = subprocess.Popen(args.paths, stdout=subprocess.PIPE)
                        except (FileNotFoundError, PermissionError) as e:
                            self.print_error("Failed to execute command: %s", e)
                            return self.exit_code
                        status = fso.process_pipe(
                            path=path, cache=cache, fd=proc.stdout, mode=mode, user=user, group=group
                        )
                        rc = proc.wait()
                        if rc != 0:
                            self.print_error("Command %r exited with status %d", args.paths[0], rc)
                            return self.exit_code
                    except BackupOSError as e:
                        self.print_error("%s: %s", path, e)
                        return self.exit_code
                else:
                    status = "-"
                self.print_file_status(status, path)
            elif args.paths_from_command or args.paths_from_stdin:
                paths_sep = eval_escapes(args.paths_delimiter) if args.paths_delimiter is not None else "\n"
                if args.paths_from_command:
                    try:
                        proc = subprocess.Popen(args.paths, stdout=subprocess.PIPE)
                    except (FileNotFoundError, PermissionError) as e:
                        self.print_error("Failed to execute command: %s", e)
                        return self.exit_code
                    pipe_bin = proc.stdout
                else:  # args.paths_from_stdin == True
                    pipe_bin = sys.stdin.buffer
                pipe = TextIOWrapper(pipe_bin, errors="surrogateescape")
                for path in iter_separated(pipe, paths_sep):
                    path = os.path.normpath(path)
                    try:
                        with backup_io("stat"):
                            st = os_stat(path=path, parent_fd=None, name=None, follow_symlinks=False)
                        status = self._process_any(
                            path=path,
                            parent_fd=None,
                            name=None,
                            st=st,
                            fso=fso,
                            cache=cache,
                            read_special=args.read_special,
                            dry_run=dry_run,
                        )
                    except (BackupOSError, BackupError) as e:
                        self.print_warning("%s: %s", path, e)
                        status = "E"
                    if status == "C":
                        self.print_warning("%s: file changed while we backed it up", path)
                    self.print_file_status(status, path)
                if args.paths_from_command:
                    rc = proc.wait()
                    if rc != 0:
                        self.print_error("Command %r exited with status %d", args.paths[0], rc)
                        return self.exit_code
            else:
                for path in args.paths:
                    if path == "-":  # stdin
                        path = args.stdin_name
                        mode = args.stdin_mode
                        user = args.stdin_user
                        group = args.stdin_group
                        if not dry_run:
                            try:
                                status = fso.process_pipe(
                                    path=path, cache=cache, fd=sys.stdin.buffer, mode=mode, user=user, group=group
                                )
                            except BackupOSError as e:
                                status = "E"
                                self.print_warning("%s: %s", path, e)
                        else:
                            status = "-"
                        self.print_file_status(status, path)
                        continue
                    path = os.path.normpath(path)
                    parent_dir = os.path.dirname(path) or "."
                    name = os.path.basename(path)
                    try:
                        # note: for path == '/':  name == '' and parent_dir == '/'.
                        # the empty name will trigger a fall-back to path-based processing in os_stat and os_open.
                        with OsOpen(path=parent_dir, flags=flags_root, noatime=True, op="open_root") as parent_fd:
                            try:
                                st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=False)
                            except OSError as e:
                                self.print_warning("%s: %s", path, e)
                                continue
                            if args.one_file_system:
                                restrict_dev = st.st_dev
                            else:
                                restrict_dev = None
                            self._rec_walk(
                                path=path,
                                parent_fd=parent_fd,
                                name=name,
                                fso=fso,
                                cache=cache,
                                matcher=matcher,
                                exclude_caches=args.exclude_caches,
                                exclude_if_present=args.exclude_if_present,
                                keep_exclude_tags=args.keep_exclude_tags,
                                skip_inodes=skip_inodes,
                                restrict_dev=restrict_dev,
                                read_special=args.read_special,
                                dry_run=dry_run,
                            )
                            # if we get back here, we've finished recursing into <path>,
                            # we do not ever want to get back in there (even if path is given twice as recursion root)
                            skip_inodes.add((st.st_ino, st.st_dev))
                    except (BackupOSError, BackupError) as e:
                        # this comes from OsOpen, self._rec_walk has own exception handler
                        self.print_warning("%s: %s", path, e)
                        continue
            if not dry_run:
                if args.progress:
                    archive.stats.show_progress(final=True)
                archive.stats += fso.stats
                if sig_int:
                    # do not save the archive if the user ctrl-c-ed - it is valid, but incomplete.
                    # we already have a checkpoint archive in this case.
                    self.print_error("Got Ctrl-C / SIGINT.")
                else:
                    archive.save(comment=args.comment, timestamp=args.timestamp, stats=archive.stats)
                    args.stats |= args.json
                    if args.stats:
                        if args.json:
                            json_print(basic_json_data(manifest, cache=cache, extra={"archive": archive}))
                        else:
                            log_multi(str(archive), str(archive.stats), logger=logging.getLogger("borg.output.stats"))

        self.output_filter = args.output_filter
        self.output_list = args.output_list
        self.noflags = args.noflags
        self.noacls = args.noacls
        self.noxattrs = args.noxattrs
        self.exclude_nodump = args.exclude_nodump
        dry_run = args.dry_run
        t0 = datetime.utcnow()
        t0_monotonic = time.monotonic()
        logger.info('Creating archive at "%s"' % args.location.processed)
        if not dry_run:
            with Cache(
                repository,
                key,
                manifest,
                progress=args.progress,
                lock_wait=self.lock_wait,
                permit_adhoc_cache=args.no_cache_sync,
                cache_mode=args.files_cache_mode,
                iec=args.iec,
            ) as cache:
                archive = Archive(
                    repository,
                    key,
                    manifest,
                    args.name,
                    cache=cache,
                    create=True,
                    checkpoint_interval=args.checkpoint_interval,
                    numeric_ids=args.numeric_ids,
                    noatime=not args.atime,
                    noctime=args.noctime,
                    progress=args.progress,
                    chunker_params=args.chunker_params,
                    start=t0,
                    start_monotonic=t0_monotonic,
                    log_json=args.log_json,
                    iec=args.iec,
                )
                metadata_collector = MetadataCollector(
                    noatime=not args.atime,
                    noctime=args.noctime,
                    noflags=args.noflags,
                    noacls=args.noacls,
                    noxattrs=args.noxattrs,
                    numeric_ids=args.numeric_ids,
                    nobirthtime=args.nobirthtime,
                )
                cp = ChunksProcessor(
                    cache=cache,
                    key=key,
                    add_item=archive.add_item,
                    write_checkpoint=archive.write_checkpoint,
                    checkpoint_interval=args.checkpoint_interval,
                    rechunkify=False,
                )
                fso = FilesystemObjectProcessors(
                    metadata_collector=metadata_collector,
                    cache=cache,
                    key=key,
                    process_file_chunks=cp.process_file_chunks,
                    add_item=archive.add_item,
                    chunker_params=args.chunker_params,
                    show_progress=args.progress,
                    sparse=args.sparse,
                    log_json=args.log_json,
                    iec=args.iec,
                    file_status_printer=self.print_file_status,
                )
                create_inner(archive, cache, fso)
        else:
            create_inner(None, None, None)
        return self.exit_code

    def _process_any(self, *, path, parent_fd, name, st, fso, cache, read_special, dry_run):
        """
        Call the right method on the given FilesystemObjectProcessor.
        """

        if dry_run:
            return "-"
        elif stat.S_ISREG(st.st_mode):
            return fso.process_file(path=path, parent_fd=parent_fd, name=name, st=st, cache=cache)
        elif stat.S_ISDIR(st.st_mode):
            return fso.process_dir(path=path, parent_fd=parent_fd, name=name, st=st)
        elif stat.S_ISLNK(st.st_mode):
            if not read_special:
                return fso.process_symlink(path=path, parent_fd=parent_fd, name=name, st=st)
            else:
                try:
                    st_target = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=True)
                except OSError:
                    special = False
                else:
                    special = is_special(st_target.st_mode)
                if special:
                    return fso.process_file(
                        path=path, parent_fd=parent_fd, name=name, st=st_target, cache=cache, flags=flags_special_follow
                    )
                else:
                    return fso.process_symlink(path=path, parent_fd=parent_fd, name=name, st=st)
        elif stat.S_ISFIFO(st.st_mode):
            if not read_special:
                return fso.process_fifo(path=path, parent_fd=parent_fd, name=name, st=st)
            else:
                return fso.process_file(
                    path=path, parent_fd=parent_fd, name=name, st=st, cache=cache, flags=flags_special
                )
        elif stat.S_ISCHR(st.st_mode):
            if not read_special:
                return fso.process_dev(path=path, parent_fd=parent_fd, name=name, st=st, dev_type="c")
            else:
                return fso.process_file(
                    path=path, parent_fd=parent_fd, name=name, st=st, cache=cache, flags=flags_special
                )
        elif stat.S_ISBLK(st.st_mode):
            if not read_special:
                return fso.process_dev(path=path, parent_fd=parent_fd, name=name, st=st, dev_type="b")
            else:
                return fso.process_file(
                    path=path, parent_fd=parent_fd, name=name, st=st, cache=cache, flags=flags_special
                )
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
            self.print_warning("Unknown file type: %s", path)
            return

    def _rec_walk(
        self,
        *,
        path,
        parent_fd,
        name,
        fso,
        cache,
        matcher,
        exclude_caches,
        exclude_if_present,
        keep_exclude_tags,
        skip_inodes,
        restrict_dev,
        read_special,
        dry_run,
    ):
        """
        Process *path* (or, preferably, parent_fd/name) recursively according to the various parameters.

        This should only raise on critical errors. Per-item errors must be handled within this method.
        """
        if sig_int and sig_int.action_done():
            # the user says "get out of here!" and we have already completed the desired action.
            return

        status = None
        try:
            recurse_excluded_dir = False
            if matcher.match(path):
                with backup_io("stat"):
                    st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=False)
            else:
                self.print_file_status("x", path)
                # get out here as quickly as possible:
                # we only need to continue if we shall recurse into an excluded directory.
                # if we shall not recurse, then do not even touch (stat()) the item, it
                # could trigger an error, e.g. if access is forbidden, see #3209.
                if not matcher.recurse_dir:
                    return
                recurse_excluded_dir = True
                with backup_io("stat"):
                    st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode):
                    return

            if (st.st_ino, st.st_dev) in skip_inodes:
                return
            # if restrict_dev is given, we do not want to recurse into a new filesystem,
            # but we WILL save the mountpoint directory (or more precise: the root
            # directory of the mounted filesystem that shadows the mountpoint dir).
            recurse = restrict_dev is None or st.st_dev == restrict_dev

            if self.exclude_nodump:
                # Ignore if nodump flag is set
                with backup_io("flags"):
                    if get_flags(path=path, st=st) & stat.UF_NODUMP:
                        self.print_file_status("x", path)
                        return

            if not stat.S_ISDIR(st.st_mode):
                # directories cannot go in this branch because they can be excluded based on tag
                # files they might contain
                status = self._process_any(
                    path=path,
                    parent_fd=parent_fd,
                    name=name,
                    st=st,
                    fso=fso,
                    cache=cache,
                    read_special=read_special,
                    dry_run=dry_run,
                )
            else:
                with OsOpen(
                    path=path, parent_fd=parent_fd, name=name, flags=flags_dir, noatime=True, op="dir_open"
                ) as child_fd:
                    # child_fd is None for directories on windows, in that case a race condition check is not possible.
                    if child_fd is not None:
                        with backup_io("fstat"):
                            st = stat_update_check(st, os.fstat(child_fd))
                    if recurse:
                        tag_names = dir_is_tagged(path, exclude_caches, exclude_if_present)
                        if tag_names:
                            # if we are already recursing in an excluded dir, we do not need to do anything else than
                            # returning (we do not need to archive or recurse into tagged directories), see #3991:
                            if not recurse_excluded_dir:
                                if keep_exclude_tags:
                                    if not dry_run:
                                        fso.process_dir_with_fd(path=path, fd=child_fd, st=st)
                                    for tag_name in tag_names:
                                        tag_path = os.path.join(path, tag_name)
                                        self._rec_walk(
                                            path=tag_path,
                                            parent_fd=child_fd,
                                            name=tag_name,
                                            fso=fso,
                                            cache=cache,
                                            matcher=matcher,
                                            exclude_caches=exclude_caches,
                                            exclude_if_present=exclude_if_present,
                                            keep_exclude_tags=keep_exclude_tags,
                                            skip_inodes=skip_inodes,
                                            restrict_dev=restrict_dev,
                                            read_special=read_special,
                                            dry_run=dry_run,
                                        )
                                self.print_file_status("x", path)
                            return
                    if not recurse_excluded_dir and not dry_run:
                        status = fso.process_dir_with_fd(path=path, fd=child_fd, st=st)
                    if recurse:
                        with backup_io("scandir"):
                            entries = helpers.scandir_inorder(path=path, fd=child_fd)
                        for dirent in entries:
                            normpath = os.path.normpath(os.path.join(path, dirent.name))
                            self._rec_walk(
                                path=normpath,
                                parent_fd=child_fd,
                                name=dirent.name,
                                fso=fso,
                                cache=cache,
                                matcher=matcher,
                                exclude_caches=exclude_caches,
                                exclude_if_present=exclude_if_present,
                                keep_exclude_tags=keep_exclude_tags,
                                skip_inodes=skip_inodes,
                                restrict_dev=restrict_dev,
                                read_special=read_special,
                                dry_run=dry_run,
                            )

        except (BackupOSError, BackupError) as e:
            self.print_warning("%s: %s", path, e)
            status = "E"
        if status == "C":
            self.print_warning("%s: file changed while we backed it up", path)
        if not recurse_excluded_dir:
            self.print_file_status(status, path)

    @staticmethod
    def build_filter(matcher, strip_components):
        if strip_components:

            def item_filter(item):
                matched = matcher.match(item.path) and os.sep.join(item.path.split(os.sep)[strip_components:])
                return matched

        else:

            def item_filter(item):
                matched = matcher.match(item.path)
                return matched

        return item_filter

    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_extract(self, args, repository, manifest, key, archive):
        """Extract archive contents"""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == "ascii":
            logger.warning(
                'Warning: File system encoding is "ascii", extracting non-ascii filenames will not be supported.'
            )
            if sys.platform.startswith(("linux", "freebsd", "netbsd", "openbsd", "darwin")):
                logger.warning(
                    "Hint: You likely need to fix your locale setup. E.g. install locales and use: LANG=en_US.UTF-8"
                )

        matcher = self.build_matcher(args.patterns, args.paths)

        progress = args.progress
        output_list = args.output_list
        dry_run = args.dry_run
        stdout = args.stdout
        sparse = args.sparse
        strip_components = args.strip_components
        dirs = []
        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> path

        filter = self.build_filter(matcher, strip_components)
        if progress:
            pi = ProgressIndicatorPercent(msg="%5.1f%% Extracting: %s", step=0.1, msgid="extract")
            pi.output("Calculating total archive size for the progress indicator (might take long for large archives)")
            extracted_size = sum(item.get_size() for item in archive.iter_items(filter))
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
                        self.print_warning("%s: %s", remove_surrogates(dir_item.path), e)
            if output_list:
                logging.getLogger("borg.output.list").info(remove_surrogates(item.path))
            try:
                if dry_run:
                    archive.extract_item(item, dry_run=True, hlm=hlm, pi=pi)
                else:
                    if stat.S_ISDIR(item.mode):
                        dirs.append(item)
                        archive.extract_item(item, stdout=stdout, restore_attrs=False)
                    else:
                        archive.extract_item(
                            item,
                            stdout=stdout,
                            sparse=sparse,
                            hlm=hlm,
                            stripped_components=strip_components,
                            original_path=orig_path,
                            pi=pi,
                        )
            except (BackupOSError, BackupError) as e:
                self.print_warning("%s: %s", remove_surrogates(orig_path), e)

        if pi:
            pi.finish()

        if not args.dry_run:
            pi = ProgressIndicatorPercent(
                total=len(dirs), msg="Setting directory permissions %3.0f%%", msgid="extract.permissions"
            )
            while dirs:
                pi.show()
                dir_item = dirs.pop(-1)
                try:
                    archive.extract_item(dir_item, stdout=stdout)
                except BackupOSError as e:
                    self.print_warning("%s: %s", remove_surrogates(dir_item.path), e)
        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning("Include pattern '%s' never matched.", pattern)
        if pi:
            # clear progress output
            pi.finish()
        return self.exit_code

    @with_repository(exclusive=True, cache=True, compatibility=(Manifest.Operation.CHECK,))
    @with_archive
    def do_rename(self, args, repository, manifest, key, cache, archive):
        """Rename an existing archive"""
        archive.rename(args.newname)
        manifest.write()
        repository.commit(compact=False)
        cache.commit()
        return self.exit_code

    @with_repository(exclusive=True, manifest=False)
    def do_delete(self, args, repository):
        """Delete archives"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        manifest, key = Manifest.load(repository, (Manifest.Operation.DELETE,))
        archive_names = tuple(x.name for x in manifest.archives.list_considering(args))
        if not archive_names:
            return self.exit_code
        if args.glob_archives is None and args.first == 0 and args.last == 0:
            self.print_error(
                "Aborting: if you really want to delete all archives, please use -a '*' "
                "or just delete the whole repository (might be much faster)."
            )
            return EXIT_ERROR

        if args.forced == 2:
            deleted = False
            logger_list = logging.getLogger("borg.output.list")
            for i, archive_name in enumerate(archive_names, 1):
                try:
                    current_archive = manifest.archives.pop(archive_name)
                except KeyError:
                    self.exit_code = EXIT_WARNING
                    logger.warning(f"Archive {archive_name} not found ({i}/{len(archive_names)}).")
                else:
                    deleted = True
                    if self.output_list:
                        msg = "Would delete: {} ({}/{})" if dry_run else "Deleted archive: {} ({}/{})"
                        logger_list.info(msg.format(format_archive(current_archive), i, len(archive_names)))
            if dry_run:
                logger.info("Finished dry-run.")
            elif deleted:
                manifest.write()
                # note: might crash in compact() after committing the repo
                repository.commit(compact=False)
                logger.warning('Done. Run "borg check --repair" to clean up the mess.')
            else:
                logger.warning("Aborted.")
            return self.exit_code

        stats = Statistics(iec=args.iec)
        with Cache(repository, key, manifest, progress=args.progress, lock_wait=self.lock_wait, iec=args.iec) as cache:
            msg_delete = "Would delete archive: {} ({}/{})" if dry_run else "Deleting archive: {} ({}/{})"
            msg_not_found = "Archive {} not found ({}/{})."
            logger_list = logging.getLogger("borg.output.list")
            delete_count = 0
            for i, archive_name in enumerate(archive_names, 1):
                try:
                    archive_info = manifest.archives[archive_name]
                except KeyError:
                    logger.warning(msg_not_found.format(archive_name, i, len(archive_names)))
                else:
                    if self.output_list:
                        logger_list.info(msg_delete.format(format_archive(archive_info), i, len(archive_names)))

                    if not dry_run:
                        archive = Archive(
                            repository,
                            key,
                            manifest,
                            archive_name,
                            cache=cache,
                            consider_part_files=args.consider_part_files,
                        )
                        archive.delete(stats, progress=args.progress, forced=args.forced)
                        delete_count += 1
            if delete_count > 0:
                # only write/commit if we actually changed something, see #6060.
                manifest.write()
                repository.commit(compact=False, save_space=args.save_space)
                cache.commit()
            if args.stats:
                log_multi(str(stats), logger=logging.getLogger("borg.output.stats"))

        return self.exit_code

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_list(self, args, repository, manifest, key):
        """List archive contents"""
        matcher = self.build_matcher(args.patterns, args.paths)
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{path}{NL}"
        else:
            format = "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}"

        def _list_inner(cache):
            archive = Archive(
                repository, key, manifest, args.name, cache=cache, consider_part_files=args.consider_part_files
            )

            formatter = ItemFormatter(archive, format, json_lines=args.json_lines)
            for item in archive.iter_items(lambda item: matcher.match(item.path)):
                sys.stdout.write(formatter.format_item(item))

        # Only load the cache if it will be used
        if ItemFormatter.format_needs_cache(format):
            with Cache(repository, key, manifest, lock_wait=self.lock_wait) as cache:
                _list_inner(cache)
        else:
            _list_inner(cache=None)

        return self.exit_code

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_rlist(self, args, repository, manifest, key):
        """List the archives contained in a repository"""
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}{NL}"
        else:
            format = "{archive:<36} {time} [{id}]{NL}"
        formatter = ArchiveFormatter(format, repository, manifest, key, json=args.json, iec=args.iec)

        output_data = []

        for archive_info in manifest.archives.list_considering(args):
            if args.json:
                output_data.append(formatter.get_item_data(archive_info))
            else:
                sys.stdout.write(formatter.format_item(archive_info))

        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))

        return self.exit_code

    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_rinfo(self, args, repository, manifest, key, cache):
        """Show repository infos"""
        info = basic_json_data(manifest, cache=cache, extra={"security_dir": cache.security_manager.dir})

        if args.json:
            json_print(info)
        else:
            encryption = "Encrypted: "
            if key.NAME in ("plaintext", "authenticated"):
                encryption += "No"
            else:
                encryption += "Yes (%s)" % key.NAME
            if key.NAME.startswith("key file"):
                encryption += "\nKey file: %s" % key.find_key()
            info["encryption"] = encryption

            print(
                textwrap.dedent(
                    """
            Repository ID: {id}
            Location: {location}
            Repository version: {version}
            Append only: {append_only}
            {encryption}
            Cache: {cache.path}
            Security dir: {security_dir}
            """
                )
                .strip()
                .format(
                    id=bin_to_hex(repository.id),
                    location=repository._location.canonical_path(),
                    version=repository.version,
                    append_only=repository.append_only,
                    **info,
                )
            )
            print(str(cache))
        return self.exit_code

    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_info(self, args, repository, manifest, key, cache):
        """Show archive details such as disk space used"""

        def format_cmdline(cmdline):
            return remove_surrogates(" ".join(shlex.quote(x) for x in cmdline))

        args.consider_checkpoints = True
        archive_names = tuple(x.name for x in manifest.archives.list_considering(args))

        output_data = []

        for i, archive_name in enumerate(archive_names, 1):
            archive = Archive(
                repository,
                key,
                manifest,
                archive_name,
                cache=cache,
                consider_part_files=args.consider_part_files,
                iec=args.iec,
            )
            info = archive.info()
            if args.json:
                output_data.append(info)
            else:
                info["duration"] = format_timedelta(timedelta(seconds=info["duration"]))
                info["command_line"] = format_cmdline(info["command_line"])
                print(
                    textwrap.dedent(
                        """
                Archive name: {name}
                Archive fingerprint: {id}
                Comment: {comment}
                Hostname: {hostname}
                Username: {username}
                Time (start): {start}
                Time (end): {end}
                Duration: {duration}
                Command line: {command_line}
                Utilization of maximum supported archive size: {limits[max_archive_size]:.0%}
                Number of files: {stats[nfiles]}
                Original size: {stats[original_size]}
                Deduplicated size: {stats[deduplicated_size]}
                """
                    )
                    .strip()
                    .format(**info)
                )
            if self.exit_code:
                break
            if not args.json and len(archive_names) - i:
                print()

        if args.json:
            json_print(basic_json_data(manifest, cache=cache, extra={"archives": output_data}))
        return self.exit_code

    @with_repository(cache=True, exclusive=True, compatibility=(Manifest.Operation.CHECK,))
    def do_recreate(self, args, repository, manifest, key, cache):
        """Re-create archives"""
        matcher = self.build_matcher(args.patterns, args.paths)
        self.output_list = args.output_list
        self.output_filter = args.output_filter
        recompress = args.recompress != "never"
        always_recompress = args.recompress == "always"

        recreater = ArchiveRecreater(
            repository,
            manifest,
            key,
            cache,
            matcher,
            exclude_caches=args.exclude_caches,
            exclude_if_present=args.exclude_if_present,
            keep_exclude_tags=args.keep_exclude_tags,
            chunker_params=args.chunker_params,
            compression=args.compression,
            recompress=recompress,
            always_recompress=always_recompress,
            progress=args.progress,
            stats=args.stats,
            file_status_printer=self.print_file_status,
            checkpoint_interval=args.checkpoint_interval,
            dry_run=args.dry_run,
            timestamp=args.timestamp,
        )

        archive_names = tuple(archive.name for archive in manifest.archives.list_considering(args))
        if args.target is not None and len(archive_names) != 1:
            self.print_error("--target: Need to specify single archive")
            return self.exit_code
        for name in archive_names:
            if recreater.is_temporary_archive(name):
                continue
            print("Processing", name)
            if not recreater.recreate(name, args.comment, args.target):
                logger.info("Skipped archive %s: Nothing to do. Archive was not processed.", name)
        if not args.dry_run:
            manifest.write()
            repository.commit(compact=False)
            cache.commit()
        return self.exit_code

    def preprocess_args(self, args):
        deprecations = [
            # ('--old', '--new' or None, 'Warning: "--old" has been deprecated. Use "--new" instead.'),
        ]
        for i, arg in enumerate(args[:]):
            for old_name, new_name, warning in deprecations:
                if arg.startswith(old_name):
                    if new_name is not None:
                        args[i] = arg.replace(old_name, new_name)
                    print(warning, file=sys.stderr)
        return args

    class CommonOptions:
        """
        Support class to allow specifying common options directly after the top-level command.

        Normally options can only be specified on the parser defining them, which means
        that generally speaking *all* options go after all sub-commands. This is annoying
        for common options in scripts, e.g. --remote-path or logging options.

        This class allows adding the same set of options to both the top-level parser
        and the final sub-command parsers (but not intermediary sub-commands, at least for now).

        It does so by giving every option's target name ("dest") a suffix indicating its level
        -- no two options in the parser hierarchy can have the same target --
        then, after parsing the command line, multiple definitions are resolved.

        Defaults are handled by only setting them on the top-level parser and setting
        a sentinel object in all sub-parsers, which then allows one to discern which parser
        supplied the option.
        """

        def __init__(self, define_common_options, suffix_precedence):
            """
            *define_common_options* should be a callable taking one argument, which
            will be a argparse.Parser.add_argument-like function.

            *define_common_options* will be called multiple times, and should call
            the passed function to define common options exactly the same way each time.

            *suffix_precedence* should be a tuple of the suffixes that will be used.
            It is ordered from lowest precedence to highest precedence:
            An option specified on the parser belonging to index 0 is overridden if the
            same option is specified on any parser with a higher index.
            """
            self.define_common_options = define_common_options
            self.suffix_precedence = suffix_precedence

            # Maps suffixes to sets of target names.
            # E.g. common_options["_subcommand"] = {..., "log_level", ...}
            self.common_options = dict()
            # Set of options with the 'append' action.
            self.append_options = set()
            # This is the sentinel object that replaces all default values in parsers
            # below the top-level parser.
            self.default_sentinel = object()

        def add_common_group(self, parser, suffix, provide_defaults=False):
            """
            Add common options to *parser*.

            *provide_defaults* must only be True exactly once in a parser hierarchy,
            at the top level, and False on all lower levels. The default is chosen
            accordingly.

            *suffix* indicates the suffix to use internally. It also indicates
            which precedence the *parser* has for common options. See *suffix_precedence*
            of __init__.
            """
            assert suffix in self.suffix_precedence

            def add_argument(*args, **kwargs):
                if "dest" in kwargs:
                    kwargs.setdefault("action", "store")
                    assert kwargs["action"] in ("help", "store_const", "store_true", "store_false", "store", "append")
                    is_append = kwargs["action"] == "append"
                    if is_append:
                        self.append_options.add(kwargs["dest"])
                        assert (
                            kwargs["default"] == []
                        ), "The default is explicitly constructed as an empty list in resolve()"
                    else:
                        self.common_options.setdefault(suffix, set()).add(kwargs["dest"])
                    kwargs["dest"] += suffix
                    if not provide_defaults:
                        # Interpolate help now, in case the %(default)d (or so) is mentioned,
                        # to avoid producing incorrect help output.
                        # Assumption: Interpolated output can safely be interpolated again,
                        # which should always be the case.
                        # Note: We control all inputs.
                        kwargs["help"] = kwargs["help"] % kwargs
                        if not is_append:
                            kwargs["default"] = self.default_sentinel

                common_group.add_argument(*args, **kwargs)

            common_group = parser.add_argument_group("Common options")
            self.define_common_options(add_argument)

        def resolve(self, args: argparse.Namespace):  # Namespace has "in" but otherwise is not like a dict.
            """
            Resolve the multiple definitions of each common option to the final value.
            """
            for suffix in self.suffix_precedence:
                # From highest level to lowest level, so the "most-specific" option wins, e.g.
                # "borg --debug create --info" shall result in --info being effective.
                for dest in self.common_options.get(suffix, []):
                    # map_from is this suffix' option name, e.g. log_level_subcommand
                    # map_to is the target name, e.g. log_level
                    map_from = dest + suffix
                    map_to = dest
                    # Retrieve value; depending on the action it may not exist, but usually does
                    # (store_const/store_true/store_false), either because the action implied a default
                    # or a default is explicitly supplied.
                    # Note that defaults on lower levels are replaced with default_sentinel.
                    # Only the top level has defaults.
                    value = getattr(args, map_from, self.default_sentinel)
                    if value is not self.default_sentinel:
                        # value was indeed specified on this level. Transfer value to target,
                        # and un-clobber the args (for tidiness - you *cannot* use the suffixed
                        # names for other purposes, obviously).
                        setattr(args, map_to, value)
                    try:
                        delattr(args, map_from)
                    except AttributeError:
                        pass

            # Options with an "append" action need some special treatment. Instead of
            # overriding values, all specified values are merged together.
            for dest in self.append_options:
                option_value = []
                for suffix in self.suffix_precedence:
                    # Find values of this suffix, if any, and add them to the final list
                    extend_from = dest + suffix
                    if extend_from in args:
                        values = getattr(args, extend_from)
                        delattr(args, extend_from)
                        option_value.extend(values)
                setattr(args, dest, option_value)

    def build_parser(self):

        from .common import process_epilog
        from .common import define_exclusion_group, define_archive_filters_group

        def define_common_options(add_common_option):
            add_common_option("-h", "--help", action="help", help="show this help message and exit")
            add_common_option(
                "--critical",
                dest="log_level",
                action="store_const",
                const="critical",
                default="warning",
                help="work on log level CRITICAL",
            )
            add_common_option(
                "--error",
                dest="log_level",
                action="store_const",
                const="error",
                default="warning",
                help="work on log level ERROR",
            )
            add_common_option(
                "--warning",
                dest="log_level",
                action="store_const",
                const="warning",
                default="warning",
                help="work on log level WARNING (default)",
            )
            add_common_option(
                "--info",
                "-v",
                "--verbose",
                dest="log_level",
                action="store_const",
                const="info",
                default="warning",
                help="work on log level INFO",
            )
            add_common_option(
                "--debug",
                dest="log_level",
                action="store_const",
                const="debug",
                default="warning",
                help="enable debug output, work on log level DEBUG",
            )
            add_common_option(
                "--debug-topic",
                metavar="TOPIC",
                dest="debug_topics",
                action="append",
                default=[],
                help="enable TOPIC debugging (can be specified multiple times). "
                "The logger path is borg.debug.<TOPIC> if TOPIC is not fully qualified.",
            )
            add_common_option(
                "-p", "--progress", dest="progress", action="store_true", help="show progress information"
            )
            add_common_option("--iec", dest="iec", action="store_true", help="format using IEC units (1KiB = 1024B)")
            add_common_option(
                "--log-json",
                dest="log_json",
                action="store_true",
                help="Output one JSON object per log line instead of formatted text.",
            )
            add_common_option(
                "--lock-wait",
                metavar="SECONDS",
                dest="lock_wait",
                type=int,
                default=1,
                help="wait at most SECONDS for acquiring a repository/cache lock (default: %(default)d).",
            )
            add_common_option(
                "--bypass-lock",
                dest="lock",
                action="store_false",
                default=argparse.SUPPRESS,  # only create args attribute if option is specified
                help="Bypass locking mechanism",
            )
            add_common_option(
                "--show-version", dest="show_version", action="store_true", help="show/log the borg version"
            )
            add_common_option("--show-rc", dest="show_rc", action="store_true", help="show/log the return code (rc)")
            add_common_option(
                "--umask",
                metavar="M",
                dest="umask",
                type=lambda s: int(s, 8),
                default=UMASK_DEFAULT,
                help="set umask to M (local only, default: %(default)04o)",
            )
            add_common_option(
                "--remote-path",
                metavar="PATH",
                dest="remote_path",
                help='use PATH as borg executable on the remote (default: "borg")',
            )
            add_common_option(
                "--upload-ratelimit",
                metavar="RATE",
                dest="upload_ratelimit",
                type=int,
                help="set network upload rate limit in kiByte/s (default: 0=unlimited)",
            )
            add_common_option(
                "--upload-buffer",
                metavar="UPLOAD_BUFFER",
                dest="upload_buffer",
                type=int,
                help="set network upload buffer size in MiB. (default: 0=no buffer)",
            )
            add_common_option(
                "--consider-part-files",
                dest="consider_part_files",
                action="store_true",
                help="treat part files like normal files (e.g. to list/extract them)",
            )
            add_common_option(
                "--debug-profile",
                metavar="FILE",
                dest="debug_profile",
                default=None,
                help="Write execution profile in Borg format into FILE. For local use a Python-"
                'compatible file can be generated by suffixing FILE with ".pyprof".',
            )
            add_common_option(
                "--rsh",
                metavar="RSH",
                dest="rsh",
                help="Use this command to connect to the 'borg serve' process (default: 'ssh')",
            )
            add_common_option(
                "-r",
                "--repo",
                metavar="REPO",
                dest="location",
                type=location_validator(other=False),
                default=Location(other=False),
                help="repository to use",
            )

        parser = argparse.ArgumentParser(prog=self.prog, description="Borg - Deduplicated Backups", add_help=False)
        # paths and patterns must have an empty list as default everywhere
        parser.set_defaults(fallback2_func=functools.partial(self.do_maincommand_help, parser), paths=[], patterns=[])
        parser.common_options = self.CommonOptions(
            define_common_options, suffix_precedence=("_maincommand", "_midcommand", "_subcommand")
        )
        parser.add_argument(
            "-V", "--version", action="version", version="%(prog)s " + __version__, help="show version number and exit"
        )
        parser.common_options.add_common_group(parser, "_maincommand", provide_defaults=True)

        common_parser = argparse.ArgumentParser(add_help=False, prog=self.prog)
        common_parser.set_defaults(paths=[], patterns=[])
        parser.common_options.add_common_group(common_parser, "_subcommand")

        mid_common_parser = argparse.ArgumentParser(add_help=False, prog=self.prog)
        mid_common_parser.set_defaults(paths=[], patterns=[])
        parser.common_options.add_common_group(mid_common_parser, "_midcommand")

        if parser.prog == "borgfs":
            return self.build_parser_borgfs(parser)

        subparsers = parser.add_subparsers(title="required arguments", metavar="<command>")

        self.build_parser_benchmarks(subparsers, common_parser, mid_common_parser)
        self.build_parser_check(subparsers, common_parser, mid_common_parser)
        self.build_parser_compact(subparsers, common_parser, mid_common_parser)
        self.build_parser_diff(subparsers, common_parser, mid_common_parser)
        self.build_parser_locks(subparsers, common_parser, mid_common_parser)
        self.build_parser_mount_umount(subparsers, common_parser, mid_common_parser)
        self.build_parser_prune(subparsers, common_parser, mid_common_parser)

        # borg create
        create_epilog = process_epilog(
            """
        This command creates a backup archive containing all files found while recursively
        traversing all paths specified. Paths are added to the archive as they are given,
        that means if relative paths are desired, the command has to be run from the correct
        directory.

        When giving '-' as path, borg will read data from standard input and create a
        file 'stdin' in the created archive from that data. In some cases it's more
        appropriate to use --content-from-command, however. See section *Reading from
        stdin* below for details.

        The archive will consume almost no disk space for files or parts of files that
        have already been stored in other archives.

        The archive name needs to be unique. It must not end in '.checkpoint' or
        '.checkpoint.N' (with N being a number), because these names are used for
        checkpoints and treated in special ways.

        In the archive name, you may use the following placeholders:
        {now}, {utcnow}, {fqdn}, {hostname}, {user} and some others.

        Backup speed is increased by not reprocessing files that are already part of
        existing archives and weren't modified. The detection of unmodified files is
        done by comparing multiple file metadata values with previous values kept in
        the files cache.

        This comparison can operate in different modes as given by ``--files-cache``:

        - ctime,size,inode (default)
        - mtime,size,inode (default behaviour of borg versions older than 1.1.0rc4)
        - ctime,size (ignore the inode number)
        - mtime,size (ignore the inode number)
        - rechunk,ctime (all files are considered modified - rechunk, cache ctime)
        - rechunk,mtime (all files are considered modified - rechunk, cache mtime)
        - disabled (disable the files cache, all files considered modified - rechunk)

        inode number: better safety, but often unstable on network filesystems

        Normally, detecting file modifications will take inode information into
        consideration to improve the reliability of file change detection.
        This is problematic for files located on sshfs and similar network file
        systems which do not provide stable inode numbers, such files will always
        be considered modified. You can use modes without `inode` in this case to
        improve performance, but reliability of change detection might be reduced.

        ctime vs. mtime: safety vs. speed

        - ctime is a rather safe way to detect changes to a file (metadata and contents)
          as it can not be set from userspace. But, a metadata-only change will already
          update the ctime, so there might be some unnecessary chunking/hashing even
          without content changes. Some filesystems do not support ctime (change time).
          E.g. doing a chown or chmod to a file will change its ctime.
        - mtime usually works and only updates if file contents were changed. But mtime
          can be arbitrarily set from userspace, e.g. to set mtime back to the same value
          it had before a content change happened. This can be used maliciously as well as
          well-meant, but in both cases mtime based cache modes can be problematic.

        The mount points of filesystems or filesystem snapshots should be the same for every
        creation of a new archive to ensure fast operation. This is because the file cache that
        is used to determine changed files quickly uses absolute filenames.
        If this is not possible, consider creating a bind mount to a stable location.

        The ``--progress`` option shows (from left to right) Original, Compressed and Deduplicated
        (O, C and D, respectively), then the Number of files (N) processed so far, followed by
        the currently processed path.

        When using ``--stats``, you will get some statistics about how much data was
        added - the "This Archive" deduplicated size there is most interesting as that is
        how much your repository will grow. Please note that the "All archives" stats refer to
        the state after creation. Also, the ``--stats`` and ``--dry-run`` options are mutually
        exclusive because the data is not actually compressed and deduplicated during a dry run.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        For more help on placeholders, see the :ref:`borg_placeholders` command output.

        .. man NOTES

        The ``--exclude`` patterns are not like tar. In tar ``--exclude`` .bundler/gems will
        exclude foo/.bundler/gems. In borg it will not, you need to use ``--exclude``
        '\\*/.bundler/gems' to get the same effect.

        In addition to using ``--exclude`` patterns, it is possible to use
        ``--exclude-if-present`` to specify the name of a filesystem object (e.g. a file
        or folder name) which, when contained within another folder, will prevent the
        containing folder from being backed up.  By default, the containing folder and
        all of its contents will be omitted from the backup.  If, however, you wish to
        only include the objects specified by ``--exclude-if-present`` in your backup,
        and not include any other contents of the containing folder, this can be enabled
        through using the ``--keep-exclude-tags`` option.

        The ``-x`` or ``--one-file-system`` option excludes directories, that are mountpoints (and everything in them).
        It detects mountpoints by comparing the device number from the output of ``stat()`` of the directory and its
        parent directory. Specifically, it excludes directories for which ``stat()`` reports a device number different
        from the device number of their parent. Be aware that in Linux (and possibly elsewhere) there are directories
        with device number different from their parent, which the kernel does not consider a mountpoint and also the
        other way around. Examples are bind mounts (possibly same device number, but always a mountpoint) and ALL
        subvolumes of a btrfs (different device number from parent but not necessarily a mountpoint). Therefore when
        using ``--one-file-system``, one should make doubly sure that the backup works as intended especially when using
        btrfs. This is even more important, if the btrfs layout was created by someone else, e.g. a distribution
        installer.


        .. _list_item_flags:

        Item flags
        ++++++++++

        ``--list`` outputs a list of all files, directories and other
        file system items it considered (no matter whether they had content changes
        or not). For each item, it prefixes a single-letter flag that indicates type
        and/or status of the item.

        If you are interested only in a subset of that output, you can give e.g.
        ``--filter=AME`` and it will only show regular files with A, M or E status (see
        below).

        A uppercase character represents the status of a regular file relative to the
        "files" cache (not relative to the repo -- this is an issue if the files cache
        is not used). Metadata is stored in any case and for 'A' and 'M' also new data
        chunks are stored. For 'U' all data chunks refer to already existing chunks.

        - 'A' = regular file, added (see also :ref:`a_status_oddity` in the FAQ)
        - 'M' = regular file, modified
        - 'U' = regular file, unchanged
        - 'C' = regular file, it changed while we backed it up
        - 'E' = regular file, an error happened while accessing/reading *this* file

        A lowercase character means a file type other than a regular file,
        borg usually just stores their metadata:

        - 'd' = directory
        - 'b' = block device
        - 'c' = char device
        - 'h' = regular file, hardlink (to already seen inodes)
        - 's' = symlink
        - 'f' = fifo

        Other flags used include:

        - 'i' = backup data was read from standard input (stdin)
        - '-' = dry run, item was *not* backed up
        - 'x' = excluded, item was *not* backed up
        - '?' = missing status code (if you see this, please file a bug report!)

        Reading from stdin
        ++++++++++++++++++

        There are two methods to read from stdin. Either specify ``-`` as path and
        pipe directly to borg::

            backup-vm --id myvm --stdout | borg create REPO::ARCHIVE -

        Or use ``--content-from-command`` to have Borg manage the execution of the
        command and piping. If you do so, the first PATH argument is interpreted
        as command to execute and any further arguments are treated as arguments
        to the command::

            borg create --content-from-command REPO::ARCHIVE -- backup-vm --id myvm --stdout

        ``--`` is used to ensure ``--id`` and ``--stdout`` are **not** considered
        arguments to ``borg`` but rather ``backup-vm``.

        The difference between the two approaches is that piping to borg creates an
        archive even if the command piping to borg exits with a failure. In this case,
        **one can end up with truncated output being backed up**. Using
        ``--content-from-command``, in contrast, borg is guaranteed to fail without
        creating an archive should the command fail. The command is considered failed
        when it returned a non-zero exit code.

        Reading from stdin yields just a stream of data without file metadata
        associated with it, and the files cache is not needed at all. So it is
        safe to disable it via ``--files-cache disabled`` and speed up backup
        creation a bit.

        By default, the content read from stdin is stored in a file called 'stdin'.
        Use ``--stdin-name`` to change the name.
        """
        )

        subparser = subparsers.add_parser(
            "create",
            parents=[common_parser],
            add_help=False,
            description=self.do_create.__doc__,
            epilog=create_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="create backup",
        )
        subparser.set_defaults(func=self.do_create)

        # note: --dry-run and --stats are mutually exclusive, but we do not want to abort when
        #  parsing, but rather proceed with the dry-run, but without stats (see run() method).
        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not create a backup archive"
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics for the created archive"
        )

        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "--filter",
            metavar="STATUSCHARS",
            dest="output_filter",
            action=Highlander,
            help="only display items with the given status characters (see description)",
        )
        subparser.add_argument("--json", action="store_true", help="output stats as JSON. Implies ``--stats``.")
        subparser.add_argument(
            "--no-cache-sync",
            dest="no_cache_sync",
            action="store_true",
            help="experimental: do not synchronize the cache. Implies not using the files cache.",
        )
        subparser.add_argument(
            "--stdin-name",
            metavar="NAME",
            dest="stdin_name",
            default="stdin",
            help="use NAME in archive for stdin data (default: %(default)r)",
        )
        subparser.add_argument(
            "--stdin-user",
            metavar="USER",
            dest="stdin_user",
            default=uid2user(0),
            help="set user USER in archive for stdin data (default: %(default)r)",
        )
        subparser.add_argument(
            "--stdin-group",
            metavar="GROUP",
            dest="stdin_group",
            default=gid2group(0),
            help="set group GROUP in archive for stdin data (default: %(default)r)",
        )
        subparser.add_argument(
            "--stdin-mode",
            metavar="M",
            dest="stdin_mode",
            type=lambda s: int(s, 8),
            default=STDIN_MODE_DEFAULT,
            help="set mode to M in archive for stdin data (default: %(default)04o)",
        )
        subparser.add_argument(
            "--content-from-command",
            action="store_true",
            help="interpret PATH as command and store its stdout. See also section Reading from" " stdin below.",
        )
        subparser.add_argument(
            "--paths-from-stdin",
            action="store_true",
            help="read DELIM-separated list of paths to backup from stdin. Will not " "recurse into directories.",
        )
        subparser.add_argument(
            "--paths-from-command",
            action="store_true",
            help="interpret PATH as command and treat its output as ``--paths-from-stdin``",
        )
        subparser.add_argument(
            "--paths-delimiter",
            metavar="DELIM",
            help="set path delimiter for ``--paths-from-stdin`` and ``--paths-from-command`` (default: \\n) ",
        )

        exclude_group = define_exclusion_group(subparser, tag_files=True)
        exclude_group.add_argument(
            "--exclude-nodump", dest="exclude_nodump", action="store_true", help="exclude files flagged NODUMP"
        )

        fs_group = subparser.add_argument_group("Filesystem options")
        fs_group.add_argument(
            "-x",
            "--one-file-system",
            dest="one_file_system",
            action="store_true",
            help="stay in the same file system and do not store mount points of other file systems.  This might behave different from your expectations, see the docs.",
        )
        fs_group.add_argument(
            "--numeric-ids",
            dest="numeric_ids",
            action="store_true",
            help="only store numeric user and group identifiers",
        )
        fs_group.add_argument("--atime", dest="atime", action="store_true", help="do store atime into archive")
        fs_group.add_argument("--noctime", dest="noctime", action="store_true", help="do not store ctime into archive")
        fs_group.add_argument(
            "--nobirthtime",
            dest="nobirthtime",
            action="store_true",
            help="do not store birthtime (creation date) into archive",
        )
        fs_group.add_argument(
            "--noflags",
            dest="noflags",
            action="store_true",
            help="do not read and store flags (e.g. NODUMP, IMMUTABLE) into archive",
        )
        fs_group.add_argument(
            "--noacls", dest="noacls", action="store_true", help="do not read and store ACLs into archive"
        )
        fs_group.add_argument(
            "--noxattrs", dest="noxattrs", action="store_true", help="do not read and store xattrs into archive"
        )
        fs_group.add_argument(
            "--sparse",
            dest="sparse",
            action="store_true",
            help="detect sparse holes in input (supported only by fixed chunker)",
        )
        fs_group.add_argument(
            "--files-cache",
            metavar="MODE",
            dest="files_cache_mode",
            action=Highlander,
            type=FilesCacheMode,
            default=FILES_CACHE_MODE_UI_DEFAULT,
            help="operate files cache in MODE. default: %s" % FILES_CACHE_MODE_UI_DEFAULT,
        )
        fs_group.add_argument(
            "--read-special",
            dest="read_special",
            action="store_true",
            help="open and read block and char device files as well as FIFOs as if they were "
            "regular files. Also follows symlinks pointing to these kinds of files.",
        )

        archive_group = subparser.add_argument_group("Archive options")
        archive_group.add_argument(
            "--comment",
            dest="comment",
            metavar="COMMENT",
            type=CommentSpec,
            default="",
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            metavar="TIMESTAMP",
            dest="timestamp",
            type=timestamp,
            default=None,
            help="manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). "
            "Alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "-c",
            "--checkpoint-interval",
            metavar="SECONDS",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )
        archive_group.add_argument(
            "--chunker-params",
            metavar="PARAMS",
            dest="chunker_params",
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            action=Highlander,
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, HASH_WINDOW_SIZE). default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )

        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument("paths", metavar="PATH", nargs="*", type=str, help="paths to archive")

        self.build_parser_config(subparsers, common_parser, mid_common_parser)
        self.build_parser_debug(subparsers, common_parser, mid_common_parser)
        self.build_parser_help(subparsers, common_parser, mid_common_parser, parser)
        self.build_parser_rdelete(subparsers, common_parser, mid_common_parser, parser)

        # borg delete
        delete_epilog = process_epilog(
            """
        This command deletes archives from the repository.

        Important: When deleting archives, repository disk space is **not** freed until
        you run ``borg compact``.

        When in doubt, use ``--dry-run --list`` to see what would be deleted.

        When using ``--stats``, you will get some statistics about how much data was
        deleted - the "Deleted data" deduplicated size there is most interesting as
        that is how much your repository will shrink.
        Please note that the "All archives" stats refer to the state after deletion.

        You can delete multiple archives by specifying a matching shell pattern,
        using the ``--glob-archives GLOB`` option (for more info on these patterns,
        see :ref:`borg_patterns`).

        Always first use ``--dry-run --list`` to see what would be deleted.
        """
        )
        subparser = subparsers.add_parser(
            "delete",
            parents=[common_parser],
            add_help=False,
            description=self.do_delete.__doc__,
            epilog=delete_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="delete archive",
        )
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository")
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives"
        )
        subparser.add_argument(
            "--consider-checkpoints",
            action="store_true",
            dest="consider_checkpoints",
            help="consider checkpoint archives for deletion (default: not considered).",
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics for the deleted archive"
        )
        subparser.add_argument(
            "--cache-only",
            dest="cache_only",
            action="store_true",
            help="delete only the local cache for the given repository",
        )
        subparser.add_argument(
            "--force",
            dest="forced",
            action="count",
            default=0,
            help="force deletion of corrupted archives, " "use ``--force --force`` in case ``--force`` does not work.",
        )
        subparser.add_argument(
            "--keep-security-info",
            dest="keep_security_info",
            action="store_true",
            help="keep the local security info when deleting a repository",
        )
        subparser.add_argument(
            "--save-space", dest="save_space", action="store_true", help="work slower, but using less space"
        )
        define_archive_filters_group(subparser)

        # borg extract
        extract_epilog = process_epilog(
            """
        This command extracts the contents of an archive. By default the entire
        archive is extracted but a subset of files and directories can be selected
        by passing a list of ``PATHs`` as arguments. The file selection can further
        be restricted by using the ``--exclude`` option.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        By using ``--dry-run``, you can do all extraction steps except actually writing the
        output data: reading metadata and data chunks from the repo, checking the hash/hmac,
        decrypting, decompressing.

        ``--progress`` can be slower than no progress display, since it makes one additional
        pass over the archive metadata.

        .. note::

            Currently, extract always writes into the current working directory ("."),
            so make sure you ``cd`` to the right place before calling ``borg extract``.

            When parent directories are not extracted (because of using file/directory selection
            or any other reason), borg can not restore parent directories' metadata, e.g. owner,
            group, permission, etc.
        """
        )
        subparser = subparsers.add_parser(
            "extract",
            parents=[common_parser],
            add_help=False,
            description=self.do_extract.__doc__,
            epilog=extract_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="extract archive contents",
        )
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not actually change any files"
        )
        subparser.add_argument(
            "--numeric-ids",
            dest="numeric_ids",
            action="store_true",
            help="only obey numeric user and group identifiers",
        )
        subparser.add_argument(
            "--noflags", dest="noflags", action="store_true", help="do not extract/set flags (e.g. NODUMP, IMMUTABLE)"
        )
        subparser.add_argument("--noacls", dest="noacls", action="store_true", help="do not extract/set ACLs")
        subparser.add_argument("--noxattrs", dest="noxattrs", action="store_true", help="do not extract/set xattrs")
        subparser.add_argument(
            "--stdout", dest="stdout", action="store_true", help="write all extracted data to stdout"
        )
        subparser.add_argument(
            "--sparse",
            dest="sparse",
            action="store_true",
            help="create holes in output sparse file from all-zero chunks",
        )
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(subparser, strip_components=True)

        # borg rinfo
        rinfo_epilog = process_epilog(
            """
        This command displays detailed information about the repository.

        Please note that the deduplicated sizes of the individual archives do not add
        up to the deduplicated size of the repository ("all archives"), because the two
        are meaning different things:

        This archive / deduplicated size = amount of data stored ONLY for this archive
        = unique chunks of this archive.
        All archives / deduplicated size = amount of data stored in the repo
        = all chunks in the repository.
        """
        )
        subparser = subparsers.add_parser(
            "rinfo",
            parents=[common_parser],
            add_help=False,
            description=self.do_rinfo.__doc__,
            epilog=rinfo_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show repository information",
        )
        subparser.set_defaults(func=self.do_rinfo)
        subparser.add_argument("--json", action="store_true", help="format output as JSON")

        # borg info
        info_epilog = process_epilog(
            """
        This command displays detailed information about the specified archive.

        Please note that the deduplicated sizes of the individual archives do not add
        up to the deduplicated size of the repository ("all archives"), because the two
        are meaning different things:

        This archive / deduplicated size = amount of data stored ONLY for this archive
        = unique chunks of this archive.
        All archives / deduplicated size = amount of data stored in the repo
        = all chunks in the repository.

        Borg archives can only contain a limited amount of file metadata.
        The size of an archive relative to this limit depends on a number of factors,
        mainly the number of files, the lengths of paths and other metadata stored for files.
        This is shown as *utilization of maximum supported archive size*.
        """
        )
        subparser = subparsers.add_parser(
            "info",
            parents=[common_parser],
            add_help=False,
            description=self.do_info.__doc__,
            epilog=info_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show repository or archive information",
        )
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
        define_archive_filters_group(subparser)

        self.build_parser_keys(subparsers, common_parser, mid_common_parser)
        self.build_parser_rcreate(subparsers, common_parser, mid_common_parser)

        # borg list
        list_epilog = (
            process_epilog(
                """
        This command lists the contents of an archive.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses python's `format string syntax
        <https://docs.python.org/3.9/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg list --format '{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}' ArchiveFoo
            -rw-rw-r-- user   user       1024 Thu, 2021-12-09 10:22:17 file-foo
            ...

            # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
            # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
            $ borg list --format '{mode} {user:>6} {group:>6} {size:<8} {mtime} {path}{extra}{NL}' ArchiveFoo
            -rw-rw-r--   user   user 1024     Thu, 2021-12-09 10:22:17 file-foo
            ...

        The following keys are always available:


        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when listing files in an archive:

        """
            )
            + ItemFormatter.keys_help()
        )
        subparser = subparsers.add_parser(
            "list",
            parents=[common_parser],
            add_help=False,
            description=self.do_list.__doc__,
            epilog=list_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="list archive contents",
        )
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print file/directory names, nothing else"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            help="specify format for file listing "
            '(default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")',
        )
        subparser.add_argument(
            "--json-lines",
            action="store_true",
            help="Format output as JSON Lines. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text. "
            'A "bpath" key is therefore not available.',
        )
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to list; patterns are supported"
        )
        define_exclusion_group(subparser)

        # borg rlist
        rlist_epilog = (
            process_epilog(
                """
        This command lists the archives contained in a repository.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses python's `format string syntax
        <https://docs.python.org/3.9/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg rlist --format '{archive}{NL}'
            ArchiveFoo
            ArchiveBar
            ...

            # {VAR:NUMBER} - pad to NUMBER columns.
            # Strings are left-aligned, numbers are right-aligned.
            # Note: time columns except ``isomtime``, ``isoctime`` and ``isoatime`` cannot be padded.
            $ borg rlist --format '{archive:36} {time} [{id}]{NL}' /path/to/repo
            ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9a312bef3f2f6e2d0fc110c196827786c15eba0188738e81697a7fa3b274]
            ...

        The following keys are always available:


        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when listing archives in a repository:

        """
            )
            + ArchiveFormatter.keys_help()
        )
        subparser = subparsers.add_parser(
            "rlist",
            parents=[common_parser],
            add_help=False,
            description=self.do_rlist.__doc__,
            epilog=rlist_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="list repository contents",
        )
        subparser.set_defaults(func=self.do_rlist)
        subparser.add_argument(
            "--consider-checkpoints",
            action="store_true",
            dest="consider_checkpoints",
            help="Show checkpoint archives in the repository contents list (default: hidden).",
        )
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print the archive names, nothing else"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            help="specify format for archive listing " '(default: "{archive:<36} {time} [{id}]{NL}")',
        )
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Format output as JSON. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text. "
            'A "barchive" key is therefore not available.',
        )
        define_archive_filters_group(subparser)

        # borg recreate
        recreate_epilog = process_epilog(
            """
        Recreate the contents of existing archives.

        recreate is a potentially dangerous function and might lead to data loss
        (if used wrongly). BE VERY CAREFUL!

        Important: Repository disk space is **not** freed until you run ``borg compact``.

        ``--exclude``, ``--exclude-from``, ``--exclude-if-present``, ``--keep-exclude-tags``
        and PATH have the exact same semantics as in "borg create", but they only check
        for files in the archives and not in the local file system. If PATHs are specified,
        the resulting archives will only contain files from these PATHs.

        Note that all paths in an archive are relative, therefore absolute patterns/paths
        will *not* match (``--exclude``, ``--exclude-from``, PATHs).

        ``--recompress`` allows one to change the compression of existing data in archives.
        Due to how Borg stores compressed size information this might display
        incorrect information for archives that were not recreated at the same time.
        There is no risk of data loss by this.

        ``--chunker-params`` will re-chunk all files in the archive, this can be
        used to have upgraded Borg 0.xx or Attic archives deduplicate with
        Borg 1.x archives.

        **USE WITH CAUTION.**
        Depending on the PATHs and patterns given, recreate can be used to permanently
        delete files from archives.
        When in doubt, use ``--dry-run --verbose --list`` to see how patterns/PATHS are
        interpreted. See :ref:`list_item_flags` in ``borg create`` for details.

        The archive being recreated is only removed after the operation completes. The
        archive that is built during the operation exists at the same time at
        "<ARCHIVE>.recreate". The new archive will have a different archive ID.

        With ``--target`` the original archive is not replaced, instead a new archive is created.

        When rechunking (or recompressing), space usage can be substantial - expect
        at least the entire deduplicated size of the archives using the previous
        chunker (or compression) params.

        If you recently ran borg check --repair and it had to fix lost chunks with all-zero
        replacement chunks, please first run another backup for the same data and re-run
        borg check --repair afterwards to heal any archives that had lost chunks which are
        still generated from the input data.

        Important: running borg recreate to re-chunk will remove the chunks_healthy
        metadata of all items with replacement chunks, so healing will not be possible
        any more after re-chunking (it is also unlikely it would ever work: due to the
        change of chunking parameters, the missing chunk likely will never be seen again
        even if you still have the data that produced it).
        """
        )
        subparser = subparsers.add_parser(
            "recreate",
            parents=[common_parser],
            add_help=False,
            description=self.do_recreate.__doc__,
            epilog=recreate_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help=self.do_recreate.__doc__,
        )
        subparser.set_defaults(func=self.do_recreate)
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "--filter",
            metavar="STATUSCHARS",
            dest="output_filter",
            action=Highlander,
            help="only display items with the given status characters (listed in borg create --help)",
        )
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change anything")
        subparser.add_argument("-s", "--stats", dest="stats", action="store_true", help="print statistics at end")

        define_exclusion_group(subparser, tag_files=True)

        archive_group = define_archive_filters_group(subparser)
        archive_group.add_argument(
            "--target",
            dest="target",
            metavar="TARGET",
            default=None,
            type=archivename_validator(),
            help="create a new archive with the name ARCHIVE, do not replace existing archive "
            "(only applies for a single archive)",
        )
        archive_group.add_argument(
            "-c",
            "--checkpoint-interval",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            metavar="SECONDS",
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )
        archive_group.add_argument(
            "--comment",
            dest="comment",
            metavar="COMMENT",
            type=CommentSpec,
            default=None,
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            metavar="TIMESTAMP",
            dest="timestamp",
            type=timestamp,
            default=None,
            help="manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). "
            "alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        archive_group.add_argument(
            "--recompress",
            metavar="MODE",
            dest="recompress",
            nargs="?",
            default="never",
            const="if-different",
            choices=("never", "if-different", "always"),
            help="recompress data chunks according to `MODE` and ``--compression``. "
            "Possible modes are "
            "`if-different`: recompress if current compression is with a different "
            "compression algorithm or different level; "
            "`always`: recompress unconditionally; and "
            "`never`: do not recompress (use this option to explicitly prevent "
            "recompression). "
            "If no MODE is given, `if-different` will be used. "
            'Not passing --recompress is equivalent to "--recompress never".',
        )
        archive_group.add_argument(
            "--chunker-params",
            metavar="PARAMS",
            dest="chunker_params",
            action=Highlander,
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the current defaults. "
            "default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )

        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to recreate; patterns are supported"
        )

        # borg rename
        rename_epilog = process_epilog(
            """
        This command renames an archive in the repository.

        This results in a different archive ID.
        """
        )
        subparser = subparsers.add_parser(
            "rename",
            parents=[common_parser],
            add_help=False,
            description=self.do_rename.__doc__,
            epilog=rename_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="rename archive",
        )
        subparser.set_defaults(func=self.do_rename)
        subparser.add_argument("name", metavar="OLDNAME", type=archivename_validator(), help="specify the archive name")
        subparser.add_argument(
            "newname", metavar="NEWNAME", type=archivename_validator(), help="specify the new archive name"
        )

        self.build_parser_serve(subparsers, common_parser, mid_common_parser)
        self.build_parser_tar(subparsers, common_parser, mid_common_parser)

        self.build_parser_transfer(subparsers, common_parser, mid_common_parser)

        return parser

    def get_args(self, argv, cmd):
        """usually, just returns argv, except if we deal with a ssh forced command for borg serve."""
        result = self.parse_args(argv[1:])
        if cmd is not None and result.func == self.do_serve:
            # borg serve case:
            # - "result" is how borg got invoked (e.g. via forced command from authorized_keys),
            # - "client_result" (from "cmd") refers to the command the client wanted to execute,
            #   which might be different in the case of a forced command or same otherwise.
            client_argv = shlex.split(cmd)
            # Drop environment variables (do *not* interpret them) before trying to parse
            # the borg command line.
            client_argv = list(itertools.dropwhile(lambda arg: "=" in arg, client_argv))
            client_result = self.parse_args(client_argv[1:])
            if client_result.func == result.func:
                # make sure we only process like normal if the client is executing
                # the same command as specified in the forced command, otherwise
                # just skip this block and return the forced command (== result).
                # client is allowed to specify the allowlisted options,
                # everything else comes from the forced "borg serve" command (or the defaults).
                # stuff from denylist must never be used from the client.
                denylist = {"restrict_to_paths", "restrict_to_repositories", "append_only", "storage_quota", "umask"}
                allowlist = {"debug_topics", "lock_wait", "log_level"}
                not_present = object()
                for attr_name in allowlist:
                    assert attr_name not in denylist, "allowlist has denylisted attribute name %s" % attr_name
                    value = getattr(client_result, attr_name, not_present)
                    if value is not not_present:
                        # note: it is not possible to specify a allowlisted option via a forced command,
                        # it always gets overridden by the value specified (or defaulted to) by the client command.
                        setattr(result, attr_name, value)

        return result

    def parse_args(self, args=None):
        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)
        parser = self.build_parser()
        args = parser.parse_args(args or ["-h"])
        parser.common_options.resolve(args)
        func = get_func(args)
        if func == self.do_create and args.paths and args.paths_from_stdin:
            parser.error("Must not pass PATH with ``--paths-from-stdin``.")
        if func == self.do_create and not args.paths:
            if args.content_from_command or args.paths_from_command:
                parser.error("No command given.")
            elif not args.paths_from_stdin:
                # need at least 1 path but args.paths may also be populated from patterns
                parser.error("Need at least one PATH argument.")
        if not getattr(args, "lock", True):  # Option --bypass-lock sets args.lock = False
            bypass_allowed = {
                self.do_check,
                self.do_config,
                self.do_diff,
                self.do_export_tar,
                self.do_extract,
                self.do_info,
                self.do_rinfo,
                self.do_list,
                self.do_rlist,
                self.do_mount,
                self.do_umount,
            }
            if func not in bypass_allowed:
                raise Error("Not allowed to bypass locking mechanism for chosen command")
        if getattr(args, "timestamp", None):
            args.location = args.location.with_timestamp(args.timestamp)
        return args

    def prerun_checks(self, logger, is_serve):
        if not is_serve:
            # this is the borg *client*, we need to check the python:
            check_python()
        check_extension_modules()
        selftest(logger)

    def _setup_implied_logging(self, args):
        """turn on INFO level logging for args that imply that they will produce output"""
        # map of option name to name of logger for that option
        option_logger = {
            "output_list": "borg.output.list",
            "show_version": "borg.output.show-version",
            "show_rc": "borg.output.show-rc",
            "stats": "borg.output.stats",
            "progress": "borg.output.progress",
        }
        for option, logger_name in option_logger.items():
            option_set = args.get(option, False)
            logging.getLogger(logger_name).setLevel("INFO" if option_set else "WARN")

    def _setup_topic_debugging(self, args):
        """Turn on DEBUG level logging for specified --debug-topics."""
        for topic in args.debug_topics:
            if "." not in topic:
                topic = "borg.debug." + topic
            logger.debug("Enabling debug topic %s", topic)
            logging.getLogger(topic).setLevel("DEBUG")

    def run(self, args):
        os.umask(args.umask)  # early, before opening files
        self.lock_wait = args.lock_wait
        func = get_func(args)
        # do not use loggers before this!
        is_serve = func == self.do_serve
        setup_logging(level=args.log_level, is_serve=is_serve, json=args.log_json)
        self.log_json = args.log_json
        args.progress |= is_serve
        self._setup_implied_logging(vars(args))
        self._setup_topic_debugging(args)
        if getattr(args, "stats", False) and getattr(args, "dry_run", False):
            # the data needed for --stats is not computed when using --dry-run, so we can't do it.
            # for ease of scripting, we just ignore --stats when given with --dry-run.
            logger.warning("Ignoring --stats. It is not supported when using --dry-run.")
            args.stats = False
        if args.show_version:
            logging.getLogger("borg.output.show-version").info("borgbackup version %s" % __version__)
        self.prerun_checks(logger, is_serve)
        if not is_supported_msgpack():
            logger.error("You do not have a supported version of the msgpack python package installed. Terminating.")
            logger.error("This should never happen as specific, supported versions are required by our setup.py.")
            logger.error("Do not contact borgbackup support about this.")
            return set_ec(EXIT_ERROR)
        if is_slow_msgpack():
            logger.warning(PURE_PYTHON_MSGPACK_WARNING)
        if args.debug_profile:
            # Import only when needed - avoids a further increase in startup time
            import cProfile
            import marshal

            logger.debug("Writing execution profile to %s", args.debug_profile)
            # Open the file early, before running the main program, to avoid
            # a very late crash in case the specified path is invalid.
            with open(args.debug_profile, "wb") as fd:
                profiler = cProfile.Profile()
                variables = dict(locals())
                profiler.enable()
                try:
                    return set_ec(func(args))
                finally:
                    profiler.disable()
                    profiler.snapshot_stats()
                    if args.debug_profile.endswith(".pyprof"):
                        marshal.dump(profiler.stats, fd)
                    else:
                        # We use msgpack here instead of the marshal module used by cProfile itself,
                        # because the latter is insecure. Since these files may be shared over the
                        # internet we don't want a format that is impossible to interpret outside
                        # an insecure implementation.
                        # See scripts/msgpack2marshal.py for a small script that turns a msgpack file
                        # into a marshal file that can be read by e.g. pyprof2calltree.
                        # For local use it's unnecessary hassle, though, that's why .pyprof makes
                        # it compatible (see above).
                        msgpack.pack(profiler.stats, fd, use_bin_type=True)
        else:
            return set_ec(func(args))


def sig_info_handler(sig_no, stack):  # pragma: no cover
    """search the stack for infos about the currently processed file and print them"""
    with signal_handler(sig_no, signal.SIG_IGN):
        for frame in inspect.getouterframes(stack):
            func, loc = frame[3], frame[0].f_locals
            if func in ("process_file", "_rec_walk"):  # create op
                path = loc["path"]
                try:
                    pos = loc["fd"].tell()
                    total = loc["st"].st_size
                except Exception:
                    pos, total = 0, 0
                logger.info(f"{path} {format_file_size(pos)}/{format_file_size(total)}")
                break
            if func in ("extract_item",):  # extract op
                path = loc["item"].path
                try:
                    pos = loc["fd"].tell()
                except Exception:
                    pos = 0
                logger.info(f"{path} {format_file_size(pos)}/???")
                break


def sig_trace_handler(sig_no, stack):  # pragma: no cover
    print("\nReceived SIGUSR2 at %s, dumping trace..." % datetime.now().replace(microsecond=0), file=sys.stderr)
    faulthandler.dump_traceback()


def main():  # pragma: no cover
    # Make sure stdout and stderr have errors='replace' to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = ErrorIgnoringTextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, "replace", line_buffering=True)
    sys.stderr = ErrorIgnoringTextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, "replace", line_buffering=True)

    # If we receive SIGINT (ctrl-c), SIGTERM (kill) or SIGHUP (kill -HUP),
    # catch them and raise a proper exception that can be handled for an
    # orderly exit.
    # SIGHUP is important especially for systemd systems, where logind
    # sends it when a session exits, in addition to any traditional use.
    # Output some info if we receive SIGUSR1 or SIGINFO (ctrl-t).

    # Register fault handler for SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL.
    faulthandler.enable()
    with signal_handler("SIGINT", raising_signal_handler(KeyboardInterrupt)), signal_handler(
        "SIGHUP", raising_signal_handler(SigHup)
    ), signal_handler("SIGTERM", raising_signal_handler(SigTerm)), signal_handler(
        "SIGUSR1", sig_info_handler
    ), signal_handler(
        "SIGUSR2", sig_trace_handler
    ), signal_handler(
        "SIGINFO", sig_info_handler
    ):
        archiver = Archiver()
        msg = msgid = tb = None
        tb_log_level = logging.ERROR
        try:
            args = archiver.get_args(sys.argv, os.environ.get("SSH_ORIGINAL_COMMAND"))
        except Error as e:
            msg = e.get_message()
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            # we might not have logging setup yet, so get out quickly
            print(msg, file=sys.stderr)
            if tb_log_level == logging.ERROR:
                print(tb, file=sys.stderr)
            sys.exit(e.exit_code)
        try:
            with sig_int:
                exit_code = archiver.run(args)
        except Error as e:
            msg = e.get_message()
            msgid = type(e).__qualname__
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = e.exit_code
        except RemoteRepository.RPCError as e:
            important = e.exception_class not in ("LockTimeout",) and e.traceback
            msgid = e.exception_class
            tb_log_level = logging.ERROR if important else logging.DEBUG
            if important:
                msg = e.exception_full
            else:
                msg = e.get_message()
            tb = "\n".join("Borg server: " + l for l in e.sysinfo.splitlines())
            tb += "\n" + sysinfo()
            exit_code = EXIT_ERROR
        except Exception:
            msg = "Local Exception"
            msgid = "Exception"
            tb_log_level = logging.ERROR
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_ERROR
        except KeyboardInterrupt:
            msg = "Keyboard interrupt"
            tb_log_level = logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_SIGNAL_BASE + 2
        except SigTerm:
            msg = "Received SIGTERM"
            msgid = "Signal.SIGTERM"
            tb_log_level = logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_SIGNAL_BASE + 15
        except SigHup:
            msg = "Received SIGHUP."
            msgid = "Signal.SIGHUP"
            exit_code = EXIT_SIGNAL_BASE + 1
        if msg:
            logger.error(msg, msgid=msgid)
        if tb:
            logger.log(tb_log_level, tb)
        if args.show_rc:
            rc_logger = logging.getLogger("borg.output.show-rc")
            exit_msg = "terminating with %s status, rc %d"
            if exit_code == EXIT_SUCCESS:
                rc_logger.info(exit_msg % ("success", exit_code))
            elif exit_code == EXIT_WARNING:
                rc_logger.warning(exit_msg % ("warning", exit_code))
            elif exit_code == EXIT_ERROR:
                rc_logger.error(exit_msg % ("error", exit_code))
            elif exit_code >= EXIT_SIGNAL_BASE:
                rc_logger.error(exit_msg % ("signal", exit_code))
            else:
                rc_logger.error(exit_msg % ("abnormal", exit_code or 666))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
