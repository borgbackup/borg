import errno
import sys
import logging
import os
import posixpath
import stat
import subprocess
import time
from io import TextIOWrapper

from ._common import with_repository, Highlander
from .. import helpers
from ..archive import Archive, Statistics, is_special, SF_DATALESS
from ..archive import BackupError, BackupOSError, BackupItemExcluded, backup_io, OsOpen, stat_update_check
from ..archive import FilesystemObjectProcessors, MetadataCollector, ChunksProcessor
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import comment_validator, ChunkerParams, FilesystemPathSpec, CompressionSpec
from ..helpers import archivename_validator, FilesCacheMode, files_cache_mode_no_ctime
from ..helpers import octal_int, nonnegative_seconds
from ..helpers import read_input_map
from ..helpers import eval_escapes
from ..helpers import timestamp, archive_ts_now
from ..helpers import get_cache_dir, os_stat, get_strip_prefix, slashify
from ..helpers import BackupBrokenSymlinkError
from ..helpers import dir_is_tagged
from ..helpers import log_multi
from ..helpers import basic_json_data, json_print, FileSize
from ..helpers import flags_dir, flags_dir_follow, flags_special_follow, flags_special
from ..helpers import flags_normal, flags_normal_follow
from ..helpers import prepare_subprocess_env
from ..helpers import sig_int, ignore_sigint
from ..helpers import iter_separated
from ..helpers import MakePathSafeAction
from ..helpers import Error, CommandError, BackupWarning, FileChangedWarning
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest
from ..patterns import PatternMatcher
from ..platform import is_win32, get_flags

from ..logger import create_logger

logger = create_logger()


def stat_root(path):
    """
    stat a recursion root, following it if it is a symlink, see #4737.

    Returns (st, followed): for a symlink, st is the stat of what it points to and followed
    is True, so the caller knows that it must not use O_NOFOLLOW when opening path.

    Raises BackupBrokenSymlinkError if path is a symlink with a non-existing target.
    """
    st = os_stat(path=path, parent_fd=None, name=None, follow_symlinks=False)
    if not stat.S_ISLNK(st.st_mode):
        return st, False
    try:
        return os_stat(path=path, parent_fd=None, name=None, follow_symlinks=True), True
    except FileNotFoundError:
        raise BackupBrokenSymlinkError("stat", "broken symlink, skipping it") from None


class CreateMixIn:
    @with_repository(compatibility=(Manifest.Operation.WRITE,))
    def do_create(self, args, repository, manifest):
        """Creates a new archive."""
        if args.read_special_timeout is not None and not args.read_special:
            raise CommandError("--read-special-timeout requires --read-special.")
        read_special_timeout = args.read_special_timeout
        if read_special_timeout is None:
            read_special_timeout = READ_SPECIAL_TIMEOUT_DEFAULT
        if read_special_timeout == 0:
            read_special_timeout = None  # wait forever
        if args.reuse_from is not None and args.input_map is None:
            raise CommandError("--reuse-from requires --map.")
        if args.reuse_path is not None and args.reuse_from is None:
            raise CommandError("--reuse-path requires --reuse-from.")
        input_map = None
        if args.input_map is not None:
            # --map only makes sense for a single, seekable input file, see #4363.
            if args.paths_from_stdin or args.paths_from_command or args.paths_from_shell_command:
                raise CommandError("--map cannot be used with --paths-from-*.")
            if args.content_from_command:
                raise CommandError("--map cannot be used with --content-from-command.")
            if len(args.paths) != 1:
                raise CommandError("--map requires exactly one input path.")
            if args.paths[0] == "-":
                raise CommandError("--map cannot be used with stdin input.")
            try:
                st_map = os.stat(args.paths[0], follow_symlinks=True)
            except OSError as e:
                raise CommandError(f"--map input: {args.paths[0]}: {e}")
            if stat.S_ISBLK(st_map.st_mode):
                if not args.read_special:
                    raise CommandError("--map with a block device requires --read-special.")
            elif not stat.S_ISREG(st_map.st_mode):
                raise CommandError("--map input must be a regular file or a block device.")
            input_map = read_input_map(args.input_map, allow_same=args.reuse_from is not None)
        reuse_chunks = None
        if args.reuse_from is not None:
            ref_info = manifest.archives.get_one([args.reuse_from])
            ref_archive = Archive(manifest, ref_info.id)
            ref_items = [item for item in ref_archive.iter_items() if "chunks" in item]
            if args.reuse_path is not None:
                ref_items = [item for item in ref_items if item.path == args.reuse_path]
                if not ref_items:
                    raise CommandError(
                        f"--reuse-from: no file item with path {args.reuse_path!r} in reference archive."
                    )
            if len(ref_items) != 1:
                raise CommandError(
                    f"--reuse-from: reference archive has {len(ref_items)} file items, "
                    f"use --reuse-path to select the reference item."
                )
            reuse_chunks = ref_items[0].chunks
        if is_win32:
            # st_ctime is the file *creation* time on Windows, not the "metadata change time",
            # so a ctime based files cache mode would not detect content changes of a file that
            # keeps its size and inode number. Use the mtime based equivalent instead, see #7193.
            # note: this must happen before the Cache is created (it gets the files cache mode).
            files_cache_mode, changed = files_cache_mode_no_ctime(args.files_cache_mode)
            if changed:
                self.print_warning(
                    "--files-cache=ctime,... is not supported on Windows "
                    "(ctime is file creation time, not change time). Using mtime instead.",
                    wc=None,
                )
                args.files_cache_mode = files_cache_mode
        key = manifest.key
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
            if args.location.proto == "file":
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
                            env = prepare_subprocess_env(system=True)
                            proc = subprocess.Popen(  # nosec B603
                                args.paths,
                                stdout=subprocess.PIPE,
                                env=env,
                                preexec_fn=None if is_win32 else ignore_sigint,
                            )
                        except (FileNotFoundError, PermissionError) as e:
                            raise CommandError(f"Failed to execute command: {e}")
                        status = fso.process_pipe(
                            path=path, cache=cache, fd=proc.stdout, mode=mode, user=user, group=group
                        )
                        rc = proc.wait()
                        if rc != 0:
                            raise CommandError(f"Command {args.paths[0]!r} exited with status {rc}")
                    except BackupError as e:
                        raise Error(f"{path!r}: {e}")
                else:
                    status = "+"  # included
                    self.dry_run_stats.nfiles += 1  # size unknown without running the command
                self.print_file_status(status, path)
            elif args.paths_from_command or args.paths_from_shell_command or args.paths_from_stdin:
                paths_sep = eval_escapes(args.paths_delimiter) if args.paths_delimiter is not None else "\n"
                if args.paths_from_command or args.paths_from_shell_command:
                    try:
                        env = prepare_subprocess_env(system=True)
                        if args.paths_from_shell_command:
                            # Use shell=True to support pipes, redirection, etc.
                            shell = True
                            cmd = " ".join(args.paths)
                        else:
                            shell = False
                            cmd = args.paths
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            env=env,
                            shell=shell,  # nosec B602
                            preexec_fn=None if is_win32 else ignore_sigint,
                        )
                    except (FileNotFoundError, PermissionError) as e:
                        raise CommandError(f"Failed to execute command: {e}")
                    pipe_bin = proc.stdout
                else:  # args.paths_from_stdin == True
                    pipe_bin = sys.stdin.buffer
                pipe = TextIOWrapper(pipe_bin, errors="surrogateescape")
                for path in iter_separated(pipe, paths_sep):
                    path = slashify(path)
                    strip_prefix = get_strip_prefix(path)
                    path = posixpath.normpath(path)
                    try:
                        with backup_io("stat"):
                            # symlinks given this way are never followed, see #4737.
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
                            strip_prefix=strip_prefix,
                        )
                    except BackupError as e:
                        self.print_warning_instance(BackupWarning(path, e))
                        status = "E"
                    if status == "C":
                        self.print_warning_instance(FileChangedWarning(path))
                    self.print_file_status(status, path)
                    if not dry_run and status is not None:
                        fso.stats.files_stats[status] += 1
                if args.paths_from_command or args.paths_from_shell_command:
                    rc = proc.wait()
                    if rc != 0:
                        raise CommandError(f"Command {args.paths[0]!r} exited with status {rc}")
            else:
                paths = list(args.pattern_roots) + list(args.paths)
                for path in paths:
                    if path == "":  # issue #5637
                        self.print_warning("An empty string was given as PATH, ignoring.")
                        continue
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
                            except BackupError as e:
                                self.print_warning_instance(BackupWarning(path, e))
                                status = "E"
                        else:
                            status = "+"  # included
                            self.dry_run_stats.nfiles += 1  # size unknown without reading stdin
                        self.print_file_status(status, path)
                        if not dry_run and status is not None:
                            fso.stats.files_stats[status] += 1
                        continue

                    strip_prefix = get_strip_prefix(path)
                    path = posixpath.normpath(path)
                    try:
                        with backup_io("stat"):
                            st, followed = stat_root(path)
                        restrict_dev = st.st_dev if args.one_file_system else None
                        self._rec_walk(
                            path=path,
                            parent_fd=None,
                            name=None,
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
                            strip_prefix=strip_prefix,
                            follow_symlink=followed,
                        )
                        # if we get back here, we've finished recursing into <path>,
                        # we do not ever want to get back in there (even if path is given twice as recursion root)
                        skip_inodes.add((st.st_ino, st.st_dev))
                    except BackupError as e:
                        # this comes from os.stat, self._rec_walk has own exception handler
                        self.print_warning_instance(BackupWarning(path, e))
                        continue
            if not dry_run:
                if args.progress:
                    archive.stats.show_progress(final=True)
                archive.stats += fso.stats
                if sig_int:
                    # do not save the archive if the user ctrl-c-ed.
                    raise Error("Got Ctrl-C / SIGINT.")
                else:
                    archive.tags = set(args.tags or [])
                    archive.save(comment=args.comment, timestamp=args.timestamp)

        self.output_filter = args.output_filter
        self.output_list = args.output_list
        self.noflags = args.noflags
        self.noacls = args.noacls
        self.noxattrs = args.noxattrs
        self.exclude_dataless = args.exclude_dataless
        dry_run = args.dry_run
        self.dry_run_stats = Statistics() if dry_run else None
        self.start_backup = time.time_ns()
        t0 = archive_ts_now()
        logger.info('Creating archive "%s" in repository %s' % (args.name, args.location.processed))
        if not dry_run:
            with Cache(
                repository, manifest, progress=args.progress, cache_mode=args.files_cache_mode, archive_name=args.name
            ) as cache:
                archive = Archive(
                    manifest,
                    args.name,
                    cache=cache,
                    create=True,
                    numeric_ids=args.numeric_ids,
                    noatime=not args.atime,
                    noctime=args.noctime,
                    progress=args.progress,
                    chunker_params=args.chunker_params,
                    start=t0,
                    log_json=args.log_json,
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
                cp = ChunksProcessor(cache=cache, key=key, add_item=archive.add_item, rechunkify=False)
                if is_win32 and args.files_changed == "ctime":
                    self.print_warning(
                        "--files-changed=ctime is not supported on Windows "
                        "(ctime is file creation time, not change time). Using mtime instead.",
                        wc=None,
                    )
                    args.files_changed = "mtime"
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
                    file_status_printer=self.print_file_status,
                    files_changed=args.files_changed,
                    read_special_timeout=read_special_timeout,
                    input_map=input_map,
                    reuse_chunks=reuse_chunks,
                )
                create_inner(archive, cache, fso)
            args.stats |= args.json
            if args.stats:
                # Cache.close() writes the chunks index to the repo; sample after it so that traffic is counted.
                archive.stats.store_stats = repository.store.stats
                if args.json:
                    json_print(basic_json_data(manifest, cache=cache, extra={"archive": archive}))
                else:
                    log_multi(str(archive), str(archive.stats), logger=logging.getLogger("borg.output.stats"))
        else:
            create_inner(None, None, None)
            args.stats |= args.json
            if args.stats:
                stats = self.dry_run_stats
                if args.json:
                    json_data = basic_json_data(
                        manifest,
                        extra={
                            "dry_run": True,
                            "stats": {"nfiles": stats.nfiles, "original_size": FileSize(stats.osize)},
                        },
                    )
                    json_print(json_data)
                else:
                    log_multi(
                        f"Number of files: {stats.nfiles}",
                        f"Original size: {stats.osize_fmt}",
                        logger=logging.getLogger("borg.output.stats"),
                    )

    def _process_any(
        self, *, path, parent_fd, name, st, fso, cache, read_special, dry_run, strip_prefix, followed_symlink=False
    ):
        """
        Call the right method on the given FilesystemObjectProcessor.

        If followed_symlink is True, *path* is a symlink we followed (recursion root, see #4737)
        and *st* is the stat of its target, so we must not use O_NOFOLLOW when opening it.
        """

        if dry_run:
            stats = self.dry_run_stats
            if stat.S_ISREG(st.st_mode):
                stats.nfiles += 1
                stats.osize += st.st_size
            elif read_special:
                if stat.S_ISLNK(st.st_mode):
                    try:
                        st_target = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=True)
                    except OSError:
                        special = False
                    else:
                        special = is_special(st_target.st_mode)
                else:
                    special = is_special(st.st_mode)
                if special:
                    stats.nfiles += 1  # size unknown without reading the special file
            return "+"  # included
        MAX_RETRIES = 10  # count includes the initial try (initial try == "retry 0")
        # if we followed a symlink, we must not refuse to open its target via the symlink:
        flags_file = flags_normal_follow if followed_symlink else flags_normal
        flags_specialfile = flags_special_follow if followed_symlink else flags_special
        for retry in range(MAX_RETRIES):
            last_try = retry == MAX_RETRIES - 1
            try:
                if stat.S_ISREG(st.st_mode):
                    return fso.process_file(
                        path=path,
                        parent_fd=parent_fd,
                        name=name,
                        st=st,
                        cache=cache,
                        flags=flags_file,
                        last_try=last_try,
                        strip_prefix=strip_prefix,
                    )
                elif stat.S_ISDIR(st.st_mode):
                    # note: a followed symlink to a directory does not get here, _rec_walk deals with it.
                    return fso.process_dir(path=path, parent_fd=parent_fd, name=name, st=st, strip_prefix=strip_prefix)
                elif stat.S_ISLNK(st.st_mode):
                    if not read_special:
                        return fso.process_symlink(
                            path=path, parent_fd=parent_fd, name=name, st=st, strip_prefix=strip_prefix
                        )
                    else:
                        try:
                            st_target = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=True)
                        except OSError:
                            special = False
                        else:
                            special = is_special(st_target.st_mode)
                        if special:
                            return fso.process_file(
                                path=path,
                                parent_fd=parent_fd,
                                name=name,
                                st=st_target,
                                cache=cache,
                                flags=flags_special_follow,
                                last_try=last_try,
                                strip_prefix=strip_prefix,
                            )
                        else:
                            return fso.process_symlink(
                                path=path, parent_fd=parent_fd, name=name, st=st, strip_prefix=strip_prefix
                            )
                elif stat.S_ISFIFO(st.st_mode):
                    if not read_special:
                        return fso.process_fifo(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            strip_prefix=strip_prefix,
                            flags=flags_file,
                        )
                    else:
                        return fso.process_file(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            cache=cache,
                            flags=flags_specialfile,
                            last_try=last_try,
                            strip_prefix=strip_prefix,
                        )
                elif stat.S_ISCHR(st.st_mode):
                    if not read_special:
                        return fso.process_dev(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            dev_type="c",
                            strip_prefix=strip_prefix,
                            follow_symlinks=followed_symlink,
                        )
                    else:
                        return fso.process_file(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            cache=cache,
                            flags=flags_specialfile,
                            last_try=last_try,
                            strip_prefix=strip_prefix,
                        )
                elif stat.S_ISBLK(st.st_mode):
                    if not read_special:
                        return fso.process_dev(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            dev_type="b",
                            strip_prefix=strip_prefix,
                            follow_symlinks=followed_symlink,
                        )
                    else:
                        return fso.process_file(
                            path=path,
                            parent_fd=parent_fd,
                            name=name,
                            st=st,
                            cache=cache,
                            flags=flags_specialfile,
                            last_try=last_try,
                            strip_prefix=strip_prefix,
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
            except BackupItemExcluded:
                return "-"
            except BackupError as err:
                if isinstance(err, BackupOSError):
                    if err.errno in (errno.EPERM, errno.EACCES, errno.ETIMEDOUT):
                        # Do not try again: permission errors can not be fixed by retrying
                        # and a --read-special-timeout would just expire again (10 more times).
                        raise
                if last_try:
                    # giving up with retries, error will be dealt with (logged) by upper error handler
                    raise
                # sleep a bit, so temporary problems might go away...
                sleep_s = 1000.0 / 1e6 * 10 ** (retry / 2)  # retry 0: 1ms, retry 6: 1s, ...
                time.sleep(sleep_s)
                logger.warning(f"{path}: {err}, slept {sleep_s:.3f}s, next: retry: {retry + 1} of {MAX_RETRIES - 1}...")
                # we better do a fresh stat on the file, just to make sure to get the current file
                # mode right (which could have changed due to a race condition and is important for
                # dispatching) and also to get current inode number of that file.
                with backup_io("stat"):
                    st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=followed_symlink)

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
        strip_prefix,
        follow_symlink=False,
    ):
        """
        Process *path* (or, preferably, parent_fd/name) recursively according to the various parameters.

        follow_symlink is only given for a recursion root that is a symlink, see #4737: we then
        archive what the symlink points to (using the symlink's path). Symlinks encountered while
        recursing are never followed, so this is never passed on to the recursive calls.

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
                    st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=follow_symlink)
            else:
                self.print_file_status("-", path)  # excluded
                # get out here as quickly as possible:
                # we only need to continue if we shall recurse into an excluded directory.
                # if we shall not recurse, then do not even touch (stat()) the item, it
                # could trigger an error, e.g. if access is forbidden, see #3209.
                if not matcher.recurse_dir:
                    return
                recurse_excluded_dir = True
                with backup_io("stat"):
                    st = os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=follow_symlink)
                if not stat.S_ISDIR(st.st_mode):
                    return

            if (st.st_ino, st.st_dev) in skip_inodes:
                return
            # if restrict_dev is given, we do not want to recurse into a new filesystem,
            # but we WILL save the mountpoint directory (or more precise: the root
            # directory of the mounted filesystem that shadows the mountpoint dir).
            recurse = restrict_dev is None or st.st_dev == restrict_dev

            if self.exclude_dataless:
                # this needs to be done BEFORE opening the file, as opening
                # would otherwise materialize the file contents.
                with backup_io("flags"):
                    flags = get_flags(path=path, st=st)
                if flags & SF_DATALESS:
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
                    strip_prefix=strip_prefix,
                    followed_symlink=follow_symlink,
                )
            else:
                with OsOpen(
                    path=path,
                    parent_fd=parent_fd,
                    name=name,
                    flags=flags_dir_follow if follow_symlink else flags_dir,
                    noatime=True,
                    op="dir_open",
                ) as child_fd:
                    # child_fd is None for directories on windows, in that case a race condition check is not possible.
                    if child_fd is not None:
                        with backup_io("fstat"):
                            st = stat_update_check(st, os.fstat(child_fd))
                    if recurse:
                        tag_names = dir_is_tagged(path, exclude_caches, exclude_if_present, dir_fd=child_fd)
                        if tag_names:
                            # if we are already recursing in an excluded dir, we do not need to do anything else than
                            # returning (we do not need to archive or recurse into tagged directories), see #3991:
                            if not recurse_excluded_dir:
                                if keep_exclude_tags:
                                    if not dry_run:
                                        fso.process_dir_with_fd(
                                            path=path, fd=child_fd, st=st, strip_prefix=strip_prefix
                                        )
                                    for tag_name in tag_names:
                                        tag_path = posixpath.join(path, tag_name)
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
                                            strip_prefix=strip_prefix,
                                        )
                                self.print_file_status("-", path)  # excluded
                            return
                    if not recurse_excluded_dir:
                        if not dry_run:
                            try:
                                status = fso.process_dir_with_fd(
                                    path=path, fd=child_fd, st=st, strip_prefix=strip_prefix
                                )
                            except BackupItemExcluded:
                                status = "-"  # excluded (dir)
                                recurse = False
                        else:
                            status = "+"  # included (dir)
                    if recurse:
                        with backup_io("scandir"):
                            entries = helpers.scandir_inorder(path=path, fd=child_fd)
                        for dirent in entries:
                            normpath = posixpath.normpath(posixpath.join(path, dirent.name))
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
                                strip_prefix=strip_prefix,
                            )

        except BackupError as e:
            self.print_warning_instance(BackupWarning(path, e))
            status = "E"
        if status == "C":
            self.print_warning_instance(FileChangedWarning(path))
        if not recurse_excluded_dir:
            self.print_file_status(status, path)
            if not dry_run and status is not None:
                fso.stats.files_stats[status] += 1

    def build_parser_create(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group

        create_epilog = process_epilog(
            """
        This command creates a backup archive containing all files found while recursively
        traversing all specified paths. Paths are added to the archive as they are given,
        which means that if relative paths are desired, the command must be run from the correct
        directory.

        The slashdot hack in paths (recursion roots) is triggered by using ``/./``:
        ``/this/gets/stripped/./this/gets/archived`` means to process that fs object, but
        strip the prefix on the left side of ``./`` from the archived items (in this case,
        ``this/gets/archived`` will be the path in the archived item).

        If a recursion root (a path given on the command line or in a patterns file) is a
        symlink, borg follows it and archives what it points to - using the path you gave.
        If ``current`` is a symlink pointing to the directory ``20260801-2345``,
        ``borg create ARCHIVE current`` thus archives ``current`` as a directory (with the
        metadata of ``20260801-2345``) and recurses into it, archiving the contained fs
        objects as ``current/...``. As the archived paths do not change when the symlink
        target changes, the files cache keeps working for such backups.

        Note that the symlink itself is then not in the archive (and neither is its target
        path), so restoring will create a real directory (or file) where the symlink was.
        If you want the symlink archived as a symlink, do not give it as a recursion root,
        but let borg find it while recursing (symlinks found that way are never followed).
        A recursion root that is a symlink with a non-existing target is skipped with a warning.

        If you give both a symlink and its target as recursion roots, borg archives the fs
        objects only once, under the path given first (like for any other root given twice).

        When specifying '-' as a path, borg will read data from standard input and create a
        file named 'stdin' in the created archive from that data. In some cases, it is more
        appropriate to use --content-from-command. See the section *Reading from stdin*
        below for details.

        The archive will consume almost no disk space for files or parts of files that
        have already been stored in other archives.

        The ``--tags`` option can be used to add a list of tags to the new archive.

        The archive name does not need to be unique; you can and should use the same
        name for a series of archives. The unique archive identifier is its ID (hash),
        and you can abbreviate the ID as long as it is unique.

        In the archive name, you may use the following placeholders:
        {now}, {utcnow}, {fqdn}, {hostname}, {user} and some others.

        Backup speed is increased by not reprocessing files that are already part of
        existing archives and were not modified. The detection of unmodified files is
        done by comparing multiple file metadata values with previous values kept in
        the files cache.

        This comparison can operate in different modes as given by ``--files-cache``:

        - ctime,size,inode (default on POSIX systems)
        - mtime,size,inode (default on Windows)
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
          as it cannot be set from userspace. But a metadata-only change will already
          update the ctime, so there might be some unnecessary chunking/hashing even
          without content changes. Some filesystems do not support ctime (change time).
          E.g. doing a chown or chmod to a file will change its ctime.
        - mtime usually works and only updates if file contents were changed. But mtime
          can be arbitrarily set from userspace, e.g., to set mtime back to the same value
          it had before a content change happened. This can be used maliciously as well as
          well-meant, but in both cases mtime-based cache modes can be problematic.

        On Windows, ctime is the file *creation* time, not the "metadata change time" it is
        on POSIX systems. A ctime based mode would therefore not notice content changes of a
        file that keeps its size and inode number, so borg defaults to ``mtime,size,inode``
        there. If a ctime based mode is given explicitly on Windows, borg warns and uses the
        corresponding mtime based mode instead: ctime,size,inode -> mtime,size,inode,
        ctime,size -> mtime,size, rechunk,ctime -> rechunk,mtime.

        The ``--files-changed`` option controls how Borg detects if a file has changed during backup:
         - ctime (default on POSIX): Use ctime to detect changes. This is the safest option.
           Not supported on Windows (ctime is file creation time there).
         - mtime (default on Windows): Use mtime to detect changes.
         - disabled: Disable the "file has changed while we backed it up" detection completely.
           This is not recommended unless you know what you're doing, as it could lead to
           inconsistent backups if files change during the backup process.

        The mount points of filesystems or filesystem snapshots should be the same for every
        creation of a new archive to ensure fast operation. This is because the file cache that
        is used to determine changed files quickly uses absolute filenames.
        If this is not possible, consider creating a bind mount to a stable location.

        The ``--progress`` option shows (from left to right) Original and (uncompressed)
        deduplicated size (O and U respectively), then the Number of files (N) processed so far,
        followed by the currently processed path.

        Sizes of GB and above are shown with enough decimal places that even MB-sized progress
        stays visible. On a terminal, this needs a width of at least 110 columns - on narrower
        terminals, the compact format is used, so that the path stays readable. If the output
        does not go to a terminal (e.g. into a logfile), the precise format is always used.

        When using ``--stats``, you will get some statistics about how much data was
        added - the "This Archive" deduplicated size there is most interesting as that is
        how much your repository will grow. Please note that the "All archives" stats refer to
        the state after creation.

        When ``--stats`` is used together with ``--dry-run``, only the number of files and the
        original size are reported. They are computed from file system metadata, without reading
        the file contents, so a dry run stays fast. As data is not actually read, chunked, and
        deduplicated during a dry run, the deduplicated size is unknown. The sizes of data read
        from standard input, from a command's output, or from special files (``--read-special``)
        are also unknown in a dry run and counted as zero.

        The ``--stats`` output also reports the store statistics (lines prefixed with
        "Store"), taken from the storage layer after this run. These cover the backend and
        the local store cache: call counts and timings per operation, the load/store data
        volumes and throughput, and cache hits/misses. "Store backend load volume" and
        "Store backend store volume" are the bytes actually read from and sent to the
        backend; a load counts only what missed the cache, and a store counts chunk data
        together with Borg's own index and metadata writes. The values are approximate
        because of write buffering and caching. On a repeated backup a near-zero store
        volume means almost no new data had to be written, because the chunks already exist
        in the repository (deduplication).

        The "Added", "Modified" and "Unchanged" file counters come from the files-cache
        comparison described above: "Unchanged" files matched the cached metadata and were
        not read again (their existing chunks are reused); "Added" and "Modified" files did
        not match and were read and chunked (new chunks are stored, already-known chunks are
        deduplicated). The comparison uses the files cache, keyed by the file's absolute path.

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
        from the device number of their parent.
        In general: be aware that there are directories with device number different from their parent, which the kernel
        does not consider a mountpoint and also the other way around.
        Linux examples for this are bind mounts (possibly same device number, but always a mountpoint) and ALL
        subvolumes of a btrfs (different device number from parent but not necessarily a mountpoint).
        macOS examples are the apfs mounts of a typical macOS installation.
        Therefore, when using ``--one-file-system``, you should double-check that the backup works as intended.

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
        - 'h' = regular file, hard link (to already seen inodes)
        - 's' = symlink
        - 'f' = fifo

        Other flags used include:

        - '+' = included, item would be backed up (if not in dry-run mode)
        - '-' = excluded, item would not be / was not backed up
        - 'i' = backup data was read from standard input (stdin)
        - '?' = missing status code (if you see this, please file a bug report!)

        Errors and (incomplete) archives
        ++++++++++++++++++++++++++++++++

        If an error happens during archive creation (e.g. some file could not be read
        due to a permission error or some other OS error), borg will log a warning or
        an error (depending on the type of issue) and continue with the next item.

        At the end of the backup, if there were any such issues, borg will exit with
        a non-zero exit code (usually 1 for warnings).

        **The archive is still saved even if warnings or errors occurred**, but it will
        only contain the data borg was able to read successfully. It is like a
        checkpoint (see below), but with a user-given name.

        You should always check the backup logs and the exit code of the borg command.

        Reading backup data from stdin
        ++++++++++++++++++++++++++++++

        There are two methods to read from stdin. Either specify ``-`` as path and
        pipe directly to borg::

            backup-vm --id myvm --stdout | borg create --repo REPO ARCHIVE -

        Or use ``--content-from-command`` to have Borg manage the execution of the
        command and piping. If you do so, the first PATH argument is interpreted
        as command to execute and any further arguments are treated as arguments
        to the command::

            borg create --content-from-command --repo REPO ARCHIVE -- backup-vm --id myvm --stdout

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

        Input maps
        ++++++++++

        Usually, borg reads the complete input to determine its contents. If you already
        know the contents of parts of the input from an external source of truth, you can
        give that information via ``--map MAPFILE`` and borg will not read the known parts.
        The primary use case is backing up snapshots of large block devices (e.g. LVM thin
        volumes), where the storage layer knows which ranges are in use.

        ``--map`` requires giving exactly one input path, which must be a regular file or
        (with ``--read-special``) a block device.

        The map file must describe the whole input: one range per line, in the form
        ``START LENGTH STATE`` (byte values, decimal or 0x-prefixed hexadecimal). The
        ranges must be sorted, non-overlapping and contiguous, starting at offset 0 and
        covering the exact input size. ``#`` starts a comment, empty lines are ignored.
        STATE is one of:

        - ``data``: the range's contents are read and backed up.
        - ``zero``: the range is known to read as all-zero bytes. borg stores a hole
          (all-zero range) of that size without reading the range.
        - ``same``: the range is known to be identical to the same range of the input
          backed up in the ``--reuse-from REFARCHIVE`` reference archive (usually: the
          previous backup of an earlier snapshot of the same device). borg reuses the
          reference archive's chunks for such ranges without reading them. This state
          requires ``--reuse-from``.

        The reference archive must contain exactly one file item; if it contains more,
        select the reference item with ``--reuse-path PATH`` (its archive-internal path).
        Reference chunks that only partially overlap ``same`` ranges are re-read from
        the input, so any chunker gives correct results - but a fixed block size chunker
        (e.g. ``--chunker-params fixed,4194304``, same parameters as used for the
        reference archive) avoids re-reading at the edges of changed ranges and gives
        stable chunk boundaries across backups.

        **The map is trusted**: if it is wrong (e.g. a range marked ``zero`` actually
        contains data, or a range marked ``same`` actually changed), the archive will
        not match the input and borg cannot detect that. Independently verify the
        source producing the maps, and consider doing a periodic full read backup
        (without ``--map``).

        For LVM thin volume snapshots, maps can be generated from ``thin_dump`` /
        ``thin_delta`` XML with the ``scripts/lvm-thin-map.py`` converter from the
        borg sources; its docstring shows the complete workflow.

        Feeding all file paths from externally
        ++++++++++++++++++++++++++++++++++++++

        Usually, you give a starting path (recursion root) to borg and then borg
        automatically recurses, finds and backs up all fs objects contained in
        there (optionally considering include/exclude rules).

        If you need more control and you want to give every single fs object path
        to borg (maybe implementing your own recursion or your own rules), you can use
        ``--paths-from-stdin``, ``--paths-from-command`` or ``--paths-from-shell-command``
        (with the latter two, borg will fail to create an archive should the command fail).

        Borg supports paths with the slashdot hack to strip path prefixes here also.
        So, be careful not to unintentionally trigger that.

        Symlinks given this way are never followed (unlike recursion roots are), they are
        archived as symlinks.
        """
        )

        subparser = ArgumentParser(parents=[common_parser], description=self.do_create.__doc__, epilog=create_epilog)
        subparsers.add_subcommand("create", subparser, help="create a backup")

        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not create a backup archive"
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics for the created archive"
        )

        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output a verbose list of items (files, dirs, ...)"
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
            "--stdin-name",
            metavar="NAME",
            dest="stdin_name",
            default="stdin",
            action=MakePathSafeAction,
            help="use NAME in archive for stdin data (default: %(default)r)",
        )
        subparser.add_argument(
            "--stdin-user",
            metavar="USER",
            dest="stdin_user",
            default=None,
            action=Highlander,
            help="set user USER in archive for stdin data (default: do not store user/uid)",
        )
        subparser.add_argument(
            "--stdin-group",
            metavar="GROUP",
            dest="stdin_group",
            default=None,
            action=Highlander,
            help="set group GROUP in archive for stdin data (default: do not store group/gid)",
        )
        subparser.add_argument(
            "--stdin-mode",
            metavar="M",
            dest="stdin_mode",
            type=octal_int,
            default=STDIN_MODE_DEFAULT,
            action=Highlander,
            help="set mode to M in archive for stdin data (default: %(default)04o)",
        )
        subparser.add_argument(
            "--content-from-command",
            action="store_true",
            help="interpret PATH as a command and store its stdout. See also the section 'Reading from stdin' below.",
        )
        subparser.add_argument(
            "--paths-from-stdin",
            action="store_true",
            help="read DELIM-separated list of paths to back up from stdin. All control is external: it will back"
            " up all files given - no more, no less.",
        )
        subparser.add_argument(
            "--paths-from-command",
            action="store_true",
            help="interpret PATH as command and treat its output as ``--paths-from-stdin``",
        )
        subparser.add_argument(
            "--paths-from-shell-command",
            action="store_true",
            help="interpret PATH as shell command and treat its output as ``--paths-from-stdin``",
        )
        subparser.add_argument(
            "--paths-delimiter",
            action=Highlander,
            metavar="DELIM",
            help="set path delimiter for ``--paths-from-stdin`` and ``--paths-from-command`` (default: ``\\n``) ",
        )

        exclude_group = define_exclusion_group(subparser, tag_files=True)
        exclude_group.add_argument(
            "--exclude-dataless",
            dest="exclude_dataless",
            action="store_true",
            help="exclude files flagged DATALESS (macOS: placeholder files whose content "
            "is not materialized locally, e.g. not-downloaded cloud storage files)",
        )

        fs_group = subparser.add_argument_group("Filesystem options")
        fs_group.add_argument(
            "-x",
            "--one-file-system",
            dest="one_file_system",
            action="store_true",
            help="stay in the same file system and do not store mount points of other file systems - "
            "this might behave different from your expectations, see the description below.",
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
            help="detect sparse holes in input and seek over them instead of reading them",
        )
        fs_group.add_argument(
            "--files-cache",
            metavar="MODE",
            dest="files_cache_mode",
            action=Highlander,
            type=FilesCacheMode,
            default=FILES_CACHE_MODE_UI_DEFAULT_WIN32 if is_win32 else FILES_CACHE_MODE_UI_DEFAULT_POSIX,
            help="operate files cache in MODE. default: %s (on Windows: %s, because ctime is "
            "file creation time there)." % (FILES_CACHE_MODE_UI_DEFAULT_POSIX, FILES_CACHE_MODE_UI_DEFAULT_WIN32),
        )
        fs_group.add_argument(
            "--files-changed",
            metavar="MODE",
            dest="files_changed",
            action=Highlander,
            choices=["ctime", "mtime", "disabled"],
            default="mtime" if is_win32 else "ctime",
            help="specify how to detect if a file has changed during backup (ctime, mtime, disabled). "
            "default: ctime (on Windows: mtime, because ctime is file creation time there).",
        )
        fs_group.add_argument(
            "--read-special",
            dest="read_special",
            action="store_true",
            help="open and read block and char device files as well as FIFOs as if they were "
            "regular files. Also follows symlinks pointing to these kinds of files.",
        )
        fs_group.add_argument(
            "--read-special-timeout",
            metavar="SECONDS",
            dest="read_special_timeout",
            type=nonnegative_seconds,
            default=None,
            action=Highlander,
            help="when reading from FIFOs or character devices (see --read-special): skip the "
            "file with an error if no data arrives for more than SECONDS (this includes waiting "
            "for a FIFO's writer to connect). Give 0 to wait forever. default: %d seconds."
            % READ_SPECIAL_TIMEOUT_DEFAULT,
        )
        fs_group.add_argument(
            "--map",
            metavar="MAPFILE",
            dest="input_map",
            action=Highlander,
            help="give a map file describing the content ranges of the (single) input file, "
            "so borg does not need to read all of it. See the *Input maps* section below.",
        )
        fs_group.add_argument(
            "--reuse-from",
            metavar="ARCHIVE",
            dest="reuse_from",
            action=Highlander,
            help="reuse the chunks of this reference archive for the input map's ``same`` "
            "ranges (requires --map). See the *Input maps* section below.",
        )
        fs_group.add_argument(
            "--reuse-path",
            metavar="PATH",
            dest="reuse_path",
            action=Highlander,
            help="archive-internal path of the reference item in the --reuse-from archive "
            "(only needed if that archive contains more than one file item).",
        )

        archive_group = subparser.add_argument_group("Archive options")
        archive_group.add_argument(
            "--comment",
            metavar="COMMENT",
            dest="comment",
            type=comment_validator,
            default="",
            action=Highlander,
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            metavar="TIMESTAMP",
            dest="timestamp",
            type=timestamp,
            default=None,
            action=Highlander,
            help="manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, "
            "(+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "--chunker-params",
            metavar="PARAMS",
            dest="chunker_params",
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            action=Highlander,
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, NC_LEVEL). default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        archive_group.add_argument(
            "--tags",
            metavar="TAG",
            dest="tags",
            type=helpers.tag_validator,
            nargs="+",
            help="add tags to archive (comma-separated or multiple arguments)",
        )

        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=FilesystemPathSpec, action="extend", help="paths to archive"
        )
