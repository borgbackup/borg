import sys
import argparse
import logging
import os
import stat
import subprocess
import time
from datetime import datetime
from io import TextIOWrapper

from .common import with_repository, Highlander
from .. import helpers
from ..archive import Archive, is_special
from ..archive import BackupError, BackupOSError, backup_io, OsOpen, stat_update_check
from ..archive import FilesystemObjectProcessors, MetadataCollector, ChunksProcessor
from ..cache import Cache
from ..constants import *  # NOQA
from ..compress import CompressionSpec
from ..helpers import ChunkerParams
from ..helpers import NameSpec, CommentSpec, FilesCacheMode
from ..helpers import eval_escapes
from ..helpers import timestamp
from ..helpers import get_cache_dir, os_stat
from ..helpers import Manifest
from ..helpers import dir_is_tagged
from ..helpers import log_multi
from ..helpers import basic_json_data, json_print
from ..helpers import flags_root, flags_dir, flags_special_follow, flags_special
from ..helpers import sig_int, ignore_sigint
from ..helpers import iter_separated
from ..patterns import PatternMatcher
from ..platform import get_flags
from ..platform import uid2user, gid2group

from ..logger import create_logger

logger = create_logger()


class CreateMixIn:
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
                            proc = subprocess.Popen(args.paths, stdout=subprocess.PIPE, preexec_fn=ignore_sigint)
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
                        proc = subprocess.Popen(args.paths, stdout=subprocess.PIPE, preexec_fn=ignore_sigint)
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

    def build_parser_create(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog
        from .common import define_exclusion_group

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
