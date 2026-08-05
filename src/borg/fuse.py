"""
``borg mount`` using llfuse / pyfuse3, the low-level (inode based) FUSE 2 / FUSE 3 API.

This is a protocol adapter only: what an archive looks like as a file system is
defined in vfs.py, here we just translate between that and the llfuse operations
interface (inode numbers and EntryAttributes in, FUSEErrors out).

IMPORTANT
=========

This code is only safe for single-threaded and synchronous (non-async) usage.

- llfuse is synchronous and used with workers=1, so there is only 1 thread,
  and we are safe.
- pyfuse3 uses Trio, which only uses 1 thread, but could use this code in an
  asynchronous manner. However, as long as we do not use any asynchronous
  operations (like using "await") in this code, it is still de facto
  synchronous, and we are safe.

The only exception is a background thread that periodically refreshes the
repository lock while the mount is idle (see #9872). borgstore connections are
not thread-safe, so all repository access from the FUSE handlers and the refresh
thread is serialized via self._repo_lock.
"""

import errno
import functools
import os
import threading
from signal import SIGINT
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # For type checking, assume llfuse is available
    # This allows mypy to understand llfuse.Operations
    import llfuse
    from .fuse_impl import has_pyfuse3, ENOATTR
else:
    from .fuse_impl import llfuse, has_pyfuse3, ENOATTR

if has_pyfuse3:
    import trio

    def async_wrapper(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        return wrapper

else:
    trio = None

    def async_wrapper(fn):
        return fn


from .logger import create_logger

logger = create_logger()

from .helpers import daemonizing, signal_handler
from .storelocking import LockRefresher
from .vfs import ArchiveVFS, ChunkMissing, parse_mount_options

BLOCK_SIZE = 512  # Standard filesystem block size for st_blocks and statfs


def fuse_main():
    if has_pyfuse3:
        try:
            trio.run(llfuse.main)
        except KeyboardInterrupt:
            return SIGINT
        except:  # noqa
            return -1  # avoid colliding with signal numbers
        else:
            return None
    else:
        return llfuse.main(workers=1)


class FuseOperations(llfuse.Operations):
    """Export archive contents as a FUSE filesystem"""

    def __init__(self, manifest, args, repository):
        llfuse.Operations.__init__(self)
        self._manifest = manifest
        self._args = args
        self._repository = repository
        # serializes all repository access (FUSE handlers and the background lock-refresh
        # thread), because borgstore connections are not thread-safe.
        self._repo_lock = threading.RLock()
        self.vfs = None  # created by mount(), once the mount options are known

    def mount(self, mountpoint, mount_options, foreground=False, show_rc=False):
        """Mount filesystem on *mountpoint* with *mount_options*."""
        options, vfs_options = parse_mount_options(self._args, mountpoint, mount_options)
        self.vfs = ArchiveVFS(self._manifest, self._args, self._repository, lock=self._repo_lock, options=vfs_options)
        self.vfs.create_filesystem()
        llfuse.init(self, mountpoint, options)
        if not foreground:
            with daemonizing(show_rc=show_rc) as (old_id, new_id):
                # the locking process' PID is changing, migrate it:
                logger.debug("fuse: mount repo, going to background: migrating lock.")
                self._repository.migrate_lock(old_id, new_id)

        # If the file system crashes, we do not want to umount because in that
        # case the mountpoint suddenly appears to become empty. This can have
        # nasty consequences, imagine the user has e.g. an active rsync mirror
        # job - seeing the mountpoint empty, rsync would delete everything in the
        # mirror.
        umount = False
        # keep the repository lock of an idle mount alive, so it is not killed as stale (see #9872).
        # started here (after a possible daemonizing fork, as threads do not survive fork()).
        lock_refreshing_thread = LockRefresher(self._repository.info, sleep_interval=60, lock=self._repo_lock)
        lock_refreshing_thread.start()
        try:
            with signal_handler("SIGUSR1", self.sig_info_handler), signal_handler("SIGINFO", self.sig_info_handler):
                signal = fuse_main()
            # no crash and no signal (or it's ^C and we're in the foreground) -> umount request
            umount = signal is None or (signal == SIGINT and foreground)
        finally:
            lock_refreshing_thread.terminate()
            llfuse.close(umount)

    def sig_info_handler(self, sig_no, stack):
        self.vfs.log_stats()

    # -- helpers ---------------------------------------------------------------

    def _getattr(self, inode, ctx=None):
        attrs = self.vfs.attrs(inode)
        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = attrs.mode
        entry.st_nlink = attrs.nlink
        entry.st_uid = attrs.uid
        entry.st_gid = attrs.gid
        entry.st_rdev = attrs.rdev
        entry.st_size = attrs.size
        entry.st_blksize = BLOCK_SIZE
        entry.st_blocks = (entry.st_size + entry.st_blksize - 1) // entry.st_blksize
        entry.st_mtime_ns = attrs.mtime_ns
        entry.st_atime_ns = attrs.atime_ns
        entry.st_ctime_ns = attrs.ctime_ns
        entry.st_birthtime_ns = attrs.birthtime_ns
        return entry

    def _dir_node(self, inode):
        try:
            return self.vfs.get_node(inode)
        except KeyError:
            raise llfuse.FUSEError(errno.ENOTDIR) from None

    # -- filesystem operations -------------------------------------------------

    @async_wrapper
    def statfs(self, ctx=None):
        stat_ = llfuse.StatvfsData()
        stat_.f_bsize = BLOCK_SIZE  # Filesystem block size
        stat_.f_frsize = BLOCK_SIZE  # Fragment size
        stat_.f_blocks = 0  # Size of fs in f_frsize units
        stat_.f_bfree = 0  # Number of free blocks
        stat_.f_bavail = 0  # Number of free blocks for unprivileged users
        stat_.f_files = 0  # Number of inodes
        stat_.f_ffree = 0  # Number of free inodes
        stat_.f_favail = 0  # Number of free inodes for unprivileged users
        stat_.f_namemax = 255  # == NAME_MAX (depends on archive source OS / FS)
        return stat_

    @async_wrapper
    def getattr(self, inode, ctx=None):
        return self._getattr(inode, ctx=ctx)

    @async_wrapper
    def listxattr(self, inode, ctx=None):
        return self.vfs.listxattr(inode)

    @async_wrapper
    def getxattr(self, inode, name, ctx=None):
        try:
            return self.vfs.getxattr(inode, name)
        except KeyError:
            raise llfuse.FUSEError(ENOATTR) from None
        except ValueError:
            logger.warning("mount: could not convert ACL of inode %d to the xattr representation", inode)
            raise llfuse.FUSEError(errno.EIO) from None

    @async_wrapper
    def lookup(self, parent_inode, name, ctx=None):
        node = self._dir_node(parent_inode)
        if name == b".":
            inode = parent_inode
        elif name == b"..":
            inode = node.parent.ino if node.parent is not None else parent_inode
        else:
            try:
                _, child = self.vfs.lookup(node, os.fsdecode(name))
            except KeyError:
                raise llfuse.FUSEError(errno.ENOENT) from None
            inode = child.ino
        return self._getattr(inode)

    @async_wrapper
    def open(self, inode, flags, ctx=None):
        return llfuse.FileInfo(fh=inode) if has_pyfuse3 else inode

    @async_wrapper
    def opendir(self, inode, ctx=None):
        self.vfs.ensure_loaded(self._dir_node(inode))
        return inode

    @async_wrapper
    def read(self, fh, offset, size):
        try:
            return self.vfs.read(fh, offset, size, pos_key=fh)
        except ChunkMissing:
            raise llfuse.FUSEError(errno.EIO) from None

    def _readdir_entries(self, fh):
        node = self._dir_node(fh)
        parent = node.parent if node.parent is not None else node
        entries = [(b".", node.ino), (b"..", parent.ino)]
        entries.extend((os.fsencode(name), child.ino) for name, child in self.vfs.children(node))
        return entries

    # note: we can't have a generator (with yield) and not a generator (async) in the same method
    if has_pyfuse3:

        async def readdir(self, fh, off, token):  # type: ignore[misc]
            entries = self._readdir_entries(fh)
            for i, (name, inode) in enumerate(entries[off:], off):
                attrs = self._getattr(inode)
                if not llfuse.readdir_reply(token, name, attrs, i + 1):
                    break

    else:

        def readdir(self, fh, off):  # type: ignore[misc]
            entries = self._readdir_entries(fh)
            for i, (name, inode) in enumerate(entries[off:], off):
                attrs = self._getattr(inode)
                yield name, attrs, i + 1

    @async_wrapper
    def readlink(self, inode, ctx=None):
        return os.fsencode(self.vfs.readlink(inode))
