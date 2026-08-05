"""
``borg mount`` using mfusepy, the high-level (path based) FUSE 2 / FUSE 3 API.

This is a protocol adapter only: what an archive looks like as a file system is
defined in vfs.py, here we just translate between that and the mfusepy operations
interface (paths and stat dicts in, errnos out).
"""

import errno
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # For type checking, assume mfusepy is available
    # This allows mypy to understand hlfuse.Operations
    import mfusepy as hlfuse
    from .fuse_impl import ENOATTR
else:
    from .fuse_impl import hlfuse, ENOATTR

from .logger import create_logger

logger = create_logger()

from .helpers import daemonizing, signal_handler
from .storelocking import LockRefresher
from .vfs import ArchiveVFS, ChunkMissing, parse_mount_options

BLOCK_SIZE = 512  # Standard filesystem block size for st_blocks and statfs


class borgfs(hlfuse.Operations):
    """Export archive contents as a FUSE filesystem"""

    use_ns = True

    def __init__(self, manifest, args, repository):
        hlfuse.Operations.__init__(self)
        self._manifest = manifest
        self._args = args
        self._repository = repository
        # serializes all repository access (FUSE handlers and the background lock-refresh
        # thread), because borgstore connections are not thread-safe.
        self._repo_lock = threading.RLock()
        self.vfs = None  # created by mount(), once the mount options are known
        self.handles = {}  # file handle -> node
        self.handle_count = 0

    def mount(self, mountpoint, mount_options, foreground=False, show_rc=False):
        """Mount filesystem on *mountpoint* with *mount_options*."""
        options, vfs_options = parse_mount_options(self._args, mountpoint, mount_options)
        self.vfs = ArchiveVFS(self._manifest, self._args, self._repository, lock=self._repo_lock, options=vfs_options)
        self.vfs.create_filesystem()

        # hlfuse.FUSE will block if foreground=True, otherwise it returns immediately
        if not foreground:
            # Background mode: daemonize first, then start FUSE (blocking)
            with daemonizing(show_rc=show_rc) as (old_id, new_id):
                logger.debug("fuse: mount repo, going to background: migrating lock.")
                self._repository.migrate_lock(old_id, new_id)

        # keep the repository lock of an idle mount alive, so it is not killed as stale (see #9872).
        # started here (after a possible daemonizing fork, as threads do not survive fork()).
        lock_refreshing_thread = LockRefresher(self._repository.info, sleep_interval=60, lock=self._repo_lock)
        lock_refreshing_thread.start()
        try:
            # Run the FUSE main loop in foreground (we might be daemonized already or not)
            with signal_handler("SIGUSR1", self.sig_info_handler), signal_handler("SIGINFO", self.sig_info_handler):
                hlfuse.FUSE(self, mountpoint, options, foreground=True, use_ino=True)
        finally:
            lock_refreshing_thread.terminate()

    def sig_info_handler(self, sig_no, stack):
        self.vfs.log_stats()

    # -- helpers ---------------------------------------------------------------

    def _find_node(self, path):
        """Return the node at *path*; raises ENOENT if there is none."""
        segments = [segment for segment in path.split("/") if segment]
        try:
            _, node = self.vfs.resolve(segments)
        except KeyError:
            raise hlfuse.FuseOSError(errno.ENOENT) from None
        return node

    def _node_from_handle(self, fh):
        node = self.handles.get(fh)
        if node is None:
            raise hlfuse.FuseOSError(errno.EBADF)
        return node

    def _stat(self, node):
        """Build the stat dict of *node*."""
        attrs = self.vfs.attrs(node.ino)
        st = {
            "st_ino": attrs.ino,
            "st_mode": attrs.mode,
            "st_nlink": attrs.nlink,
            "st_uid": attrs.uid,
            "st_gid": attrs.gid,
            "st_rdev": attrs.rdev,
            "st_size": attrs.size,
            "st_blocks": (attrs.size + BLOCK_SIZE - 1) // BLOCK_SIZE,
        }
        if self.use_ns:
            st["st_mtime"] = attrs.mtime_ns
            st["st_atime"] = attrs.atime_ns
            st["st_ctime"] = attrs.ctime_ns
        else:
            st["st_mtime"] = attrs.mtime_ns / 1e9
            st["st_atime"] = attrs.atime_ns / 1e9
            st["st_ctime"] = attrs.ctime_ns / 1e9
        return st

    # -- filesystem operations -------------------------------------------------

    def statfs(self, path):
        return {
            "f_bsize": BLOCK_SIZE,
            "f_frsize": BLOCK_SIZE,
            "f_blocks": 0,
            "f_bfree": 0,
            "f_bavail": 0,
            "f_files": 0,
            "f_ffree": 0,
            "f_favail": 0,
            "f_namemax": 255,  # == NAME_MAX (depends on archive source OS / FS)
        }

    def getattr(self, path, fh=None):
        # use the file handle if we have one, to avoid the path lookup
        node = self._node_from_handle(fh) if fh is not None else self._find_node(path)
        return self._stat(node)

    def listxattr(self, path):
        node = self._find_node(path)
        return [name.decode("utf-8", "surrogateescape") for name in self.vfs.listxattr(node.ino)]

    def getxattr(self, path, name, position=0):
        node = self._find_node(path)
        if isinstance(name, str):
            name = name.encode("utf-8", "surrogateescape")
        try:
            return self.vfs.getxattr(node.ino, name)
        except KeyError:
            raise hlfuse.FuseOSError(ENOATTR) from None
        except ValueError:
            logger.warning(f"mount: could not convert ACL of {path!r} to the xattr representation")
            raise hlfuse.FuseOSError(errno.EIO) from None

    def open(self, path, fi):
        node = self._find_node(path)
        self.handle_count += 1
        self.handles[self.handle_count] = node
        fi.fh = self.handle_count
        return 0

    def release(self, path, fi):
        self.handles.pop(fi.fh, None)
        self.vfs.reader.forget(fi.fh)
        return 0

    def create(self, path, mode, fi=None):
        raise hlfuse.FuseOSError(errno.EROFS)

    def read(self, path, size, offset, fi):
        node = self._node_from_handle(fi.fh)
        try:
            return self.vfs.read(node.ino, offset, size, pos_key=fi.fh)
        except ChunkMissing:
            raise hlfuse.FuseOSError(errno.EIO) from None

    def readdir(self, path, fh=None):
        node = self._find_node(path)
        # offset 0 for all entries: we always return the full directory at once.
        yield (".", self._stat(node), 0)
        yield ("..", self._stat(node.parent if node.parent else node), 0)
        for name, child in self.vfs.children(node):
            yield (name, self._stat(child), 0)

    def readlink(self, path):
        node = self._find_node(path)
        return self.vfs.readlink(node.ino)
