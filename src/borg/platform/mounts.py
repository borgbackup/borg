"""
Enumerating the mounted file systems (the mount table) on the platforms that offer a way to do so.

Each platform-specific list_mounts_* function returns a list of MountEntry (source, fstype,
mountpoint) tuples with everything the OS reports, it does not know what a borg mount is.
platform/__init__.py exports the right one as platform.list_mounts(); platform/base.py has the
documented stub for the platforms not handled here.

What a FUSE file system mounted with ``-o fsname=borgfs`` looks like per platform (measured):

- Linux: source ``borgfs``, fstype ``fuse`` (``fuse.borgfs`` with the ``subtype=borgfs`` option)
- macOS (macFUSE): source ``borgfs``, fstype ``macfuse``
- FreeBSD: source ``borgfs``, fstype ``fusefs``
- NetBSD (librefuse / puffs): source ``/dev/puffs``, fstype ``puffs|borgfs``
- illumos (libfuse): source ``borgfs``, fstype ``fuse``
- Windows (WinFsp): the fs name is ``FUSE``, the volume label comes from the ``volname`` option
"""

import os
import re
from typing import NamedTuple


class MountEntry(NamedTuple):
    source: str  # what is mounted ("device"), e.g. /dev/sda1, borgfs, /dev/puffs; on Windows: the volume label
    fstype: str  # file system type, e.g. ext4, fuse.borgfs, macfuse, fusefs, puffs|borgfs; on Windows: FUSE, NTFS
    mountpoint: str  # where it is mounted; on Windows: the drive, e.g. X:


_MOUNTINFO_ESCAPE_RE = re.compile(rb"\\([0-7]{3})")


def _unescape_mountinfo(field):
    # /proc/self/mountinfo escapes space, tab, newline and backslash as \040, \011, \012 and \134.
    # It escapes bytes, so unescape bytes and decode the result, not the other way round.
    return os.fsdecode(_MOUNTINFO_ESCAPE_RE.sub(lambda m: bytes([int(m.group(1), 8)]), field))


def parse_mountinfo(lines):
    """Parse the lines of /proc/self/mountinfo (bytes), see proc_pid_mountinfo(5).

    Each line is: mount ID, parent ID, major:minor, root, mountpoint, mount options, zero or
    more optional fields, a lone "-", fstype, source, super options. As the number of optional
    fields varies, the fields after the separator are found from the end of the line.
    """
    entries = []
    for line in lines:
        fields = line.split()
        try:
            sep = fields.index(b"-")
        except ValueError:
            continue  # not a mountinfo line
        if sep < 5 or len(fields) < sep + 3:
            continue
        mountpoint, fstype, source = fields[4], fields[sep + 1], fields[sep + 2]
        entries.append(MountEntry(_unescape_mountinfo(source), os.fsdecode(fstype), _unescape_mountinfo(mountpoint)))
    return entries


def list_mounts_linux():
    with open("/proc/self/mountinfo", "rb") as f:
        return parse_mountinfo(f.read().splitlines())


def parse_mnttab(lines):
    """Parse the lines of /etc/mnttab (str), see mnttab(5).

    Each line has 5 tab-separated fields: special (source), mount point, fstype, options, time.
    """
    entries = []
    for line in lines:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 3:
            continue  # not a mnttab line
        source, mountpoint, fstype = fields[:3]
        entries.append(MountEntry(source, fstype, mountpoint))
    return entries


def list_mounts_sunos():
    with open("/etc/mnttab", encoding="utf-8", errors="surrogateescape") as f:
        return parse_mnttab(f)


MNT_NOWAIT = 2  # do not ask the file systems for fresh statistics, return what the kernel has


def _c_name(buf):
    return os.fsdecode(bytes(buf).split(b"\0", 1)[0])


def _getmntinfo(statfs_struct, symbol):
    # getmntinfo(struct statfs **mntbufp, int mode) returns the number of mounted file systems and
    # points *mntbufp to an array (allocated by libc, not to be freed) of that many struct statfs.
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    getmntinfo = getattr(libc, symbol)
    getmntinfo.argtypes = [ctypes.POINTER(ctypes.POINTER(statfs_struct)), ctypes.c_int]
    getmntinfo.restype = ctypes.c_int
    mntbuf = ctypes.POINTER(statfs_struct)()
    count = getmntinfo(ctypes.byref(mntbuf), MNT_NOWAIT)
    if count <= 0:
        raise OSError(ctypes.get_errno(), f"{symbol} failed")
    return [
        MountEntry(_c_name(mntbuf[i].f_mntfromname), _c_name(mntbuf[i].f_fstypename), _c_name(mntbuf[i].f_mntonname))
        for i in range(count)
    ]


def list_mounts_darwin():
    import ctypes

    MFSTYPENAMELEN, MAXPATHLEN = 16, 1024

    class statfs(ctypes.Structure):  # struct statfs with 64-bit inodes, see statfs(2) / sys/mount.h
        _fields_ = [
            ("f_bsize", ctypes.c_uint32),
            ("f_iosize", ctypes.c_int32),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_uint64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_uint64),
            ("f_fsid", ctypes.c_int32 * 2),
            ("f_owner", ctypes.c_uint32),
            ("f_type", ctypes.c_uint32),
            ("f_flags", ctypes.c_uint32),
            ("f_fssubtype", ctypes.c_uint32),
            ("f_fstypename", ctypes.c_char * MFSTYPENAMELEN),
            ("f_mntonname", ctypes.c_char * MAXPATHLEN),
            ("f_mntfromname", ctypes.c_char * MAXPATHLEN),
            ("f_flags_ext", ctypes.c_uint32),
            ("f_reserved", ctypes.c_uint32 * 7),
        ]

    assert ctypes.sizeof(statfs) == 2168
    # On x86_64, the plain symbol is the legacy 32-bit inode variant and the 64-bit inode one has
    # the $INODE64 suffix; arm64 only ever had the 64-bit inode variant, under the plain name.
    symbol = "getmntinfo" if os.uname().machine == "arm64" else "getmntinfo$INODE64"
    return _getmntinfo(statfs, symbol)


def list_mounts_freebsd():
    import ctypes

    MFSNAMELEN, MNAMELEN = 16, 1024

    class statfs(ctypes.Structure):  # struct statfs, see statfs(2) / sys/mount.h (STATFS_VERSION 0x20140518)
        _fields_ = [
            ("f_version", ctypes.c_uint32),
            ("f_type", ctypes.c_uint32),
            ("f_flags", ctypes.c_uint64),
            ("f_bsize", ctypes.c_uint64),
            ("f_iosize", ctypes.c_uint64),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_int64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_int64),
            ("f_syncwrites", ctypes.c_uint64),
            ("f_asyncwrites", ctypes.c_uint64),
            ("f_syncreads", ctypes.c_uint64),
            ("f_asyncreads", ctypes.c_uint64),
            ("f_spare", ctypes.c_uint64 * 10),
            ("f_namemax", ctypes.c_uint32),
            ("f_owner", ctypes.c_uint32),
            ("f_fsid", ctypes.c_int32 * 2),
            ("f_charspare", ctypes.c_char * 80),
            ("f_fstypename", ctypes.c_char * MFSNAMELEN),
            ("f_mntfromname", ctypes.c_char * MNAMELEN),
            ("f_mntonname", ctypes.c_char * MNAMELEN),
        ]

    assert ctypes.sizeof(statfs) == 2344
    return _getmntinfo(statfs, "getmntinfo")


def list_mounts_netbsd():
    import ctypes
    import ctypes.util

    VFS_NAMELEN, VFS_MNAMELEN = 32, 1024

    class statvfs(ctypes.Structure):  # struct statvfs, see statvfs(2) / sys/statvfs.h (NetBSD >= 9)
        _fields_ = [
            ("f_flag", ctypes.c_ulong),
            ("f_bsize", ctypes.c_ulong),
            ("f_frsize", ctypes.c_ulong),
            ("f_iosize", ctypes.c_ulong),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_uint64),
            ("f_bresvd", ctypes.c_uint64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_uint64),
            ("f_favail", ctypes.c_uint64),
            ("f_fresvd", ctypes.c_uint64),
            ("f_syncreads", ctypes.c_uint64),
            ("f_syncwrites", ctypes.c_uint64),
            ("f_asyncreads", ctypes.c_uint64),
            ("f_asyncwrites", ctypes.c_uint64),
            ("f_fsidx", ctypes.c_int32 * 2),
            ("f_fsid", ctypes.c_ulong),
            ("f_namemax", ctypes.c_ulong),
            ("f_owner", ctypes.c_uint32),
            ("f_spare", ctypes.c_uint64 * 4),
            ("f_fstypename", ctypes.c_char * VFS_NAMELEN),
            ("f_mntonname", ctypes.c_char * VFS_MNAMELEN),
            ("f_mntfromname", ctypes.c_char * VFS_MNAMELEN),
            ("f_mntfromlabel", ctypes.c_char * VFS_MNAMELEN),
        ]

    # getvfsstat(struct statvfs *buf, size_t bufsize, int flags) returns the number of mounted file
    # systems (all of them if buf is NULL, else as many as fit into buf). The struct grew in NetBSD 9
    # (f_mntfromlabel), the plain symbol of libc is the compat version and returns nothing useful.
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    getvfsstat = libc.__getvfsstat90
    getvfsstat.argtypes = [ctypes.POINTER(statvfs), ctypes.c_size_t, ctypes.c_int]
    getvfsstat.restype = ctypes.c_int
    count = getvfsstat(None, 0, MNT_NOWAIT)
    if count < 0:
        raise OSError(ctypes.get_errno(), "getvfsstat failed")
    buf = (statvfs * count)()
    count = getvfsstat(buf, ctypes.sizeof(buf), MNT_NOWAIT)
    if count < 0:
        raise OSError(ctypes.get_errno(), "getvfsstat failed")
    return [
        MountEntry(_c_name(buf[i].f_mntfromname), _c_name(buf[i].f_fstypename), _c_name(buf[i].f_mntonname))
        for i in range(count)
    ]


def list_mounts_win32():
    """List the volumes mounted on drive letters.

    A file system mounted on a directory (a WinFsp directory mountpoint is a junction pointing to the
    volume) is not found this way, there is no API to enumerate these mountpoints.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_unicode_buffer(1024)
    length = kernel32.GetLogicalDriveStringsW(len(buf) - 1, buf)
    if not length:
        raise ctypes.WinError()
    entries = []
    for root in buf[:length].split("\0"):  # e.g. "C:\\", "X:\\" - GetVolumeInformationW needs the backslash
        if not root:
            continue
        label = ctypes.create_unicode_buffer(wintypes.MAX_PATH + 1)
        fsname = ctypes.create_unicode_buffer(wintypes.MAX_PATH + 1)
        if not kernel32.GetVolumeInformationW(root, label, len(label), None, None, None, fsname, len(fsname)):
            continue  # e.g. a drive without media or a disconnected network drive
        entries.append(MountEntry(label.value, fsname.value, root.rstrip("\\")))
    return entries
