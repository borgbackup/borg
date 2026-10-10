# Tests for platform.list_mounts() and the mount table parsers in platform/mounts.py.

import os

import pytest

from ...platform import list_mounts, base
from ...platform.mounts import MountEntry, parse_mountinfo, parse_mnttab
from ...platformflags import is_linux, is_darwin, is_freebsd, is_netbsd, is_sunos, is_win32

# /proc/self/mountinfo lines captured on Debian 13 (the fuse lines while borg mount was running,
# with "subtype=borgfs" / without it / with "-o fsname=other"; the mountpoint has a space in it).
MOUNTINFO = b"""\
24 29 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:11 - proc proc rw
25 29 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=4045056k,nr_inodes=1011264,mode=755,inode64
29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
31 25 0:26 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw,size=4068456k,nr_inodes=1017114,inode64
67 42 0:48 / /tmp/m14/mnt\\040point ro,nosuid,nodev,relatime shared:150 - fuse.borgfs borgfs ro,user_id=0,group_id=0
68 42 0:49 / /tmp/m14/mnt2 ro,nosuid,nodev,relatime shared:151 - fuse borgfs ro,user_id=0,group_id=0
69 42 0:50 / /tmp/m14/mnt3 ro,nosuid,nodev,relatime shared:152 - fuse.borgfs other ro,user_id=0,group_id=0
"""

# /etc/mnttab lines captured on OmniOS r151058 (the fuse line while borg mount was running).
MNTTAB = """\
rpool/ROOT/omnios-r151058u\t/\tzfs\tdev=4310002\t0
/devices\t/devices\tdevfs\tdev=89c0000\t1791368839
proc\t/proc\tproc\tdev=8a80000\t1791368839
swap\t/tmp\ttmpfs\tdev=8b40002\t1791368839
borgfs\t/root/mnt\tfuse\tdev=8c40001\t1791369000
"""


def test_parse_mountinfo():
    assert parse_mountinfo(MOUNTINFO.splitlines()) == [
        MountEntry("proc", "proc", "/proc"),
        MountEntry("udev", "devtmpfs", "/dev"),
        MountEntry("/dev/sda1", "ext4", "/"),
        MountEntry("tmpfs", "tmpfs", "/dev/shm"),
        MountEntry("borgfs", "fuse.borgfs", "/tmp/m14/mnt point"),
        MountEntry("borgfs", "fuse", "/tmp/m14/mnt2"),
        MountEntry("other", "fuse.borgfs", "/tmp/m14/mnt3"),
    ]


def test_parse_mountinfo_escapes():
    # space, tab, newline and backslash are escaped as octal byte values; non-ascii bytes are not escaped.
    line = b"1 2 0:3 / /mnt/a\\040b\\011c\\012d\\134e\\303\\244f\xc3\xb6 rw - ext4 /dev/x\\040y rw"
    assert parse_mountinfo([line]) == [MountEntry("/dev/x y", "ext4", "/mnt/a b\tc\nd\\eäfö")]


def test_parse_mountinfo_skips_garbage():
    assert parse_mountinfo([b"", b"no separator here", b"1 2 - ext4 /dev/x rw"]) == []


def test_parse_mnttab():
    assert parse_mnttab(MNTTAB.splitlines(keepends=True)) == [
        MountEntry("rpool/ROOT/omnios-r151058u", "zfs", "/"),
        MountEntry("/devices", "devfs", "/devices"),
        MountEntry("proc", "proc", "/proc"),
        MountEntry("swap", "tmpfs", "/tmp"),
        MountEntry("borgfs", "fuse", "/root/mnt"),
    ]


def test_parse_mnttab_skips_garbage():
    assert parse_mnttab(["", "just one field\n"]) == []


@pytest.mark.skipif(
    not (is_linux or is_darwin or is_freebsd or is_netbsd or is_sunos or is_win32),
    reason="listing the mounted file systems is not supported on this platform",
)
def test_list_mounts():
    mounts = list_mounts()
    assert mounts and all(isinstance(entry, MountEntry) for entry in mounts)
    root = os.environ.get("SystemDrive", "C:") if is_win32 else "/"
    entry = next(entry for entry in mounts if entry.mountpoint == root)
    assert entry.fstype  # e.g. ext4, apfs, ufs, ffs, zfs, NTFS


def test_list_mounts_unsupported():
    # the base implementation (used on the platforms without support) warns and returns an empty list.
    assert base.list_mounts() == []
