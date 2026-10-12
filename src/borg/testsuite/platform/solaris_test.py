# Tests for the illumos / Solaris platform module (pure Python, so they run everywhere).

from ...platform.base import MountEntry
from ...platform.solaris import parse_mnttab

# /etc/mnttab lines captured on OmniOS r151058 (the fuse line while borg mount was running).
MNTTAB = """\
rpool/ROOT/omnios-r151058u\t/\tzfs\tdev=4310002\t0
/devices\t/devices\tdevfs\tdev=89c0000\t1791368839
proc\t/proc\tproc\tdev=8a80000\t1791368839
swap\t/tmp\ttmpfs\tdev=8b40002\t1791368839
borgfs\t/root/mnt\tfuse\tdev=8c40001\t1791369000
"""


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
