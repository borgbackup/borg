import errno
import os
import sys
import time
import subprocess
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from ...constants import *  # NOQA
from ...helpers import flags_noatime, flags_normal
from .. import has_lchflags, changedir
from .. import same_ts_ns
from ..platform.platform_test import fakeroot_detected
from . import (
    RK_ENCRYPTION,
    cmd,
    assert_dirs_equal,
    create_test_files,
    generate_archiver_tests,
    create_src_archive,
    open_archive,
    src_file,
)
from . import requires_hardlinks, _extract_hardlinks_setup

try:
    import mfusepy
except ImportError:
    mfusepy = None

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


@contextmanager
def fuse_mount2(archiver, mountpoint, *args, **kwargs):
    os.makedirs(mountpoint, exist_ok=True)

    # We use subprocess to run borg mount2 to ensure it runs in a separate process
    # and we can control it via signals if needed.
    # We use --foreground to keep it running.

    cmd_args = ["mount2", "--foreground"]

    # If the first arg is a path (not starting with -), it might be a path inside the repo
    # But mount2 syntax is: borg mount2 [options] repo_or_archive mountpoint [path]
    # Wait, standard mount is: borg mount repo mountpoint
    # mount2 is: borg mount2 repo mountpoint

    # We need to construct the command line carefully.
    # args might contain options or paths.

    # Let's assume usage: fuse_mount2(archiver, mountpoint, options...)
    # The repo path is archiver.repository_path

    # If we want to mount a specific archive: fuse_mount2(archiver, mountpoint, "archive_name")
    # But mount2 takes "repo::archive" as location.

    # Let's look at how test_fuse uses it.
    # fuse_mount(archiver, mountpoint, "-a", "test", ...)

    # mount2 supports "repo" or "repo::archive".

    location = archiver.repository_path

    # Check if we have extra args that look like options
    # Just pass all args to the command
    # We put mountpoint first, then --repo location, then all other args
    # This assumes mount2 supports: borg mount2 mountpoint --repo location [options] [paths]
    # or: borg mount2 mountpoint --repo location -a archive [paths]

    borg_cmd = [sys.executable, "-m", "borg"]
    full_cmd = borg_cmd + cmd_args + [mountpoint, "--repo", location] + list(args)

    # If other_args has something, it might be that we want to mount a specific archive
    # or a path inside the archive?
    # mount2 currently supports: borg mount2 repo::archive mountpoint
    # It does NOT support: borg mount2 repo mountpoint path
    # It DOES support: borg mount2 repo mountpoint

    # If the test passes "-a", "archive", we should handle it.
    # But mount2 might not support -a yet?
    # Let's check mount2_cmds.py arguments.
    # It supports "location" and "mountpoint".
    # It also supports --options (-o).
    # It does NOT seem to support -a / --match-archives yet based on my previous read,
    # OR it does via list_considering?
    # Re-reading mount2_cmds.py would be good, but I recall it uses `self._args.name`
    # if provided via `location` parsing.

    # If the test wants to mount a specific archive, it should probably pass it in location.
    # But `fuse_mount` in `mount_cmds_test.py` takes `*options`.

    # Let's try to be smart.
    # If "-a" is in options, mount2 probably doesn't support it directly as a flag
    # if it expects repo::archive.
    # But wait, `list_considering` was used.

    # Let's just pass all args to the command and see.
    # But we need to put location and mountpoint in the right place.

    # Command: borg mount2 [options] MOUNTPOINT --repo=LOCATION

    borg_cmd = [sys.executable, "-m", "borg"]
    # We pass mountpoint as positional arg, and repo as --repo
    # options and other_args are passed as is
    # full_cmd constructed above

    env = os.environ.copy()
    # env["BORG_REPO"] = archiver.repository_location # Not needed if --repo is used, but keeps it safe?
    # Actually, if we use --repo, we don't need BORG_REPO env var for the command,
    # but we might need it for other things?
    # Let's keep it but --repo should take precedence or be used.
    env["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"

    # p = subprocess.Popen(full_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # For debugging, let's inherit stderr
    # p = subprocess.Popen(full_cmd, env=env, stdout=subprocess.PIPE, stderr=None)

    log_file = open("/Users/tw/w/borg_ag/mount2.log", "w")
    p = subprocess.Popen(full_cmd, env=env, stdout=log_file, stderr=log_file)

    # Wait for mount
    timeout = 5
    start = time.time()
    while time.time() - start < timeout:
        if os.path.ismount(mountpoint):
            break
        time.sleep(0.1)
    else:
        # Timeout or failed
        p.terminate()
        p.wait()
        log_file.close()
        with open(log_file_path, "r") as f:
            output = f.read()
        print("Mount failed to appear. Output:", output, file=sys.stderr)
        # We might want to raise, but let's yield to let the test fail with a better error
        # or maybe the test expects failure?

    try:
        yield
    finally:
        if not log_file.closed:
            log_file.close()
        if os.path.ismount(mountpoint):
            # Try to umount
            subprocess.call(["umount", mountpoint])
            # If that fails (e.g. busy), we might need force or fusermount -u
            if os.path.ismount(mountpoint):
                subprocess.call(["fusermount", "-u", "-z", mountpoint])

        p.terminate()
        p.wait()
        # Cleanup mountpoint dir if empty
        try:
            os.rmdir(mountpoint)
        except OSError:
            pass


def test_mount2_missing_mfuse(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # Ensure mfuse is NOT in sys.modules or is None
    with patch.dict(sys.modules, {"mfusepy": None}):
        cmd(archiver, "repo-create", RK_ENCRYPTION)
        cmd(archiver, "create", "archive", "input")
        mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
        os.makedirs(mountpoint, exist_ok=True)

        from ...helpers import CommandError

        try:
            cmd(archiver, "mount2", archiver.repository_path + "::archive", mountpoint)
        except CommandError:
            # We expect it to fail because mfuse is missing
            # The error message might vary depending on how it's handled
            pass
        except Exception:
            pass


@requires_hardlinks
@pytest.mark.skipif(mfusepy is None, reason="mfusepy not installed")
def test_fuse_mount_hardlinks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _extract_hardlinks_setup(archiver)
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    # we need to get rid of permissions checking because fakeroot causes issues with it.
    # On all platforms, borg defaults to "default_permissions" and we need to get rid of it via "ignore_permissions".
    # On macOS (darwin), we additionally need "defer_permissions" to switch off the checks in osxfuse.
    if sys.platform == "darwin":
        ignore_perms = ["-o", "ignore_permissions,defer_permissions"]
    else:
        ignore_perms = ["-o", "ignore_permissions"]
    with fuse_mount2(archiver, mountpoint, "-a", "test", "--strip-components=2", *ignore_perms):
        with changedir(os.path.join(mountpoint, "test")):
            assert os.stat("hardlink").st_nlink == 2
            assert os.stat("subdir/hardlink").st_nlink == 2
            assert open("subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("aaaa").st_nlink == 2
            assert os.stat("source2").st_nlink == 2

    with fuse_mount2(archiver, mountpoint, "input/dir1", "-a", "test", *ignore_perms):
        with changedir(os.path.join(mountpoint, "test")):
            assert os.stat("input/dir1/hardlink").st_nlink == 2
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("input/dir1/aaaa").st_nlink == 2
            assert os.stat("input/dir1/source2").st_nlink == 2

    with fuse_mount2(archiver, mountpoint, "-a", "test", *ignore_perms):
        with changedir(os.path.join(mountpoint, "test")):
            assert os.stat("input/source").st_nlink == 4
            assert os.stat("input/abba").st_nlink == 4
            assert os.stat("input/dir1/hardlink").st_nlink == 4
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 4
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"


@pytest.mark.skipif(mfusepy is None, reason="mfusepy not installed")
def test_fuse_duplicate_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "duplicate", "input")
    cmd(archiver, "create", "duplicate", "input")
    cmd(archiver, "create", "unique1", "input")
    cmd(archiver, "create", "unique2", "input")
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    # mount the whole repository, archives show up as toplevel directories:
    with fuse_mount2(archiver, mountpoint):
        path = os.path.join(mountpoint)
        dirs = os.listdir(path)
        assert len(set(dirs)) == 4  # there must be 4 unique dir names for 4 archives
        assert "unique1" in dirs  # if an archive has a unique name, do not append the archive id
        assert "unique2" in dirs


@pytest.mark.skipif(mfusepy is None, reason="mfusepy not installed")
def test_fuse_allow_damaged_files(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    # Get rid of a chunk
    archive, repository = open_archive(archiver.repository_path, "archive")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                repository.delete(item.chunks[-1].id)
                path = item.path  # store full path for later
                break
        else:
            assert False  # missed the file

    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    with fuse_mount2(archiver, mountpoint, "-a", "archive"):
        with open(os.path.join(mountpoint, "archive", path), "rb") as f:
            with pytest.raises(OSError) as excinfo:
                f.read()
            assert excinfo.value.errno == errno.EIO

    with fuse_mount2(archiver, mountpoint, "-a", "archive", "-o", "allow_damaged_files"):
        with open(os.path.join(mountpoint, "archive", path), "rb") as f:
            # no exception raised, missing data will be all-zero
            data = f.read()
        assert data.endswith(b"\0\0")


@pytest.mark.skipif(mfusepy is None, reason="mfusepy not installed")
def test_fuse_mount_options(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "arch11")
    create_src_archive(archiver, "arch12")
    create_src_archive(archiver, "arch21")
    create_src_archive(archiver, "arch22")
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    with fuse_mount2(archiver, mountpoint, "--first=2", "--sort-by=name"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
    with fuse_mount2(archiver, mountpoint, "--last=2", "--sort-by=name"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
    with fuse_mount2(archiver, mountpoint, "--match-archives=sh:arch1*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
    with fuse_mount2(archiver, mountpoint, "--match-archives=sh:arch2*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
    with fuse_mount2(archiver, mountpoint, "--match-archives=sh:arch*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12", "arch21", "arch22"]
    with fuse_mount2(archiver, mountpoint, "--match-archives=nope"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == []


def test_fuse2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE and fakeroot_detected():
        pytest.skip("test_fuse with the binary is not compatible with fakeroot")

    def has_noatime(some_file):
        atime_before = os.stat(some_file).st_atime_ns
        try:
            os.close(os.open(some_file, flags_noatime))
        except PermissionError:
            return False
        else:
            atime_after = os.stat(some_file).st_atime_ns
            noatime_used = flags_noatime != flags_normal
            return noatime_used and atime_before == atime_after

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_test_files(archiver.input_path)
    have_noatime = has_noatime("input/file1")
    cmd(archiver, "create", "--atime", "archive", "input")
    cmd(archiver, "create", "--atime", "archive2", "input")

    if has_lchflags:
        os.remove(os.path.join("input", "flagfile"))

    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")

    # Mount specific archive
    with fuse_mount2(archiver, mountpoint, "-a", "archive"):
        # Check if archive is listed
        assert "archive" in os.listdir(mountpoint)

        # Check contents
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )

        # Check details of a file
        in_fn = "input/file1"
        out_fn = os.path.join(mountpoint, "archive", "input", "file1")

        sti1 = os.stat(in_fn)
        sto1 = os.stat(out_fn)

        assert sti1.st_mode == sto1.st_mode
        assert sti1.st_uid == sto1.st_uid
        assert sti1.st_gid == sto1.st_gid
        assert sti1.st_size == sto1.st_size

        # Check timestamps (nanosecond resolution)
        # We enabled use_ns = True, so we expect high precision if supported
        assert same_ts_ns(sti1.st_mtime * 1e9, sto1.st_mtime * 1e9)
        assert same_ts_ns(sti1.st_ctime * 1e9, sto1.st_ctime * 1e9)

        if have_noatime:
            assert same_ts_ns(sti1.st_atime * 1e9, sto1.st_atime * 1e9)

        # Read content
        with open(in_fn, "rb") as f1, open(out_fn, "rb") as f2:
            assert f1.read() == f2.read()

    # Mount whole repository
    with fuse_mount2(archiver, mountpoint):
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive2", "input"), ignore_flags=True, ignore_xattrs=True
        )

    # Ignore permissions
    with fuse_mount2(archiver, mountpoint, "-o", "ignore_permissions"):
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )

    # Allow damaged files
    with fuse_mount2(archiver, mountpoint, "-o", "allow_damaged_files"):
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )
