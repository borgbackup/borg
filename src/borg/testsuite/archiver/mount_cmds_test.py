import errno
import os
import stat
import sys

import pytest

from ... import xattr, platform
from ...constants import *  # NOQA
from ...storelocking import Lock
from ...helpers import flags_noatime, flags_normal
from .. import has_lchflags, llfuse
from .. import changedir, no_selinux, same_ts_ns
from .. import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported
from ..platform.platform_test import fakeroot_detected
from . import RK_ENCRYPTION, cmd, assert_dirs_equal, create_regular_file, create_src_archive, open_archive, src_file
from . import requires_hardlinks, _extract_hardlinks_setup, fuse_mount, create_test_files, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


@requires_hardlinks
@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
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
    with (
        fuse_mount(archiver, mountpoint, "-a", "test", "--strip-components=2", *ignore_perms),
        changedir(os.path.join(mountpoint, "test")),
    ):
        assert os.stat("hardlink").st_nlink == 2
        assert os.stat("subdir/hardlink").st_nlink == 2
        assert open("subdir/hardlink", "rb").read() == b"123456"
        assert os.stat("aaaa").st_nlink == 2
        assert os.stat("source2").st_nlink == 2
    with (
        fuse_mount(archiver, mountpoint, "input/dir1", "-a", "test", *ignore_perms),
        changedir(os.path.join(mountpoint, "test")),
    ):
        assert os.stat("input/dir1/hardlink").st_nlink == 2
        assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
        assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"
        assert os.stat("input/dir1/aaaa").st_nlink == 2
        assert os.stat("input/dir1/source2").st_nlink == 2
    with fuse_mount(archiver, mountpoint, "-a", "test", *ignore_perms), changedir(os.path.join(mountpoint, "test")):
        assert os.stat("input/source").st_nlink == 4
        assert os.stat("input/abba").st_nlink == 4
        assert os.stat("input/dir1/hardlink").st_nlink == 4
        assert os.stat("input/dir1/subdir/hardlink").st_nlink == 4
        assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_fuse(archivers, request):
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
        # remove the file that we did not back up, so input and output become equal
        os.remove(os.path.join("input", "flagfile"))
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    # mount the whole repository, archive contents shall show up in archivename subdirectories of mountpoint:
    with fuse_mount(archiver, mountpoint):
        # flags are not supported by the FUSE mount
        # we also ignore xattrs here, they are tested separately
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive2", "input"), ignore_flags=True, ignore_xattrs=True
        )
    with fuse_mount(archiver, mountpoint, "-a", "archive"):
        assert_dirs_equal(
            archiver.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
        )
        # regular file
        in_fn = "input/file1"
        out_fn = os.path.join(mountpoint, "archive", "input", "file1")
        # stat
        sti1 = os.stat(in_fn)
        sto1 = os.stat(out_fn)
        assert sti1.st_mode == sto1.st_mode
        assert sti1.st_uid == sto1.st_uid
        assert sti1.st_gid == sto1.st_gid
        assert sti1.st_size == sto1.st_size
        if have_noatime:
            assert same_ts_ns(sti1.st_atime * 1e9, sto1.st_atime * 1e9)
        assert same_ts_ns(sti1.st_ctime * 1e9, sto1.st_ctime * 1e9)
        assert same_ts_ns(sti1.st_mtime * 1e9, sto1.st_mtime * 1e9)
        if are_hardlinks_supported():
            # note: there is another hardlink to this, see below
            assert sti1.st_nlink == sto1.st_nlink == 2
        # read
        with open(in_fn, "rb") as in_f, open(out_fn, "rb") as out_f:
            assert in_f.read() == out_f.read()
        # hardlink (to 'input/file1')
        if are_hardlinks_supported():
            in_fn = "input/hardlink"
            out_fn = os.path.join(mountpoint, "archive", "input", "hardlink")
            sti2 = os.stat(in_fn)
            sto2 = os.stat(out_fn)
            assert sti2.st_nlink == sto2.st_nlink == 2
            assert sto1.st_ino == sto2.st_ino
        # symlink
        if are_symlinks_supported():
            in_fn = "input/link1"
            out_fn = os.path.join(mountpoint, "archive", "input", "link1")
            sti = os.stat(in_fn, follow_symlinks=False)
            sto = os.stat(out_fn, follow_symlinks=False)
            assert sti.st_size == len("somewhere")
            assert sto.st_size == len("somewhere")
            assert stat.S_ISLNK(sti.st_mode)
            assert stat.S_ISLNK(sto.st_mode)
            assert os.readlink(in_fn) == os.readlink(out_fn)
        # FIFO
        if are_fifos_supported():
            out_fn = os.path.join(mountpoint, "archive", "input", "fifo1")
            sto = os.stat(out_fn)
            assert stat.S_ISFIFO(sto.st_mode)
        # list/read xattrs
        try:
            in_fn = "input/fusexattr"
            out_fn = os.fsencode(os.path.join(mountpoint, "archive", "input", "fusexattr"))
            if not xattr.XATTR_FAKEROOT and xattr.is_enabled(archiver.input_path):
                assert sorted(no_selinux(xattr.listxattr(out_fn))) == [b"user.empty", b"user.foo"]
                assert xattr.getxattr(out_fn, b"user.foo") == b"bar"
                assert xattr.getxattr(out_fn, b"user.empty") == b""
            else:
                assert no_selinux(xattr.listxattr(out_fn)) == []
                try:
                    xattr.getxattr(out_fn, b"user.foo")
                except OSError as e:
                    assert e.errno == llfuse.ENOATTR
                else:
                    assert False, "expected OSError(ENOATTR), but no error was raised"
        except OSError as err:
            if sys.platform.startswith(("nothing_here_now",)) and err.errno == errno.ENOTSUP:
                # some systems have no xattr support on FUSE
                pass
            else:
                raise


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_fuse_versions_view(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "test", contents=b"first")
    if are_hardlinks_supported():
        create_regular_file(archiver.input_path, "hardlink1", contents=b"123456")
        os.link("input/hardlink1", "input/hardlink2")
        os.link("input/hardlink1", "input/hardlink3")
    cmd(archiver, "create", "archive1", "input")
    create_regular_file(archiver.input_path, "test", contents=b"second")
    cmd(archiver, "create", "archive2", "input")
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    # mount the whole repository, archive contents shall show up in versioned view:
    with fuse_mount(archiver, mountpoint, "-o", "versions"):
        path = os.path.join(mountpoint, "input", "test")  # filename shows up as directory ...
        files = os.listdir(path)
        assert all(f.startswith("test.") for f in files)  # ... with files test.xxxxx in there
        assert {b"first", b"second"} == {open(os.path.join(path, f), "rb").read() for f in files}
        if are_hardlinks_supported():
            hl1 = os.path.join(mountpoint, "input", "hardlink1", "hardlink1.00001")
            hl2 = os.path.join(mountpoint, "input", "hardlink2", "hardlink2.00001")
            hl3 = os.path.join(mountpoint, "input", "hardlink3", "hardlink3.00001")
            assert os.stat(hl1).st_ino == os.stat(hl2).st_ino == os.stat(hl3).st_ino
            assert open(hl3, "rb").read() == b"123456"
    # similar again, but exclude the 1st hardlink:
    with fuse_mount(archiver, mountpoint, "-o", "versions", "-e", "input/hardlink1"):
        if are_hardlinks_supported():
            hl2 = os.path.join(mountpoint, "input", "hardlink2", "hardlink2.00001")
            hl3 = os.path.join(mountpoint, "input", "hardlink3", "hardlink3.00001")
            assert os.stat(hl2).st_ino == os.stat(hl3).st_ino
            assert open(hl3, "rb").read() == b"123456"


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_fuse_duplicate_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "duplicate", "input")
    cmd(archiver, "create", "duplicate", "input")
    cmd(archiver, "create", "unique1", "input")
    cmd(archiver, "create", "unique2", "input")
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    # mount the whole repository, archives show up as toplevel directories:
    with fuse_mount(archiver, mountpoint):
        path = os.path.join(mountpoint)
        dirs = os.listdir(path)
        assert len(set(dirs)) == 4  # there must be 4 unique dir names for 4 archives
        assert "unique1" in dirs  # if an archive has a unique name, do not append the archive id
        assert "unique2" in dirs


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_fuse_allow_damaged_files(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    # Get rid of a chunk and repair it
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
    with fuse_mount(archiver, mountpoint, "-a", "archive"):
        with open(os.path.join(mountpoint, "archive", path), "rb") as f:
            with pytest.raises(OSError) as excinfo:
                f.read()
            assert excinfo.value.errno == errno.EIO

    with fuse_mount(archiver, mountpoint, "-a", "archive", "-o", "allow_damaged_files"):
        with open(os.path.join(mountpoint, "archive", path), "rb") as f:
            # no exception raised, missing data will be all-zero
            data = f.read()
        assert data.endswith(b"\0\0")


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_fuse_mount_options(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "arch11")
    create_src_archive(archiver, "arch12")
    create_src_archive(archiver, "arch21")
    create_src_archive(archiver, "arch22")
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    with fuse_mount(archiver, mountpoint, "--first=2", "--sort=name"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
    with fuse_mount(archiver, mountpoint, "--last=2", "--sort=name"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
    with fuse_mount(archiver, mountpoint, "--match-archives=sh:arch1*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
    with fuse_mount(archiver, mountpoint, "--match-archives=sh:arch2*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
    with fuse_mount(archiver, mountpoint, "--match-archives=sh:arch*"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12", "arch21", "arch22"]
    with fuse_mount(archiver, mountpoint, "--match-archives=nope"):
        assert sorted(os.listdir(os.path.join(mountpoint))) == []


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_migrate_lock_alive(archivers, request):
    """Both old_id and new_id must not be stale during lock migration / daemonization."""
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    from functools import wraps
    import pickle
    import traceback

    # Check results are communicated from the borg mount background process
    # to the pytest process by means of a serialized dict object stored in this file.
    assert_data_file = os.path.join(archiver.tmpdir, "migrate_lock_assert_data.pickle")

    # Decorates Lock.migrate_lock() with process_alive() checks before and after.
    # (We don't want to mix testing code into runtime.)
    def write_assert_data(migrate_lock):
        @wraps(migrate_lock)
        def wrapper(self, old_id, new_id):
            wrapper.num_calls += 1
            assert_data = {
                "num_calls": wrapper.num_calls,
                "old_id": old_id,
                "new_id": new_id,
                "before": {
                    "old_id_alive": platform.process_alive(*old_id),
                    "new_id_alive": platform.process_alive(*new_id),
                },
                "exception": None,
                "exception.extr_tb": None,
                "after": {"old_id_alive": None, "new_id_alive": None},
            }
            try:
                with open(assert_data_file, "wb") as _out:
                    pickle.dump(assert_data, _out)
            except:  # noqa
                pass
            try:
                return migrate_lock(self, old_id, new_id)
            except BaseException as e:
                assert_data["exception"] = e
                assert_data["exception.extr_tb"] = traceback.extract_tb(e.__traceback__)
            finally:
                assert_data["after"].update(
                    {"old_id_alive": platform.process_alive(*old_id), "new_id_alive": platform.process_alive(*new_id)}
                )
                try:
                    with open(assert_data_file, "wb") as _out:
                        pickle.dump(assert_data, _out)
                except:  # noqa
                    pass

        wrapper.num_calls = 0
        return wrapper

    # Decorate
    Lock.migrate_lock = write_assert_data(Lock.migrate_lock)
    try:
        cmd(archiver, "repo-create", "--encryption=none")
        create_src_archive(archiver, "arch")
        mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
        # In order that the decoration is kept for the borg mount process, we must not spawn, but actually fork;
        # not to be confused with the forking in borg.helpers.daemonize() which is done as well.
        with fuse_mount(archiver, mountpoint, os_fork=True):
            pass
        with open(assert_data_file, "rb") as _in:
            assert_data = pickle.load(_in)
        print(f"\nLock.migrate_lock(): assert_data = {assert_data!r}.", file=sys.stderr, flush=True)
        exception = assert_data["exception"]
        if exception is not None:
            extracted_tb = assert_data["exception.extr_tb"]
            print(
                "Lock.migrate_lock() raised an exception:\n",
                "Traceback (most recent call last):\n",
                *traceback.format_list(extracted_tb),
                *traceback.format_exception(exception.__class__, exception, None),
                sep="",
                end="",
                file=sys.stderr,
                flush=True,
            )

        assert assert_data["num_calls"] == 1, "Lock.migrate_lock() must be called exactly once."
        assert exception is None, "Lock.migrate_lock() may not raise an exception."

        assert_data_before = assert_data["before"]
        assert assert_data_before[
            "old_id_alive"
        ], "old_id must be alive (=must not be stale) when calling Lock.migrate_lock()."
        assert assert_data_before[
            "new_id_alive"
        ], "new_id must be alive (=must not be stale) when calling Lock.migrate_lock()."

        assert_data_after = assert_data["after"]
        assert assert_data_after[
            "old_id_alive"
        ], "old_id must be alive (=must not be stale) when Lock.migrate_lock() has returned."
        assert assert_data_after[
            "new_id_alive"
        ], "new_id must be alive (=must not be stale) when Lock.migrate_lock() has returned."
    finally:
        # Undecorate
        Lock.migrate_lock = Lock.migrate_lock.__wrapped__
