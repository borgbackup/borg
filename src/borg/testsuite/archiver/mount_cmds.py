import errno
import os
import stat
import sys
import unittest

import pytest

import borg
import borg.helpers.errors
from ... import xattr, platform
from ...constants import *  # NOQA
from ...helpers import flags_noatime, flags_normal
from .. import has_lchflags, llfuse
from .. import changedir, no_selinux
from .. import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported
from ..platform import fakeroot_detected
from . import (
    ArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RemoteArchiverTestCaseBase,
    RK_ENCRYPTION,
    requires_hardlinks,
    BORG_EXES,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    @requires_hardlinks
    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_fuse_mount_hardlinks(self):
        self._extract_hardlinks_setup()
        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        # we need to get rid of permissions checking because fakeroot causes issues with it.
        # On all platforms, borg defaults to "default_permissions" and we need to get rid of it via "ignore_permissions".
        # On macOS (darwin), we additionally need "defer_permissions" to switch off the checks in osxfuse.
        if sys.platform == "darwin":
            ignore_perms = ["-o", "ignore_permissions,defer_permissions"]
        else:
            ignore_perms = ["-o", "ignore_permissions"]
        with self.fuse_mount(
            self.repository_location, mountpoint, "-a", "test", "--strip-components=2", *ignore_perms
        ), changedir(os.path.join(mountpoint, "test")):
            assert os.stat("hardlink").st_nlink == 2
            assert os.stat("subdir/hardlink").st_nlink == 2
            assert open("subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("aaaa").st_nlink == 2
            assert os.stat("source2").st_nlink == 2
        with self.fuse_mount(
            self.repository_location, mountpoint, "input/dir1", "-a", "test", *ignore_perms
        ), changedir(os.path.join(mountpoint, "test")):
            assert os.stat("input/dir1/hardlink").st_nlink == 2
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("input/dir1/aaaa").st_nlink == 2
            assert os.stat("input/dir1/source2").st_nlink == 2
        with self.fuse_mount(self.repository_location, mountpoint, "-a", "test", *ignore_perms), changedir(
            os.path.join(mountpoint, "test")
        ):
            assert os.stat("input/source").st_nlink == 4
            assert os.stat("input/abba").st_nlink == 4
            assert os.stat("input/dir1/hardlink").st_nlink == 4
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 4
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_fuse(self):
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

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_test_files()
        have_noatime = has_noatime("input/file1")
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude-nodump", "--atime", "archive", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude-nodump", "--atime", "archive2", "input")
        if has_lchflags:
            # remove the file we did not backup, so input and output become equal
            os.remove(os.path.join("input", "flagfile"))
        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        # mount the whole repository, archive contents shall show up in archivename subdirs of mountpoint:
        with self.fuse_mount(self.repository_location, mountpoint):
            # flags are not supported by the FUSE mount
            # we also ignore xattrs here, they are tested separately
            self.assert_dirs_equal(
                self.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
            )
            self.assert_dirs_equal(
                self.input_path, os.path.join(mountpoint, "archive2", "input"), ignore_flags=True, ignore_xattrs=True
            )
        with self.fuse_mount(self.repository_location, mountpoint, "-a", "archive"):
            self.assert_dirs_equal(
                self.input_path, os.path.join(mountpoint, "archive", "input"), ignore_flags=True, ignore_xattrs=True
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
                assert sti1.st_atime == sto1.st_atime
            assert sti1.st_ctime == sto1.st_ctime
            assert sti1.st_mtime == sto1.st_mtime
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
                if not xattr.XATTR_FAKEROOT and xattr.is_enabled(self.input_path):
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

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_fuse_versions_view(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("test", contents=b"first")
        if are_hardlinks_supported():
            self.create_regular_file("hardlink1", contents=b"123456")
            os.link("input/hardlink1", "input/hardlink2")
            os.link("input/hardlink1", "input/hardlink3")
        self.cmd(f"--repo={self.repository_location}", "create", "archive1", "input")
        self.create_regular_file("test", contents=b"second")
        self.cmd(f"--repo={self.repository_location}", "create", "archive2", "input")
        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        # mount the whole repository, archive contents shall show up in versioned view:
        with self.fuse_mount(self.repository_location, mountpoint, "-o", "versions"):
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
        with self.fuse_mount(self.repository_location, mountpoint, "-o", "versions", "-e", "input/hardlink1"):
            if are_hardlinks_supported():
                hl2 = os.path.join(mountpoint, "input", "hardlink2", "hardlink2.00001")
                hl3 = os.path.join(mountpoint, "input", "hardlink3", "hardlink3.00001")
                assert os.stat(hl2).st_ino == os.stat(hl3).st_ino
                assert open(hl3, "rb").read() == b"123456"

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_fuse_allow_damaged_files(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("archive")
        # Get rid of a chunk and repair it
        archive, repository = self.open_archive("archive")
        with repository:
            for item in archive.iter_items():
                if item.path.endswith("testsuite/archiver/__init__.py"):
                    repository.delete(item.chunks[-1].id)
                    path = item.path  # store full path for later
                    break
            else:
                assert False  # missed the file
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)

        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        with self.fuse_mount(self.repository_location, mountpoint, "-a", "archive"):
            with pytest.raises(OSError) as excinfo:
                open(os.path.join(mountpoint, "archive", path))
            assert excinfo.value.errno == errno.EIO
        with self.fuse_mount(self.repository_location, mountpoint, "-a", "archive", "-o", "allow_damaged_files"):
            open(os.path.join(mountpoint, "archive", path)).close()

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_fuse_mount_options(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("arch11")
        self.create_src_archive("arch12")
        self.create_src_archive("arch21")
        self.create_src_archive("arch22")

        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        with self.fuse_mount(self.repository_location, mountpoint, "--first=2", "--sort=name"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
        with self.fuse_mount(self.repository_location, mountpoint, "--last=2", "--sort=name"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
        with self.fuse_mount(self.repository_location, mountpoint, "--match-archives=sh:arch1*"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12"]
        with self.fuse_mount(self.repository_location, mountpoint, "--match-archives=sh:arch2*"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch21", "arch22"]
        with self.fuse_mount(self.repository_location, mountpoint, "--match-archives=sh:arch*"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ["arch11", "arch12", "arch21", "arch22"]
        with self.fuse_mount(self.repository_location, mountpoint, "--match-archives=nope"):
            assert sorted(os.listdir(os.path.join(mountpoint))) == []

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_migrate_lock_alive(self):
        """Both old_id and new_id must not be stale during lock migration / daemonization."""
        from functools import wraps
        import pickle
        import traceback

        # Check results are communicated from the borg mount background process
        # to the pytest process by means of a serialized dict object stored in this file.
        assert_data_file = os.path.join(self.tmpdir, "migrate_lock_assert_data.pickle")

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
                except:
                    pass
                try:
                    return migrate_lock(self, old_id, new_id)
                except BaseException as e:
                    assert_data["exception"] = e
                    assert_data["exception.extr_tb"] = traceback.extract_tb(e.__traceback__)
                finally:
                    assert_data["after"].update(
                        {
                            "old_id_alive": platform.process_alive(*old_id),
                            "new_id_alive": platform.process_alive(*new_id),
                        }
                    )
                    try:
                        with open(assert_data_file, "wb") as _out:
                            pickle.dump(assert_data, _out)
                    except:
                        pass

            wrapper.num_calls = 0
            return wrapper

        # Decorate
        borg.locking.Lock.migrate_lock = write_assert_data(borg.locking.Lock.migrate_lock)
        try:
            self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
            self.create_src_archive("arch")
            mountpoint = os.path.join(self.tmpdir, "mountpoint")
            # In order that the decoration is kept for the borg mount process, we must not spawn, but actually fork;
            # not to be confused with the forking in borg.helpers.daemonize() which is done as well.
            with self.fuse_mount(self.repository_location, mountpoint, os_fork=True):
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
            borg.locking.Lock.migrate_lock = borg.locking.Lock.migrate_lock.__wrapped__


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""

    @unittest.skip("only works locally")
    def test_migrate_lock_alive(self):
        pass


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    def test_fuse(self):
        if fakeroot_detected():
            unittest.skip("test_fuse with the binary is not compatible with fakeroot")
        else:
            super().test_fuse()
