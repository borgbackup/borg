import argparse
import errno
import io
import json
import os
import random
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from configparser import ConfigParser
from datetime import datetime, timezone, timedelta
from io import BytesIO, StringIO
from unittest.mock import patch

import pytest

import borg
import borg.helpers.errors
from ... import xattr, helpers, platform
from ...archive import Archive
from ...archiver import Archiver, PURE_PYTHON_MSGPACK_WARNING
from ...archiver._common import build_filter
from ...cache import Cache, LocalCache
from ...chunker import has_seek_hole
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey, TAMRequiredError
from ...crypto.file_integrity import FileIntegrityError
from ...helpers import Location, get_security_dir
from ...helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from ...helpers import bin_to_hex
from ...helpers import msgpack
from ...helpers import parse_storage_quota
from ...helpers import flags_noatime, flags_normal
from ...helpers.nanorst import RstToTextLazy, rst_to_terminal
from ...manifest import Manifest, MandatoryFeatureUnsupported
from ...patterns import IECommand, PatternMatcher, parse_pattern
from ...item import Item, chunks_contents_equal
from ...logger import setup_logging
from ...remote import RemoteRepository, PathNotAllowed
from ...repository import Repository
from .. import has_lchflags, llfuse
from .. import BaseTestCase, changedir, environment_variable, no_selinux
from .. import (
    are_symlinks_supported,
    are_hardlinks_supported,
    are_fifos_supported,
    is_utime_fully_supported,
    is_birthtime_fully_supported,
)
from ..platform import fakeroot_detected, is_darwin

RK_ENCRYPTION = "--encryption=repokey-aes-ocb"
KF_ENCRYPTION = "--encryption=keyfile-chacha20-poly1305"

src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

requires_hardlinks = pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")


def exec_cmd(*args, archiver=None, fork=False, exe=None, input=b"", binary_output=False, **kw):
    if fork:
        try:
            if exe is None:
                borg = (sys.executable, "-m", "borg")
            elif isinstance(exe, str):
                borg = (exe,)
            elif not isinstance(exe, tuple):
                raise ValueError("exe must be None, a tuple or a str")
            output = subprocess.check_output(borg + args, stderr=subprocess.STDOUT, input=input)
            ret = 0
        except subprocess.CalledProcessError as e:
            output = e.output
            ret = e.returncode
        except SystemExit as e:  # possibly raised by argparse
            output = ""
            ret = e.code
        if binary_output:
            return ret, output
        else:
            return ret, os.fsdecode(output)
    else:
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = StringIO(input.decode())
            sys.stdin.buffer = BytesIO(input)
            output = BytesIO()
            # Always use utf-8 here, to simply .decode() below
            output_text = sys.stdout = sys.stderr = io.TextIOWrapper(output, encoding="utf-8")
            if archiver is None:
                archiver = Archiver()
            archiver.prerun_checks = lambda *args: None
            archiver.exit_code = EXIT_SUCCESS
            helpers.exit_code = EXIT_SUCCESS
            try:
                args = archiver.parse_args(list(args))
                # argparse parsing may raise SystemExit when the command line is bad or
                # actions that abort early (eg. --help) where given. Catch this and return
                # the error code as-if we invoked a Borg binary.
            except SystemExit as e:
                output_text.flush()
                return e.code, output.getvalue() if binary_output else output.getvalue().decode()
            ret = archiver.run(args)
            output_text.flush()
            return ret, output.getvalue() if binary_output else output.getvalue().decode()
        finally:
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr


# check if the binary "borg.exe" is available (for local testing a symlink to virtualenv/bin/borg should do)
try:
    exec_cmd("help", exe="borg.exe", fork=True)
    BORG_EXES = ["python", "binary"]
except FileNotFoundError:
    BORG_EXES = ["python"]


@pytest.fixture(params=BORG_EXES)
def cmd(request):
    if request.param == "python":
        exe = None
    elif request.param == "binary":
        exe = "borg.exe"
    else:
        raise ValueError("param must be 'python' or 'binary'")

    def exec_fn(*args, **kw):
        return exec_cmd(*args, exe=exe, fork=True, **kw)

    return exec_fn


def test_return_codes(cmd, tmpdir):
    repo = tmpdir.mkdir("repo")
    input = tmpdir.mkdir("input")
    output = tmpdir.mkdir("output")
    input.join("test_file").write("content")
    rc, out = cmd("--repo=%s" % str(repo), "rcreate", "--encryption=none")
    assert rc == EXIT_SUCCESS
    rc, out = cmd("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_SUCCESS
    with changedir(str(output)):
        rc, out = cmd("--repo=%s" % repo, "extract", "archive")
        assert rc == EXIT_SUCCESS
    rc, out = cmd("--repo=%s" % repo, "extract", "archive", "does/not/match")
    assert rc == EXIT_WARNING  # pattern did not match
    rc, out = cmd("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_ERROR  # duplicate archive name


"""
test_disk_full is very slow and not recommended to be included in daily testing.
for this test, an empty, writable 16MB filesystem mounted on DF_MOUNT is required.
for speed and other reasons, it is recommended that the underlying block device is
in RAM, not a magnetic or flash disk.

assuming /tmp is a tmpfs (in memory filesystem), one can use this:
dd if=/dev/zero of=/tmp/borg-disk bs=16M count=1
mkfs.ext4 /tmp/borg-disk
mkdir /tmp/borg-mount
sudo mount /tmp/borg-disk /tmp/borg-mount

if the directory does not exist, the test will be skipped.
"""
DF_MOUNT = "/tmp/borg-mount"


@pytest.mark.skipif(not os.path.exists(DF_MOUNT), reason="needs a 16MB fs mounted on %s" % DF_MOUNT)
def test_disk_full(cmd):
    def make_files(dir, count, size, rnd=True):
        shutil.rmtree(dir, ignore_errors=True)
        os.mkdir(dir)
        if rnd:
            count = random.randint(1, count)
            if size > 1:
                size = random.randint(1, size)
        for i in range(count):
            fn = os.path.join(dir, "file%03d" % i)
            with open(fn, "wb") as f:
                data = os.urandom(size)
                f.write(data)

    with environment_variable(BORG_CHECK_I_KNOW_WHAT_I_AM_DOING="YES"):
        mount = DF_MOUNT
        assert os.path.exists(mount)
        repo = os.path.join(mount, "repo")
        input = os.path.join(mount, "input")
        reserve = os.path.join(mount, "reserve")
        for j in range(100):
            shutil.rmtree(repo, ignore_errors=True)
            shutil.rmtree(input, ignore_errors=True)
            # keep some space and some inodes in reserve that we can free up later:
            make_files(reserve, 80, 100000, rnd=False)
            rc, out = cmd(f"--repo={repo}", "rcreate")
            if rc != EXIT_SUCCESS:
                print("rcreate", rc, out)
            assert rc == EXIT_SUCCESS
            try:
                success, i = True, 0
                while success:
                    i += 1
                    try:
                        make_files(input, 20, 200000)
                    except OSError as err:
                        if err.errno == errno.ENOSPC:
                            # already out of space
                            break
                        raise
                    try:
                        rc, out = cmd("--repo=%s" % repo, "create", "test%03d" % i, input)
                        success = rc == EXIT_SUCCESS
                        if not success:
                            print("create", rc, out)
                    finally:
                        # make sure repo is not locked
                        shutil.rmtree(os.path.join(repo, "lock.exclusive"), ignore_errors=True)
                        os.remove(os.path.join(repo, "lock.roster"))
            finally:
                # now some error happened, likely we are out of disk space.
                # free some space so we can expect borg to be able to work normally:
                shutil.rmtree(reserve, ignore_errors=True)
            rc, out = cmd(f"--repo={repo}", "rlist")
            if rc != EXIT_SUCCESS:
                print("rlist", rc, out)
            rc, out = cmd(f"--repo={repo}", "check", "--repair")
            if rc != EXIT_SUCCESS:
                print("check", rc, out)
            assert rc == EXIT_SUCCESS


def checkts(ts):
    # check if the timestamp is in the expected format
    assert datetime.strptime(ts, ISO_FORMAT + "%z")  # must not raise


class ArchiverTestCaseBase(BaseTestCase):
    EXE: str = None  # python source based
    FORK_DEFAULT = False
    prefix = ""

    def setUp(self):
        os.environ["BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"] = "YES"
        os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
        os.environ["BORG_PASSPHRASE"] = "waytooeasyonlyfortests"
        os.environ["BORG_SELFTEST"] = "disabled"
        self.archiver = not self.FORK_DEFAULT and Archiver() or None
        self.tmpdir = tempfile.mkdtemp()
        self.repository_path = os.path.join(self.tmpdir, "repository")
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, "input")
        self.output_path = os.path.join(self.tmpdir, "output")
        self.keys_path = os.path.join(self.tmpdir, "keys")
        self.cache_path = os.path.join(self.tmpdir, "cache")
        self.exclude_file_path = os.path.join(self.tmpdir, "excludes")
        self.patterns_file_path = os.path.join(self.tmpdir, "patterns")
        os.environ["BORG_KEYS_DIR"] = self.keys_path
        os.environ["BORG_CACHE_DIR"] = self.cache_path
        os.mkdir(self.input_path)
        os.chmod(self.input_path, 0o777)  # avoid troubles with fakeroot / FUSE
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"input/file2\n# A comment line, then a blank line\n\n")
        with open(self.patterns_file_path, "wb") as fd:
            fd.write(b"+input/file_important\n- input/file*\n# A comment line, then a blank line\n\n")
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._old_wd)
        # note: ignore_errors=True as workaround for issue #862
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        setup_logging()

    def cmd(self, *args, **kw):
        exit_code = kw.pop("exit_code", 0)
        fork = kw.pop("fork", None)
        binary_output = kw.get("binary_output", False)
        if fork is None:
            fork = self.FORK_DEFAULT
        ret, output = exec_cmd(*args, fork=fork, exe=self.EXE, archiver=self.archiver, **kw)
        if ret != exit_code:
            print(output)
        self.assert_equal(ret, exit_code)
        # if tests are run with the pure-python msgpack, there will be warnings about
        # this in the output, which would make a lot of tests fail.
        pp_msg = PURE_PYTHON_MSGPACK_WARNING.encode() if binary_output else PURE_PYTHON_MSGPACK_WARNING
        empty = b"" if binary_output else ""
        output = empty.join(line for line in output.splitlines(keepends=True) if pp_msg not in line)
        return output

    def create_src_archive(self, name):
        self.cmd(f"--repo={self.repository_location}", "create", "--compression=lz4", name, src_dir)

    def open_archive(self, name):
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(manifest, name)
        return archive, repository

    def open_repository(self):
        return Repository(self.repository_path, exclusive=True)

    def create_regular_file(self, name, size=0, contents=None):
        assert not (size != 0 and contents and len(contents) != size), "size and contents do not match"
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, "wb") as fd:
            if contents is None:
                contents = b"X" * size
            fd.write(contents)

    def create_test_files(self, create_hardlinks=True):
        """Create a minimal test case including all supported file types"""
        # File
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("flagfile", size=1024)
        # Directory
        self.create_regular_file("dir2/file2", size=1024 * 80)
        # File mode
        os.chmod("input/file1", 0o4755)
        # Hard link
        if are_hardlinks_supported() and create_hardlinks:
            os.link(os.path.join(self.input_path, "file1"), os.path.join(self.input_path, "hardlink"))
        # Symlink
        if are_symlinks_supported():
            os.symlink("somewhere", os.path.join(self.input_path, "link1"))
        self.create_regular_file("fusexattr", size=1)
        if not xattr.XATTR_FAKEROOT and xattr.is_enabled(self.input_path):
            fn = os.fsencode(os.path.join(self.input_path, "fusexattr"))
            # ironically, due to the way how fakeroot works, comparing FUSE file xattrs to orig file xattrs
            # will FAIL if fakeroot supports xattrs, thus we only set the xattr if XATTR_FAKEROOT is False.
            # This is because fakeroot with xattr-support does not propagate xattrs of the underlying file
            # into "fakeroot space". Because the xattrs exposed by borgfs are these of an underlying file
            # (from fakeroots point of view) they are invisible to the test process inside the fakeroot.
            xattr.setxattr(fn, b"user.foo", b"bar")
            xattr.setxattr(fn, b"user.empty", b"")
            # XXX this always fails for me
            # ubuntu 14.04, on a TMP dir filesystem with user_xattr, using fakeroot
            # same for newer ubuntu and centos.
            # if this is supported just on specific platform, platform should be checked first,
            # so that the test setup for all tests using it does not fail here always for others.
            # xattr.setxattr(os.path.join(self.input_path, 'link1'), b'user.foo_symlink', b'bar_symlink', follow_symlinks=False)
        # FIFO node
        if are_fifos_supported():
            os.mkfifo(os.path.join(self.input_path, "fifo1"))
        if has_lchflags:
            platform.set_flags(os.path.join(self.input_path, "flagfile"), stat.UF_NODUMP)
        try:
            # Block device
            os.mknod("input/bdev", 0o600 | stat.S_IFBLK, os.makedev(10, 20))
            # Char device
            os.mknod("input/cdev", 0o600 | stat.S_IFCHR, os.makedev(30, 40))
            # File mode
            os.chmod("input/dir2", 0o555)  # if we take away write perms, we need root to remove contents
            # File owner
            os.chown("input/file1", 100, 200)  # raises OSError invalid argument on cygwin
            have_root = True  # we have (fake)root
        except PermissionError:
            have_root = False
        except OSError as e:
            # Note: ENOSYS "Function not implemented" happens as non-root on Win 10 Linux Subsystem.
            if e.errno not in (errno.EINVAL, errno.ENOSYS):
                raise
            have_root = False
        time.sleep(1)  # "empty" must have newer timestamp than other files
        self.create_regular_file("empty", size=0)
        return have_root

    def _extract_repository_id(self, path):
        with Repository(self.repository_path) as repository:
            return repository.id

    def _set_repository_id(self, path, id):
        config = ConfigParser(interpolation=None)
        config.read(os.path.join(path, "config"))
        config.set("repository", "id", bin_to_hex(id))
        with open(os.path.join(path, "config"), "w") as fd:
            config.write(fd)
        with Repository(self.repository_path) as repository:
            return repository.id

    def _extract_hardlinks_setup(self):
        os.mkdir(os.path.join(self.input_path, "dir1"))
        os.mkdir(os.path.join(self.input_path, "dir1/subdir"))

        self.create_regular_file("source", contents=b"123456")
        os.link(os.path.join(self.input_path, "source"), os.path.join(self.input_path, "abba"))
        os.link(os.path.join(self.input_path, "source"), os.path.join(self.input_path, "dir1/hardlink"))
        os.link(os.path.join(self.input_path, "source"), os.path.join(self.input_path, "dir1/subdir/hardlink"))

        self.create_regular_file("dir1/source2")
        os.link(os.path.join(self.input_path, "dir1/source2"), os.path.join(self.input_path, "dir1/aaaa"))

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

    def _create_test_caches(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("cache1/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        self.create_regular_file("cache2/%s" % CACHE_TAG_NAME, contents=b"invalid signature")
        os.mkdir("input/cache3")
        if are_hardlinks_supported():
            os.link("input/cache1/%s" % CACHE_TAG_NAME, "input/cache3/%s" % CACHE_TAG_NAME)
        else:
            self.create_regular_file("cache3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")

    def _assert_test_caches(self):
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["cache2", "file1"])
        self.assert_equal(sorted(os.listdir("output/input/cache2")), [CACHE_TAG_NAME])

    def _create_test_tagged(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("tagged1/.NOBACKUP")
        self.create_regular_file("tagged2/00-NOBACKUP")
        self.create_regular_file("tagged3/.NOBACKUP/file2", size=1024)

    def _assert_test_tagged(self):
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1"])

    def _create_test_keep_tagged(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file0", size=1024)
        self.create_regular_file("tagged1/.NOBACKUP1")
        self.create_regular_file("tagged1/file1", size=1024)
        self.create_regular_file("tagged2/.NOBACKUP2/subfile1", size=1024)
        self.create_regular_file("tagged2/file2", size=1024)
        self.create_regular_file("tagged3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        self.create_regular_file("tagged3/file3", size=1024)
        self.create_regular_file("taggedall/.NOBACKUP1")
        self.create_regular_file("taggedall/.NOBACKUP2/subfile1", size=1024)
        self.create_regular_file("taggedall/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        self.create_regular_file("taggedall/file4", size=1024)

    def _assert_test_keep_tagged(self):
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file0", "tagged1", "tagged2", "tagged3", "taggedall"])
        self.assert_equal(os.listdir("output/input/tagged1"), [".NOBACKUP1"])
        self.assert_equal(os.listdir("output/input/tagged2"), [".NOBACKUP2"])
        self.assert_equal(os.listdir("output/input/tagged3"), [CACHE_TAG_NAME])
        self.assert_equal(sorted(os.listdir("output/input/taggedall")), [".NOBACKUP1", ".NOBACKUP2", CACHE_TAG_NAME])

    def check_cache(self):
        # First run a regular borg check
        self.cmd(f"--repo={self.repository_location}", "check")
        # Then check that the cache on disk matches exactly what's in the repo.
        with self.open_repository() as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest, sync=False) as cache:
                original_chunks = cache.chunks
            Cache.destroy(repository)
            with Cache(repository, manifest) as cache:
                correct_chunks = cache.chunks
        assert original_chunks is not correct_chunks
        seen = set()
        for id, (refcount, size) in correct_chunks.iteritems():
            o_refcount, o_size = original_chunks[id]
            assert refcount == o_refcount
            assert size == o_size
            seen.add(id)
        for id, (refcount, size) in original_chunks.iteritems():
            assert id in seen


class ArchiverTestCase(ArchiverTestCaseBase):
    def get_security_dir(self):
        repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
        return get_security_dir(repository_id)

    def test_basic_functionality(self):
        have_root = self.create_test_files()
        # fork required to test show-rc output
        output = self.cmd(
            f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION, "--show-version", "--show-rc", fork=True
        )
        self.assert_in("borgbackup version", output)
        self.assert_in("terminating with success status, rc 0", output)
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude-nodump", "test", "input")
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--exclude-nodump", "--stats", "test.2", "input"
        )
        self.assert_in("Archive name: test.2", output)
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        list_output = self.cmd(f"--repo={self.repository_location}", "rlist", "--short")
        self.assert_in("test", list_output)
        self.assert_in("test.2", list_output)
        expected = [
            "input",
            "input/bdev",
            "input/cdev",
            "input/dir2",
            "input/dir2/file2",
            "input/empty",
            "input/file1",
            "input/flagfile",
        ]
        if are_fifos_supported():
            expected.append("input/fifo1")
        if are_symlinks_supported():
            expected.append("input/link1")
        if are_hardlinks_supported():
            expected.append("input/hardlink")
        if not have_root:
            # we could not create these device files without (fake)root
            expected.remove("input/bdev")
            expected.remove("input/cdev")
        if has_lchflags:
            # remove the file we did not backup, so input and output become equal
            expected.remove("input/flagfile")  # this file is UF_NODUMP
            os.remove(os.path.join("input", "flagfile"))
        list_output = self.cmd(f"--repo={self.repository_location}", "list", "test", "--short")
        for name in expected:
            self.assert_in(name, list_output)
        self.assert_dirs_equal("input", "output/input")
        info_output = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")
        item_count = 5 if has_lchflags else 6  # one file is UF_NODUMP
        self.assert_in("Number of files: %d" % item_count, info_output)
        shutil.rmtree(self.cache_path)
        info_output2 = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")

        def filter(output):
            # filter for interesting "info" output, ignore cache rebuilding related stuff
            prefixes = ["Name:", "Fingerprint:", "Number of files:", "This archive:", "All archives:", "Chunk index:"]
            result = []
            for line in output.splitlines():
                for prefix in prefixes:
                    if line.startswith(prefix):
                        result.append(line)
            return "\n".join(result)

        # the interesting parts of info_output2 and info_output should be same
        self.assert_equal(filter(info_output), filter(info_output2))

    @requires_hardlinks
    def test_create_duplicate_root(self):
        # setup for #5603
        path_a = os.path.join(self.input_path, "a")
        path_b = os.path.join(self.input_path, "b")
        os.mkdir(path_a)
        os.mkdir(path_b)
        hl_a = os.path.join(path_a, "hardlink")
        hl_b = os.path.join(path_b, "hardlink")
        self.create_regular_file(hl_a, contents=b"123456")
        os.link(hl_a, hl_b)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "input")  # give input twice!
        # test if created archive has 'input' contents twice:
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        # we have all fs items exactly once!
        assert sorted(paths) == ["input", "input/a", "input/a/hardlink", "input/b", "input/b/hardlink"]

    def test_init_parent_dirs(self):
        parent_path = os.path.join(self.tmpdir, "parent1", "parent2")
        repository_path = os.path.join(parent_path, "repository")
        repository_location = self.prefix + repository_path
        with pytest.raises(Repository.ParentPathDoesNotExist):
            # normal borg init does NOT create missing parent dirs
            self.cmd(f"--repo={repository_location}", "rcreate", "--encryption=none")
        # but if told so, it does:
        self.cmd(f"--repo={repository_location}", "rcreate", "--encryption=none", "--make-parent-dirs")
        assert os.path.exists(parent_path)

    def test_unix_socket(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(os.path.join(self.input_path, "unix-socket"))
        except PermissionError as err:
            if err.errno == errno.EPERM:
                pytest.skip("unix sockets disabled or not supported")
            elif err.errno == errno.EACCES:
                pytest.skip("permission denied to create unix sockets")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        sock.close()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert not os.path.exists("input/unix-socket")

    @pytest.mark.skipif(not are_symlinks_supported(), reason="symlinks not supported")
    def test_symlink_extract(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert os.readlink("input/link1") == "somewhere"

    @pytest.mark.skipif(
        not are_symlinks_supported() or not are_hardlinks_supported() or is_darwin,
        reason="symlinks or hardlinks or hardlinked symlinks not supported",
    )
    def test_hardlinked_symlinks_extract(self):
        self.create_regular_file("target", size=1024)
        with changedir("input"):
            os.symlink("target", "symlink1")
            os.link("symlink1", "symlink2", follow_symlinks=False)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test")
            print(output)
            with changedir("input"):
                assert os.path.exists("target")
                assert os.readlink("symlink1") == "target"
                assert os.readlink("symlink2") == "target"
                st1 = os.stat("symlink1", follow_symlinks=False)
                st2 = os.stat("symlink2", follow_symlinks=False)
                assert st1.st_nlink == 2
                assert st2.st_nlink == 2
                assert st1.st_ino == st2.st_ino
                assert st1.st_size == st2.st_size

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    def test_atime(self):
        def has_noatime(some_file):
            atime_before = os.stat(some_file).st_atime_ns
            try:
                with open(os.open(some_file, flags_noatime)) as file:
                    file.read()
            except PermissionError:
                return False
            else:
                atime_after = os.stat(some_file).st_atime_ns
                noatime_used = flags_noatime != flags_normal
                return noatime_used and atime_before == atime_after

        self.create_test_files()
        atime, mtime = 123456780, 234567890
        have_noatime = has_noatime("input/file1")
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--atime", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9
        if have_noatime:
            assert sti.st_atime_ns == sto.st_atime_ns == atime * 1e9
        else:
            # it touched the input file's atime while backing it up
            assert sto.st_atime_ns == atime * 1e9

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    @pytest.mark.skipif(
        not is_birthtime_fully_supported(), reason="cannot properly setup and execute test without birthtime"
    )
    def test_birthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime("input/file1", (atime, birthtime))
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert int(sti.st_birthtime * 1e9) == int(sto.st_birthtime * 1e9) == birthtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    @pytest.mark.skipif(
        not is_birthtime_fully_supported(), reason="cannot properly setup and execute test without birthtime"
    )
    def test_nobirthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime("input/file1", (atime, birthtime))
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--nobirthtime")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert int(sti.st_birthtime * 1e9) == birthtime * 1e9
        assert int(sto.st_birthtime * 1e9) == mtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

    def test_sparse_file(self):
        def is_sparse(fn, total_size, hole_size):
            st = os.stat(fn)
            assert st.st_size == total_size
            sparse = True
            if sparse and hasattr(st, "st_blocks") and st.st_blocks * 512 >= st.st_size:
                sparse = False
            if sparse and has_seek_hole:
                with open(fn, "rb") as fd:
                    # only check if the first hole is as expected, because the 2nd hole check
                    # is problematic on xfs due to its "dynamic speculative EOF preallocation
                    try:
                        if fd.seek(0, os.SEEK_HOLE) != 0:
                            sparse = False
                        if fd.seek(0, os.SEEK_DATA) != hole_size:
                            sparse = False
                    except OSError:
                        # OS/FS does not really support SEEK_HOLE/SEEK_DATA
                        sparse = False
            return sparse

        filename = os.path.join(self.input_path, "sparse")
        content = b"foobar"
        hole_size = 5 * (1 << CHUNK_MAX_EXP)  # 5 full chunker buffers
        total_size = hole_size + len(content) + hole_size
        with open(filename, "wb") as fd:
            # create a file that has a hole at the beginning and end (if the
            # OS and filesystem supports sparse files)
            fd.seek(hole_size, 1)
            fd.write(content)
            fd.seek(hole_size, 1)
            pos = fd.tell()
            fd.truncate(pos)
        # we first check if we could create a sparse input file:
        sparse_support = is_sparse(filename, total_size, hole_size)
        if sparse_support:
            # we could create a sparse input file, so creating a backup of it and
            # extracting it again (as sparse) should also work:
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
            self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
            with changedir(self.output_path):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--sparse")
            self.assert_dirs_equal("input", "output/input")
            filename = os.path.join(self.output_path, "input", "sparse")
            with open(filename, "rb") as fd:
                # check if file contents are as expected
                self.assert_equal(fd.read(hole_size), b"\0" * hole_size)
                self.assert_equal(fd.read(len(content)), content)
                self.assert_equal(fd.read(hole_size), b"\0" * hole_size)
            assert is_sparse(filename, total_size, hole_size)

    def test_unusual_filenames(self):
        filenames = ["normal", "with some blanks", "(with_parens)"]
        for filename in filenames:
            filename = os.path.join(self.input_path, filename)
            with open(filename, "wb"):
                pass
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        for filename in filenames:
            with changedir("output"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", os.path.join("input", filename))
            assert os.path.exists(os.path.join("output", "input", filename))

    def test_repository_swap_detection(self):
        self.create_test_files()
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_swap_detection2(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rcreate", "--encryption=none")
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}_encrypted", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test", "input")
        shutil.rmtree(self.repository_path + "_encrypted")
        os.rename(self.repository_path + "_unencrypted", self.repository_path + "_encrypted")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input")

    def test_repository_swap_detection_no_cache(self):
        self.create_test_files()
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_swap_detection2_no_cache(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rcreate", "--encryption=none")
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}_encrypted", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rdelete", "--cache-only")
        self.cmd(f"--repo={self.repository_location}_encrypted", "rdelete", "--cache-only")
        shutil.rmtree(self.repository_path + "_encrypted")
        os.rename(self.repository_path + "_unencrypted", self.repository_path + "_encrypted")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input")

    def test_repository_swap_detection_repokey_blank_passphrase(self):
        # Check that a repokey repo with a blank passphrase is considered like a plaintext repo.
        self.create_test_files()
        # User initializes her repository with her passphrase
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        # Attacker replaces it with her own repository, which is encrypted but has no passphrase set
        shutil.rmtree(self.repository_path)
        with environment_variable(BORG_PASSPHRASE=""):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
            # Delete cache & security database, AKA switch to user perspective
            self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
            shutil.rmtree(self.get_security_dir())
        with environment_variable(BORG_PASSPHRASE=None):
            # This is the part were the user would be tricked, e.g. she assumes that BORG_PASSPHRASE
            # is set, while it isn't. Previously this raised no warning,
            # since the repository is, technically, encrypted.
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
            else:
                with pytest.raises(Cache.CacheInitAbortedError):
                    self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_move(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        security_dir = self.get_security_dir()
        os.rename(self.repository_path, self.repository_path + "_new")
        with environment_variable(BORG_RELOCATED_REPO_ACCESS_IS_OK="yes"):
            self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        with open(os.path.join(security_dir, "location")) as fd:
            location = fd.read()
            assert location == Location(self.repository_location + "_new").canonical_path()
        # Needs no confirmation anymore
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        shutil.rmtree(self.cache_path)
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        shutil.rmtree(security_dir)
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        for file in ("location", "key-type", "manifest-timestamp"):
            assert os.path.exists(os.path.join(security_dir, file))

    def test_security_dir_compat(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        with open(os.path.join(self.get_security_dir(), "location"), "w") as fd:
            fd.write("something outdated")
        # This is fine, because the cache still has the correct information. security_dir and cache can disagree
        # if older versions are used to confirm a renamed repository.
        self.cmd(f"--repo={self.repository_location}", "rinfo")

    def test_unknown_unencrypted(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        # Ok: repository is known
        self.cmd(f"--repo={self.repository_location}", "rinfo")

        # Ok: repository is still known (through security_dir)
        shutil.rmtree(self.cache_path)
        self.cmd(f"--repo={self.repository_location}", "rinfo")

        # Needs confirmation: cache and security dir both gone (eg. another host or rm -rf ~)
        shutil.rmtree(self.cache_path)
        shutil.rmtree(self.get_security_dir())
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "rinfo", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.CacheInitAbortedError):
                self.cmd(f"--repo={self.repository_location}", "rinfo")
        with environment_variable(BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK="yes"):
            self.cmd(f"--repo={self.repository_location}", "rinfo")

    def test_strip_components(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir/file")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "3")
            assert not os.path.exists("file")
            with self.assert_creates_file("file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "2")
            with self.assert_creates_file("dir/file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "1")
            with self.assert_creates_file("input/dir/file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "0")

    @requires_hardlinks
    def test_extract_hardlinks1(self):
        self._extract_hardlinks_setup()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert os.stat("input/source").st_nlink == 4
            assert os.stat("input/abba").st_nlink == 4
            assert os.stat("input/dir1/hardlink").st_nlink == 4
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 4
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"

    @requires_hardlinks
    def test_extract_hardlinks2(self):
        self._extract_hardlinks_setup()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "2")
            assert os.stat("hardlink").st_nlink == 2
            assert os.stat("subdir/hardlink").st_nlink == 2
            assert open("subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("aaaa").st_nlink == 2
            assert os.stat("source2").st_nlink == 2
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "input/dir1")
            assert os.stat("input/dir1/hardlink").st_nlink == 2
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("input/dir1/aaaa").st_nlink == 2
            assert os.stat("input/dir1/source2").st_nlink == 2

    @requires_hardlinks
    def test_extract_hardlinks_twice(self):
        # setup for #5603
        path_a = os.path.join(self.input_path, "a")
        path_b = os.path.join(self.input_path, "b")
        os.mkdir(path_a)
        os.mkdir(path_b)
        hl_a = os.path.join(path_a, "hardlink")
        hl_b = os.path.join(path_b, "hardlink")
        self.create_regular_file(hl_a, contents=b"123456")
        os.link(hl_a, hl_b)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "input")  # give input twice!
        # now test extraction
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            # if issue #5603 happens, extraction gives rc == 1 (triggering AssertionError) and warnings like:
            # input/a/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/a/hardlink'
            # input/b/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/b/hardlink'
            # otherwise, when fixed, the hardlinks should be there and have a link count of 2
            assert os.stat("input/a/hardlink").st_nlink == 2
            assert os.stat("input/b/hardlink").st_nlink == 2

    def test_extract_include_exclude(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude=input/file4", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "input/file1")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1"])
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--exclude=input/file2")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file3"])
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file3"])

    def test_extract_include_exclude_regex(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        # Create with regular expression exclusion for file4
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude=re:input/file4$", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333"])
        shutil.rmtree("output/input")

        # Extract with regular expression exclusion
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--exclude=re:file3+")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Combine --exclude with fnmatch and regular expression
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--exclude=input/file2",
                "--exclude=re:file[01]",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file3", "file333"])
        shutil.rmtree("output/input")

        # Combine --exclude-from and regular expression exclusion
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--exclude-from=" + self.exclude_file_path,
                "--exclude=re:file1",
                "--exclude=re:file(\\d)\\1\\1$",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file3"])

    def test_extract_include_exclude_regex_from_file(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)
        self.create_regular_file("aa:something", size=1024 * 80)

        # Create while excluding using mixed pattern styles
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:input/file4$\n")
            fd.write(b"fm:*aa:*thing\n")

        self.cmd(
            f"--repo={self.repository_location}", "create", "--exclude-from=" + self.exclude_file_path, "test", "input"
        )
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333"])
        shutil.rmtree("output/input")

        # Exclude using regular expression
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:file3+\n")

        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Mixed exclude pattern styles
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:file(\\d)\\1\\1$\n")
            fd.write(b"fm:nothingwillmatchthis\n")
            fd.write(b"*/file1\n")
            fd.write(b"re:file2$\n")

        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file3"])

    def test_extract_with_pattern(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        # Extract everything with regular expression
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "re:.*")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333", "file4"])
        shutil.rmtree("output/input")

        # Extract with pattern while also excluding files
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "--exclude=re:file[34]$", "test", r"re:file\d$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Combine --exclude with pattern for extraction
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "--exclude=input/file1", "test", "re:file[12]$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file2"])
        shutil.rmtree("output/input")

        # Multiple pattern
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "fm:input/file1", "fm:*file33*", "input/file2"
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file333"])

    def test_extract_list_output(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file", size=1024 * 80)

        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_not_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--info")
        self.assert_not_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--list")
        self.assert_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--list", "--info")
        self.assert_in("input/file", output)

    def test_extract_progress(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--progress")
            assert "Extracting:" in output

    def test_create_stdin(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        input_data = b"\x00foo\n\nbar\n   \n"
        self.cmd(f"--repo={self.repository_location}", "create", "test", "-", input=input_data)
        item = json.loads(self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines"))
        assert item["uid"] == 0
        assert item["gid"] == 0
        assert item["size"] == len(input_data)
        assert item["path"] == "stdin"
        extracted_data = self.cmd(
            f"--repo={self.repository_location}", "extract", "test", "--stdout", binary_output=True
        )
        assert extracted_data == input_data

    def test_create_content_from_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        input_data = "some test content"
        name = "a/b/c"
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--stdin-name",
            name,
            "--content-from-command",
            "test",
            "--",
            "echo",
            input_data,
        )
        item = json.loads(self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines"))
        assert item["uid"] == 0
        assert item["gid"] == 0
        assert item["size"] == len(input_data) + 1  # `echo` adds newline
        assert item["path"] == name
        extracted_data = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--stdout")
        assert extracted_data == input_data + "\n"

    def test_create_content_from_command_with_failed_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--content-from-command",
            "test",
            "--",
            "sh",
            "-c",
            "exit 73;",
            exit_code=2,
        )
        assert output.endswith("Command 'sh' exited with status 73\n")
        archive_list = json.loads(self.cmd(f"--repo={self.repository_location}", "rlist", "--json"))
        assert archive_list["archives"] == []

    def test_create_content_from_command_missing_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "--content-from-command", exit_code=2)
        assert output.endswith("No command given.\n")

    def test_create_paths_from_stdin(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir1/file2", size=1024 * 80)
        self.create_regular_file("dir1/file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)

        input_data = b"input/file1\0input/dir1\0input/file4"
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "--paths-from-stdin",
            "--paths-delimiter",
            "\\0",
            input=input_data,
        )
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        assert paths == ["input/file1", "input/dir1", "input/file4"]

    def test_create_paths_from_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)

        input_data = "input/file1\ninput/file2\ninput/file3"
        self.cmd(
            f"--repo={self.repository_location}", "create", "--paths-from-command", "test", "--", "echo", input_data
        )
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        assert paths == ["input/file1", "input/file2", "input/file3"]

    def test_create_paths_from_command_with_failed_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--paths-from-command",
            "test",
            "--",
            "sh",
            "-c",
            "exit 73;",
            exit_code=2,
        )
        assert output.endswith("Command 'sh' exited with status 73\n")
        archive_list = json.loads(self.cmd(f"--repo={self.repository_location}", "rlist", "--json"))
        assert archive_list["archives"] == []

    def test_create_paths_from_command_missing_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "--paths-from-command", exit_code=2)
        assert output.endswith("No command given.\n")

    def test_create_without_root(self):
        """test create without a root"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", exit_code=2)

    def test_create_pattern_root(self):
        """test create with only a root pattern"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "-v", "--list", "--pattern=R input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)

    def test_create_pattern(self):
        """test file patterns during create"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--pattern=+input/file_important",
            "--pattern=-input/file*",
            "test",
            "input",
        )
        self.assert_in("A input/file_important", output)
        self.assert_in("x input/file1", output)
        self.assert_in("x input/file2", output)

    def test_create_pattern_file(self):
        """test file patterns during create"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("otherfile", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--pattern=-input/otherfile",
            "--patterns-from=" + self.patterns_file_path,
            "test",
            "input",
        )
        self.assert_in("A input/file_important", output)
        self.assert_in("x input/file1", output)
        self.assert_in("x input/file2", output)
        self.assert_in("x input/otherfile", output)

    def test_create_pattern_exclude_folder_but_recurse(self):
        """test when patterns exclude a parent folder, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/b\n- input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        self.create_regular_file("y/foo_y", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--patterns-from=" + self.patterns_file_path2,
            "test",
            "input",
        )
        self.assert_in("x input/x/a/foo_a", output)
        self.assert_in("A input/x/b/foo_b", output)
        self.assert_in("A input/y/foo_y", output)

    def test_create_pattern_exclude_folder_no_recurse(self):
        """test when patterns exclude a parent folder and, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/b\n! input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        self.create_regular_file("y/foo_y", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--patterns-from=" + self.patterns_file_path2,
            "test",
            "input",
        )
        self.assert_not_in("input/x/a/foo_a", output)
        self.assert_not_in("input/x/a", output)
        self.assert_in("A input/y/foo_y", output)

    def test_create_pattern_intermediate_folders_first(self):
        """test that intermediate folders appear first when patterns exclude a parent folder but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/a\n+ input/x/b\n- input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        with changedir("input"):
            self.cmd(
                f"--repo={self.repository_location}",
                "create",
                "--patterns-from=" + self.patterns_file_path2,
                "test",
                ".",
            )

        # list the archive and verify that the "intermediate" folders appear before
        # their contents
        out = self.cmd(f"--repo={self.repository_location}", "list", "test", "--format", "{type} {path}{NL}")
        out_list = out.splitlines()

        self.assert_in("d x/a", out_list)
        self.assert_in("d x/b", out_list)

        assert out_list.index("d x/a") < out_list.index("- x/a/foo_a")
        assert out_list.index("d x/b") < out_list.index("- x/b/foo_b")

    def test_create_no_cache_sync(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        create_json = json.loads(
            self.cmd(
                f"--repo={self.repository_location}", "create", "--no-cache-sync", "--json", "--error", "test", "input"
            )
        )  # ignore experimental warning
        info_json = json.loads(self.cmd(f"--repo={self.repository_location}", "info", "-a", "test", "--json"))
        create_stats = create_json["cache"]["stats"]
        info_stats = info_json["cache"]["stats"]
        assert create_stats == info_stats
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        self.cmd(f"--repo={self.repository_location}", "create", "--no-cache-sync", "test2", "input")
        self.cmd(f"--repo={self.repository_location}", "rinfo")
        self.cmd(f"--repo={self.repository_location}", "check")

    def test_create_archivename_with_placeholder(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        ts = "1999-12-31T23:59:59"
        name_given = "test-{now}"  # placeholder in archive name gets replaced by borg
        name_expected = f"test-{ts}"  # placeholder in f-string gets replaced by python
        self.cmd(f"--repo={self.repository_location}", "create", f"--timestamp={ts}", name_given, "input")
        list_output = self.cmd(f"--repo={self.repository_location}", "rlist", "--short")
        assert name_expected in list_output

    def test_extract_pattern_opt(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--pattern=+input/file_important",
                "--pattern=-input/file*",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file_important"])

    def test_exclude_caches(self):
        self._create_test_caches()
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--exclude-caches")
        self._assert_test_caches()

    def test_exclude_tagged(self):
        self._create_test_tagged()
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "input",
            "--exclude-if-present",
            ".NOBACKUP",
            "--exclude-if-present",
            "00-NOBACKUP",
        )
        self._assert_test_tagged()

    def test_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "input",
            "--exclude-if-present",
            ".NOBACKUP1",
            "--exclude-if-present",
            ".NOBACKUP2",
            "--exclude-caches",
            "--keep-exclude-tags",
        )
        self._assert_test_keep_tagged()

    @pytest.mark.skipif(not xattr.XATTR_FAKEROOT, reason="Linux capabilities test, requires fakeroot >= 1.20.2")
    def test_extract_capabilities(self):
        fchown = os.fchown

        # We need to manually patch chown to get the behaviour Linux has, since fakeroot does not
        # accurately model the interaction of chown(2) and Linux capabilities, i.e. it does not remove them.
        def patched_fchown(fd, uid, gid):
            xattr.setxattr(fd, b"security.capability", b"", follow_symlinks=False)
            fchown(fd, uid, gid)

        # The capability descriptor used here is valid and taken from a /usr/bin/ping
        capabilities = b"\x01\x00\x00\x02\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"security.capability", capabilities)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(os, "fchown", patched_fchown):
                self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert xattr.getxattr(b"input/file", b"security.capability") == capabilities

    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_extract_xattrs_errors(self):
        def patched_setxattr_E2BIG(*args, **kwargs):
            raise OSError(errno.E2BIG, "E2BIG")

        def patched_setxattr_ENOTSUP(*args, **kwargs):
            raise OSError(errno.ENOTSUP, "ENOTSUP")

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"user.attribute", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            input_abspath = os.path.abspath("input/file")
            with patch.object(xattr, "setxattr", patched_setxattr_E2BIG):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "too big for this filesystem" in out
                assert "when setting extended attribute user.attribute" in out
            os.remove(input_abspath)
            with patch.object(xattr, "setxattr", patched_setxattr_ENOTSUP):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "ENOTSUP" in out
                assert "when setting extended attribute user.attribute" in out
            os.remove(input_abspath)
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "EACCES" in out
                assert "when setting extended attribute user.attribute" in out
            assert os.path.isfile(input_abspath)

    def test_path_normalization(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir1/dir2/file", size=1024 * 80)
        with changedir("input/dir1/dir2"):
            self.cmd(f"--repo={self.repository_location}", "create", "test", "../../../input/dir1/../dir1/dir2/..")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test")
        self.assert_not_in("..", output)
        self.assert_in(" input/dir1/dir2/file", output)

    def test_exclude_normalization(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        with changedir("input"):
            self.cmd(f"--repo={self.repository_location}", "create", "test1", ".", "--exclude=file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test1")
        self.assert_equal(sorted(os.listdir("output")), ["file2"])
        with changedir("input"):
            self.cmd(f"--repo={self.repository_location}", "create", "test2", ".", "--exclude=./file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test2")
        self.assert_equal(sorted(os.listdir("output")), ["file2"])
        self.cmd(f"--repo={self.repository_location}", "create", "test3", "input", "--exclude=input/./file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test3")
        self.assert_equal(sorted(os.listdir("output/input")), ["file2"])

    def test_repeated_files(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "input")

    def test_overwrite(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir2/file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        # Overwriting regular files and directories should be supported
        os.mkdir("output/input")
        os.mkdir("output/input/file1")
        os.mkdir("output/input/dir2")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_dirs_equal("input", "output/input")
        # But non-empty dirs should fail
        os.unlink("output/input/file1")
        os.mkdir("output/input/file1")
        os.mkdir("output/input/file1/dir")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=1)

    def test_corrupted_repository(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        self.cmd(f"--repo={self.repository_location}", "extract", "test", "--dry-run")
        output = self.cmd(f"--repo={self.repository_location}", "check", "--show-version")
        self.assert_in("borgbackup version", output)  # implied output even without --info given
        self.assert_not_in("Starting repository check", output)  # --info not given for root logger

        name = sorted(os.listdir(os.path.join(self.tmpdir, "repository", "data", "0")), reverse=True)[1]
        with open(os.path.join(self.tmpdir, "repository", "data", "0", name), "r+b") as fd:
            fd.seek(100)
            fd.write(b"XXXX")
        output = self.cmd(f"--repo={self.repository_location}", "check", "--info", exit_code=1)
        self.assert_in("Starting repository check", output)  # --info given for root logger

    @pytest.mark.skipif("BORG_TESTS_IGNORE_MODES" in os.environ, reason="modes unreliable")
    def test_umask(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        mode = os.stat(self.repository_path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_create_dry_run(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--dry-run", "test", "input")
        # Make sure no archive has been created
        with Repository(self.repository_path) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        self.assert_equal(len(manifest.archives), 0)

    def add_unknown_feature(self, operation):
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            manifest.config["feature_flags"] = {operation.value: {"mandatory": ["unknown-feature"]}}
            manifest.write()
            repository.commit(compact=False)

    def cmd_raises_unknown_feature(self, args):
        if self.FORK_DEFAULT:
            self.cmd(*args, exit_code=EXIT_ERROR)
        else:
            with pytest.raises(MandatoryFeatureUnsupported) as excinfo:
                self.cmd(*args)
            assert excinfo.value.args == (["unknown-feature"],)

    def test_unknown_feature_on_create(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.add_unknown_feature(Manifest.Operation.WRITE)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "create", "test", "input"])

    def test_unknown_feature_on_cache_sync(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        self.add_unknown_feature(Manifest.Operation.READ)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "create", "test", "input"])

    def test_unknown_feature_on_change_passphrase(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "key", "change-passphrase"])

    def test_unknown_feature_on_read(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.READ)
        with changedir("output"):
            self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "extract", "test"])

        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "rlist"])
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "info", "-a", "test"])

    def test_unknown_feature_on_rename(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "rename", "test", "other"])

    def test_unknown_feature_on_delete(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.DELETE)
        # delete of an archive raises
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "delete", "-a", "test"])
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "prune", "--keep-daily=3"])
        # delete of the whole repository ignores features
        self.cmd(f"--repo={self.repository_location}", "rdelete")

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_unknown_feature_on_mount(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.READ)
        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        os.mkdir(mountpoint)
        # XXX this might hang if it doesn't raise an error
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}::test", "mount", mountpoint])

    @pytest.mark.allow_cache_wipe
    def test_unknown_mandatory_feature_in_cache(self):
        if self.prefix:
            path_prefix = "ssh://__testsuite__"
        else:
            path_prefix = ""

        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))

        with Repository(self.repository_path, exclusive=True) as repository:
            if path_prefix:
                repository._location = Location(self.repository_location)
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest) as cache:
                cache.begin_txn()
                cache.cache_config.mandatory_features = {"unknown-feature"}
                cache.commit()

        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        else:
            called = False
            wipe_cache_safe = LocalCache.wipe_cache

            def wipe_wrapper(*args):
                nonlocal called
                called = True
                wipe_cache_safe(*args)

            with patch.object(LocalCache, "wipe_cache", wipe_wrapper):
                self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

            assert called

        with Repository(self.repository_path, exclusive=True) as repository:
            if path_prefix:
                repository._location = Location(self.repository_location)
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest) as cache:
                assert cache.cache_config.mandatory_features == set()

    def test_progress_on(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test4", "input", "--progress")
        self.assert_in("\r", output)

    def test_progress_off(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test5", "input")
        self.assert_not_in("\r", output)

    def test_file_status(self):
        """test that various file status show expected results

        clearly incomplete: only tests for the weird "unchanged" status for now"""
        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "test", "input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        # should find first file as unmodified
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "test2", "input")
        self.assert_in("U input/file1", output)
        # this is expected, although surprising, for why, see:
        # https://borgbackup.readthedocs.org/en/latest/faq.html#i-am-seeing-a-added-status-for-a-unchanged-file
        self.assert_in("A input/file2", output)

    def test_file_status_cs_cache_mode(self):
        """test that a changed file with faked "previous" mtime still gets backed up in ctime,size cache_mode"""
        self.create_regular_file("file1", contents=b"123")
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "test1", "input", "--list", "--files-cache=ctime,size"
        )
        # modify file1, but cheat with the mtime (and atime) and also keep same size:
        st = os.stat("input/file1")
        self.create_regular_file("file1", contents=b"321")
        os.utime("input/file1", ns=(st.st_atime_ns, st.st_mtime_ns))
        # this mode uses ctime for change detection, so it should find file1 as modified
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "test2", "input", "--list", "--files-cache=ctime,size"
        )
        self.assert_in("M input/file1", output)

    def test_file_status_ms_cache_mode(self):
        """test that a chmod'ed file with no content changes does not get chunked again in mtime,size cache_mode"""
        self.create_regular_file("file1", size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=mtime,size", "test1", "input"
        )
        # change mode of file1, no content change:
        st = os.stat("input/file1")
        os.chmod("input/file1", st.st_mode ^ stat.S_IRWXO)  # this triggers a ctime change, but mtime is unchanged
        # this mode uses mtime for change detection, so it should find file1 as unmodified
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=mtime,size", "test2", "input"
        )
        self.assert_in("U input/file1", output)

    def test_file_status_rc_cache_mode(self):
        """test that files get rechunked unconditionally in rechunk,ctime cache mode"""
        self.create_regular_file("file1", size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=rechunk,ctime", "test1", "input"
        )
        # no changes here, but this mode rechunks unconditionally
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=rechunk,ctime", "test2", "input"
        )
        self.assert_in("A input/file1", output)

    def test_file_status_excluded(self):
        """test that excluded paths are listed"""

        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        if has_lchflags:
            self.create_regular_file("file3", size=1024 * 80)
            platform.set_flags(os.path.join(self.input_path, "file3"), stat.UF_NODUMP)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "--exclude-nodump", "test", "input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)
        # should find second file as excluded
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test1",
            "input",
            "--list",
            "--exclude-nodump",
            "--exclude",
            "*/file2",
        )
        self.assert_in("U input/file1", output)
        self.assert_in("x input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)

    def test_create_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        create_info = json.loads(self.cmd(f"--repo={self.repository_location}", "create", "--json", "test", "input"))
        # The usual keys
        assert "encryption" in create_info
        assert "repository" in create_info
        assert "cache" in create_info
        assert "last_modified" in create_info["repository"]

        archive = create_info["archive"]
        assert archive["name"] == "test"
        assert isinstance(archive["command_line"], list)
        assert isinstance(archive["duration"], float)
        assert len(archive["id"]) == 64
        assert "stats" in archive

    def test_create_topical(self):
        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # no listing by default
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.assert_not_in("file1", output)
        # shouldn't be listed even if unchanged
        output = self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")
        self.assert_not_in("file1", output)
        # should list the file as unchanged
        output = self.cmd(f"--repo={self.repository_location}", "create", "test1", "input", "--list", "--filter=U")
        self.assert_in("file1", output)
        # should *not* list the file as changed
        output = self.cmd(f"--repo={self.repository_location}", "create", "test2", "input", "--list", "--filter=AM")
        self.assert_not_in("file1", output)
        # change the file
        self.create_regular_file("file1", size=1024 * 100)
        # should list the file as changed
        output = self.cmd(f"--repo={self.repository_location}", "create", "test3", "input", "--list", "--filter=AM")
        self.assert_in("file1", output)

    @pytest.mark.skipif(not are_fifos_supported(), reason="FIFOs not supported")
    def test_create_read_special_symlink(self):
        from threading import Thread

        def fifo_feeder(fifo_fn, data):
            fd = os.open(fifo_fn, os.O_WRONLY)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        data = b"foobar" * 1000

        fifo_fn = os.path.join(self.input_path, "fifo")
        link_fn = os.path.join(self.input_path, "link_fifo")
        os.mkfifo(fifo_fn)
        os.symlink(fifo_fn, link_fn)

        t = Thread(target=fifo_feeder, args=(fifo_fn, data))
        t.start()
        try:
            self.cmd(f"--repo={self.repository_location}", "create", "--read-special", "test", "input/link_fifo")
        finally:
            t.join()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            fifo_fn = "input/link_fifo"
            with open(fifo_fn, "rb") as f:
                extracted_data = f.read()
        assert extracted_data == data

    def test_create_read_special_broken_symlink(self):
        os.symlink("somewhere does not exist", os.path.join(self.input_path, "link"))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--read-special", "test", "input")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test")
        assert "input/link -> somewhere does not exist" in output

    # def test_cmdline_compatibility(self):
    #    self.create_regular_file('file1', size=1024 * 80)
    #    self.cmd(f'--repo={self.repository_location}', 'rcreate', RK_ENCRYPTION)
    #    self.cmd(f'--repo={self.repository_location}', 'create', 'test', 'input')
    #    output = self.cmd('foo', self.repository_location, '--old')
    #    self.assert_in('"--old" has been deprecated. Use "--new" instead', output)

    def test_log_json(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        log = self.cmd(
            f"--repo={self.repository_location}", "create", "test", "input", "--log-json", "--list", "--debug"
        )
        messages = {}  # type -> message, one of each kind
        for line in log.splitlines():
            msg = json.loads(line)
            messages[msg["type"]] = msg

        file_status = messages["file_status"]
        assert "status" in file_status
        assert file_status["path"].startswith("input")

        log_message = messages["log_message"]
        assert isinstance(log_message["time"], float)
        assert log_message["levelname"] == "DEBUG"  # there should only be DEBUG messages
        assert isinstance(log_message["message"], str)

    def test_common_options(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        log = self.cmd(f"--repo={self.repository_location}", "--debug", "create", "test", "input")
        assert "security: read previous location" in log

    def test_break_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "break-lock")

    def test_usage(self):
        self.cmd()
        self.cmd("-h")

    def test_help(self):
        assert "Borg" in self.cmd("help")
        assert "patterns" in self.cmd("help", "patterns")
        assert "creates a new, empty repository" in self.cmd("help", "rcreate")
        assert "positional arguments" not in self.cmd("help", "rcreate", "--epilog-only")
        assert "creates a new, empty repository" not in self.cmd("help", "rcreate", "--usage-only")

    def test_init_interrupt(self):
        def raise_eof(*args, **kwargs):
            raise EOFError

        with patch.object(FlexiKey, "create", raise_eof):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION, exit_code=1)
        assert not os.path.exists(self.repository_location)

    def test_init_requires_encryption_option(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", exit_code=2)

    def test_init_nested_repositories(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}/nested", "rcreate", RK_ENCRYPTION, exit_code=2)
        else:
            with pytest.raises(Repository.AlreadyExists):
                self.cmd(f"--repo={self.repository_location}/nested", "rcreate", RK_ENCRYPTION)

    def test_init_refuse_to_overwrite_keyfile(self):
        """BORG_KEY_FILE=something borg init should quit if "something" already exists.

        See https://github.com/borgbackup/borg/pull/6046"""
        keyfile = os.path.join(self.tmpdir, "keyfile")
        with environment_variable(BORG_KEY_FILE=keyfile):
            self.cmd(f"--repo={self.repository_location}0", "rcreate", KF_ENCRYPTION)
            with open(keyfile) as file:
                before = file.read()
            arg = (f"--repo={self.repository_location}1", "rcreate", KF_ENCRYPTION)
            if self.FORK_DEFAULT:
                self.cmd(*arg, exit_code=2)
            else:
                with pytest.raises(borg.helpers.errors.Error):
                    self.cmd(*arg)
            with open(keyfile) as file:
                after = file.read()
            assert before == after

    def test_check_cache(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with self.open_repository() as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest, sync=False) as cache:
                cache.begin_txn()
                cache.chunks.incref(list(cache.chunks.iteritems())[0][0])
                cache.commit()
        with pytest.raises(AssertionError):
            self.check_cache()

    def test_with_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        lock_path = os.path.join(self.repository_path, "lock.exclusive")
        cmd = "python3", "-c", 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
        self.cmd(f"--repo={self.repository_location}", "with-lock", *cmd, fork=True, exit_code=42)

    def test_bad_filters(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "delete", "--first", "1", "--last", "1", fork=True, exit_code=2)

    def test_benchmark_crud(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        with environment_variable(_BORG_BENCHMARK_CRUD_TEST="YES"):
            self.cmd(f"--repo={self.repository_location}", "benchmark", "crud", self.input_path)

    def test_config(self):
        self.create_test_files()
        os.unlink("input/flagfile")
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "config", "--list")
        self.assert_in("[repository]", output)
        self.assert_in("version", output)
        self.assert_in("segments_per_dir", output)
        self.assert_in("storage_quota", output)
        self.assert_in("append_only", output)
        self.assert_in("additional_free_space", output)
        self.assert_in("id", output)
        self.assert_not_in("last_segment_checked", output)

        output = self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked", exit_code=1)
        self.assert_in("No option ", output)
        self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked", "123")
        output = self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked")
        assert output == "123" + "\n"
        output = self.cmd(f"--repo={self.repository_location}", "config", "--list")
        self.assert_in("last_segment_checked", output)
        self.cmd(f"--repo={self.repository_location}", "config", "--delete", "last_segment_checked")

        for cfg_key, cfg_value in [("additional_free_space", "2G"), ("repository.append_only", "1")]:
            output = self.cmd(f"--repo={self.repository_location}", "config", cfg_key)
            assert output == "0" + "\n"
            self.cmd(f"--repo={self.repository_location}", "config", cfg_key, cfg_value)
            output = self.cmd(f"--repo={self.repository_location}", "config", cfg_key)
            assert output == cfg_value + "\n"
            self.cmd(f"--repo={self.repository_location}", "config", "--delete", cfg_key)
            self.cmd(f"--repo={self.repository_location}", "config", cfg_key, exit_code=1)

        self.cmd(f"--repo={self.repository_location}", "config", "--list", "--delete", exit_code=2)
        self.cmd(f"--repo={self.repository_location}", "config", exit_code=2)
        self.cmd(f"--repo={self.repository_location}", "config", "invalid-option", exit_code=1)

    # derived from test_extract_xattrs_errors()
    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_do_not_fail_when_percent_is_in_xattr_name(self):
        """https://github.com/borgbackup/borg/issues/6063"""

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"user.attribute%p", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)

    # derived from test_extract_xattrs_errors()
    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_do_not_fail_when_percent_is_in_file_name(self):
        """https://github.com/borgbackup/borg/issues/6063"""

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        os.makedirs(os.path.join(self.input_path, "dir%p"))
        xattr.setxattr(b"input/dir%p", b"user.attribute", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)

    def test_do_not_mention_archive_if_you_can_not_find_repo(self):
        """https://github.com/borgbackup/borg/issues/6014"""
        output = self.cmd(
            f"--repo={self.repository_location}-this-repository-does-not-exist",
            "info",
            "-a",
            "test",
            exit_code=2,
            fork=True,
        )
        self.assert_in("this-repository-does-not-exist", output)
        self.assert_not_in("this-repository-does-not-exist::test", output)

    def test_transfer(self):
        def check_repo(repo_option):
            listing = self.cmd(repo_option, "rlist", "--short")
            assert "arch1" in listing
            assert "arch2" in listing
            listing = self.cmd(repo_option, "list", "--short", "arch1")
            assert "file1" in listing
            assert "dir2/file2" in listing
            self.cmd(repo_option, "check")

        self.create_test_files()
        repo1 = f"--repo={self.repository_location}1"
        repo2 = f"--repo={self.repository_location}2"
        other_repo1 = f"--other-repo={self.repository_location}1"

        self.cmd(repo1, "rcreate", RK_ENCRYPTION)
        self.cmd(repo1, "create", "arch1", "input")
        self.cmd(repo1, "create", "arch2", "input")
        check_repo(repo1)

        self.cmd(repo2, "rcreate", RK_ENCRYPTION, other_repo1)
        self.cmd(repo2, "transfer", other_repo1, "--dry-run")
        self.cmd(repo2, "transfer", other_repo1)
        self.cmd(repo2, "transfer", other_repo1, "--dry-run")
        check_repo(repo2)


class ArchiverTestCaseBinaryBase:
    EXE = "borg.exe"
    FORK_DEFAULT = True


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    @unittest.skip("does not raise Exception, but sets rc==2")
    def test_init_parent_dirs(self):
        pass

    @unittest.skip("patches objects")
    def test_init_interrupt(self):
        pass

    @unittest.skip("patches objects")
    def test_extract_capabilities(self):
        pass

    @unittest.skip("patches objects")
    def test_extract_xattrs_errors(self):
        pass

    @unittest.skip("test_basic_functionality seems incompatible with fakeroot and/or the binary.")
    def test_basic_functionality(self):
        pass

    @unittest.skip("test_overwrite seems incompatible with fakeroot and/or the binary.")
    def test_overwrite(self):
        pass

    @unittest.skip("patches objects")
    def test_do_not_fail_when_percent_is_in_xattr_name(self):
        pass

    @unittest.skip("patches objects")
    def test_do_not_fail_when_percent_is_in_file_name(self):
        pass


class ManifestAuthenticationTest(ArchiverTestCaseBase):
    def spoof_manifest(self, repository):
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            cdata = manifest.repo_objs.format(
                Manifest.MANIFEST_ID,
                {},
                msgpack.packb(
                    {
                        "version": 1,
                        "archives": {},
                        "config": {},
                        "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(
                            timespec="microseconds"
                        ),
                    }
                ),
            )
            repository.put(Manifest.MANIFEST_ID, cdata)
            repository.commit(compact=False)

    def test_fresh_init_tam_required(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            cdata = manifest.repo_objs.format(
                Manifest.MANIFEST_ID,
                {},
                msgpack.packb(
                    {
                        "version": 1,
                        "archives": {},
                        "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(
                            timespec="microseconds"
                        ),
                    }
                ),
            )
            repository.put(Manifest.MANIFEST_ID, cdata)
            repository.commit(compact=False)

        with pytest.raises(TAMRequiredError):
            self.cmd(f"--repo={self.repository_location}", "rlist")

    def test_not_required(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("archive1234")
        repository = Repository(self.repository_path, exclusive=True)
        # Manifest must be authenticated now
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--debug")
        assert "archive1234" in output
        assert "TAM-verified manifest" in output
        # Try to spoof / modify pre-1.0.9
        self.spoof_manifest(repository)
        # Fails
        with pytest.raises(TAMRequiredError):
            self.cmd(f"--repo={self.repository_location}", "rlist")


class RemoteArchiverTestCaseBase:
    prefix = "ssh://__testsuite__"

    def open_repository(self):
        return RemoteRepository(Location(self.repository_location))


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    def test_remote_repo_restrict_to_path(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", self.repository_path]):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # restricted to repo directory itself, fail for other directories with same prefix:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", self.repository_path]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}_0", "rcreate", RK_ENCRYPTION)

        # restricted to a completely different path:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo"]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}_1", "rcreate", RK_ENCRYPTION)
        path_prefix = os.path.dirname(self.repository_path)
        # restrict to repo directory's parent directory:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", path_prefix]):
            self.cmd(f"--repo={self.repository_location}_2", "rcreate", RK_ENCRYPTION)
        # restrict to repo directory's parent directory and another directory:
        with patch.object(
            RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo", "--restrict-to-path", path_prefix]
        ):
            self.cmd(f"--repo={self.repository_location}_3", "rcreate", RK_ENCRYPTION)

    def test_remote_repo_restrict_to_repository(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", self.repository_path]):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        parent_path = os.path.join(self.repository_path, "..")
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", parent_path]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

    @unittest.skip("only works locally")
    def test_config(self):
        pass

    @unittest.skip("only works locally")
    def test_migrate_lock_alive(self):
        pass

    def test_remote_repo_strip_components_doesnt_leak(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir/file", contents=b"test file contents 1")
        self.create_regular_file("dir/file2", contents=b"test file contents 2")
        self.create_regular_file("skipped-file1", contents=b"test file contents 3")
        self.create_regular_file("skipped-file2", contents=b"test file contents 4")
        self.create_regular_file("skipped-file3", contents=b"test file contents 5")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        marker = "cached responses left in RemoteRepository"
        with changedir("output"):
            res = self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "3"
            )
            assert marker not in res
            with self.assert_creates_file("file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "2"
                )
                assert marker not in res
            with self.assert_creates_file("dir/file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "1"
                )
                assert marker not in res
            with self.assert_creates_file("input/dir/file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "0"
                )
                assert marker not in res


class ArchiverCorruptionTestCase(ArchiverTestCaseBase):
    def setUp(self):
        super().setUp()
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cache_path = json.loads(self.cmd(f"--repo={self.repository_location}", "rinfo", "--json"))["cache"]["path"]

    def corrupt(self, file, amount=1):
        with open(file, "r+b") as fd:
            fd.seek(-amount, io.SEEK_END)
            corrupted = bytes(255 - c for c in fd.read(amount))
            fd.seek(-amount, io.SEEK_END)
            fd.write(corrupted)

    def test_cache_chunks(self):
        self.corrupt(os.path.join(self.cache_path, "chunks"))

        if self.FORK_DEFAULT:
            out = self.cmd(f"--repo={self.repository_location}", "rinfo", exit_code=2)
            assert "failed integrity check" in out
        else:
            with pytest.raises(FileIntegrityError):
                self.cmd(f"--repo={self.repository_location}", "rinfo")

    def test_cache_files(self):
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.corrupt(os.path.join(self.cache_path, "files"))
        out = self.cmd(f"--repo={self.repository_location}", "create", "test1", "input")
        # borg warns about the corrupt files cache, but then continues without files cache.
        assert "files cache is corrupted" in out

    def test_chunks_archive(self):
        self.cmd(f"--repo={self.repository_location}", "create", "test1", "input")
        # Find ID of test1 so we can corrupt it later :)
        target_id = self.cmd(f"--repo={self.repository_location}", "rlist", "--format={id}{LF}").strip()
        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input")

        # Force cache sync, creating archive chunks of test1 and test2 in chunks.archive.d
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        self.cmd(f"--repo={self.repository_location}", "rinfo", "--json")

        chunks_archive = os.path.join(self.cache_path, "chunks.archive.d")
        assert len(os.listdir(chunks_archive)) == 4  # two archives, one chunks cache and one .integrity file each

        self.corrupt(os.path.join(chunks_archive, target_id + ".compact"))

        # Trigger cache sync by changing the manifest ID in the cache config
        config_path = os.path.join(self.cache_path, "config")
        config = ConfigParser(interpolation=None)
        config.read(config_path)
        config.set("cache", "manifest", bin_to_hex(bytes(32)))
        with open(config_path, "w") as fd:
            config.write(fd)

        # Cache sync notices corrupted archive chunks, but automatically recovers.
        out = self.cmd(f"--repo={self.repository_location}", "create", "-v", "test3", "input", exit_code=1)
        assert "Reading cached archive chunk index for test1" in out
        assert "Cached archive chunk index of test1 is corrupted" in out
        assert "Fetching and building archive index for test1" in out

    def test_old_version_interfered(self):
        # Modify the main manifest ID without touching the manifest ID in the integrity section.
        # This happens if a version without integrity checking modifies the cache.
        config_path = os.path.join(self.cache_path, "config")
        config = ConfigParser(interpolation=None)
        config.read(config_path)
        config.set("cache", "manifest", bin_to_hex(bytes(32)))
        with open(config_path, "w") as fd:
            config.write(fd)

        out = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "Cache integrity data not available: old Borg version modified the cache." in out


def test_get_args():
    archiver = Archiver()
    # everything normal:
    # first param is argv as produced by ssh forced command,
    # second param is like from SSH_ORIGINAL_COMMAND env variable
    args = archiver.get_args(
        ["borg", "serve", "--umask=0027", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], "borg serve --info"
    )
    assert args.func == archiver.do_serve
    assert args.restrict_to_paths == ["/p1", "/p2"]
    assert args.umask == 0o027
    assert args.log_level == "info"
    # similar, but with --restrict-to-repository
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --info --umask=0027",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - break out of path restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], "borg serve --restrict-to-path=/"
    )
    assert args.restrict_to_paths == ["/p1", "/p2"]
    # trying to cheat - break out of repository restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --restrict-to-repository=/",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - break below repository restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --restrict-to-repository=/r1/below",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - try to execute different subcommand
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], f"borg --repo=/ rcreate {RK_ENCRYPTION}"
    )
    assert args.func == archiver.do_serve

    # Check that environment variables in the forced command don't cause issues. If the command
    # were not forced, environment variables would be interpreted by the shell, but this does not
    # happen for forced commands - we get the verbatim command line and need to deal with env vars.
    args = archiver.get_args(["borg", "serve"], "BORG_FOO=bar borg serve --info")
    assert args.func == archiver.do_serve


def test_chunk_content_equal():
    def ccc(a, b):
        chunks_a = [data for data in a]
        chunks_b = [data for data in b]
        compare1 = chunks_contents_equal(iter(chunks_a), iter(chunks_b))
        compare2 = chunks_contents_equal(iter(chunks_b), iter(chunks_a))
        assert compare1 == compare2
        return compare1

    assert ccc([b"1234", b"567A", b"bC"], [b"1", b"23", b"4567A", b"b", b"C"])
    # one iterator exhausted before the other
    assert not ccc([b"12345"], [b"1234", b"56"])
    # content mismatch
    assert not ccc([b"1234", b"65"], [b"1234", b"56"])
    # first is the prefix of second
    assert not ccc([b"1234", b"56"], [b"1234", b"565"])


class TestBuildFilter:
    def test_basic(self):
        matcher = PatternMatcher()
        matcher.add([parse_pattern("included")], IECommand.Include)
        filter = build_filter(matcher, 0)
        assert filter(Item(path="included"))
        assert filter(Item(path="included/file"))
        assert not filter(Item(path="something else"))

    def test_empty(self):
        matcher = PatternMatcher(fallback=True)
        filter = build_filter(matcher, 0)
        assert filter(Item(path="anything"))

    def test_strip_components(self):
        matcher = PatternMatcher(fallback=True)
        filter = build_filter(matcher, strip_components=1)
        assert not filter(Item(path="shallow"))
        assert not filter(Item(path="shallow/"))  # can this even happen? paths are normalized...
        assert filter(Item(path="deep enough/file"))
        assert filter(Item(path="something/dir/file"))


class TestCommonOptions:
    @staticmethod
    def define_common_options(add_common_option):
        add_common_option("-h", "--help", action="help", help="show this help message and exit")
        add_common_option(
            "--critical", dest="log_level", help="foo", action="store_const", const="critical", default="warning"
        )
        add_common_option(
            "--error", dest="log_level", help="foo", action="store_const", const="error", default="warning"
        )
        add_common_option("--append", dest="append", help="foo", action="append", metavar="TOPIC", default=[])
        add_common_option("-p", "--progress", dest="progress", action="store_true", help="foo")
        add_common_option(
            "--lock-wait", dest="lock_wait", type=int, metavar="N", default=1, help="(default: %(default)d)."
        )

    @pytest.fixture
    def basic_parser(self):
        parser = argparse.ArgumentParser(prog="test", description="test parser", add_help=False)
        parser.common_options = Archiver.CommonOptions(
            self.define_common_options, suffix_precedence=("_level0", "_level1")
        )
        return parser

    @pytest.fixture
    def subparsers(self, basic_parser):
        return basic_parser.add_subparsers(title="required arguments", metavar="<command>")

    @pytest.fixture
    def parser(self, basic_parser):
        basic_parser.common_options.add_common_group(basic_parser, "_level0", provide_defaults=True)
        return basic_parser

    @pytest.fixture
    def common_parser(self, parser):
        common_parser = argparse.ArgumentParser(add_help=False, prog="test")
        parser.common_options.add_common_group(common_parser, "_level1")
        return common_parser

    @pytest.fixture
    def parse_vars_from_line(self, parser, subparsers, common_parser):
        subparser = subparsers.add_parser(
            "subcommand",
            parents=[common_parser],
            add_help=False,
            description="foo",
            epilog="bar",
            help="baz",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparser.set_defaults(func=1234)
        subparser.add_argument("--append-only", dest="append_only", action="store_true")

        def parse_vars_from_line(*line):
            print(line)
            args = parser.parse_args(line)
            parser.common_options.resolve(args)
            return vars(args)

        return parse_vars_from_line

    def test_simple(self, parse_vars_from_line):
        assert parse_vars_from_line("--error") == {
            "append": [],
            "lock_wait": 1,
            "log_level": "error",
            "progress": False,
        }

        assert parse_vars_from_line("--error", "subcommand", "--critical") == {
            "append": [],
            "lock_wait": 1,
            "log_level": "critical",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }

        with pytest.raises(SystemExit):
            parse_vars_from_line("--append-only", "subcommand")

        assert parse_vars_from_line("--append=foo", "--append", "bar", "subcommand", "--append", "baz") == {
            "append": ["foo", "bar", "baz"],
            "lock_wait": 1,
            "log_level": "warning",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }

    @pytest.mark.parametrize("position", ("before", "after", "both"))
    @pytest.mark.parametrize("flag,args_key,args_value", (("-p", "progress", True), ("--lock-wait=3", "lock_wait", 3)))
    def test_flag_position_independence(self, parse_vars_from_line, position, flag, args_key, args_value):
        line = []
        if position in ("before", "both"):
            line.append(flag)
        line.append("subcommand")
        if position in ("after", "both"):
            line.append(flag)

        result = {
            "append": [],
            "lock_wait": 1,
            "log_level": "warning",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }
        result[args_key] = args_value

        assert parse_vars_from_line(*line) == result


def test_parse_storage_quota():
    assert parse_storage_quota("50M") == 50 * 1000**2
    with pytest.raises(argparse.ArgumentTypeError):
        parse_storage_quota("5M")


def get_all_parsers():
    """
    Return dict mapping command to parser.
    """
    parser = Archiver(prog="borg").build_parser()
    borgfs_parser = Archiver(prog="borgfs").build_parser()
    parsers = {}

    def discover_level(prefix, parser, Archiver, extra_choices=None):
        choices = {}
        for action in parser._actions:
            if action.choices is not None and "SubParsersAction" in str(action.__class__):
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            discover_level(command + " ", parser, Archiver)
            parsers[command] = parser

    discover_level("", parser, Archiver, {"borgfs": borgfs_parser})
    return parsers


@pytest.mark.parametrize("command, parser", list(get_all_parsers().items()))
def test_help_formatting(command, parser):
    if isinstance(parser.epilog, RstToTextLazy):
        assert parser.epilog.rst


@pytest.mark.parametrize("topic, helptext", list(Archiver.helptext.items()))
def test_help_formatting_helptexts(topic, helptext):
    assert str(rst_to_terminal(helptext))
