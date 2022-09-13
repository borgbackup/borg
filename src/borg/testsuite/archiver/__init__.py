import errno
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from configparser import ConfigParser
from datetime import datetime
from io import BytesIO, StringIO

import pytest

from ... import xattr, helpers, platform
from ...archive import Archive
from ...archiver import Archiver, PURE_PYTHON_MSGPACK_WARNING
from ...archiver._common import build_filter
from ...cache import Cache
from ...constants import *  # NOQA
from ...helpers import Location
from ...helpers import EXIT_SUCCESS
from ...helpers import bin_to_hex
from ...manifest import Manifest
from ...patterns import IECommand, PatternMatcher, parse_pattern
from ...item import Item
from ...logger import setup_logging
from ...remote import RemoteRepository
from ...repository import Repository
from .. import has_lchflags
from .. import BaseTestCase, changedir, environment_variable
from .. import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported

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


class ArchiverTestCaseBinaryBase:
    EXE = "borg.exe"
    FORK_DEFAULT = True


class RemoteArchiverTestCaseBase:
    prefix = "ssh://__testsuite__"

    def open_repository(self):
        return RemoteRepository(Location(self.repository_location))


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
