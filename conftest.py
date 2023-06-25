import errno
import io
import os
import stat
import subprocess
import sys
import time
from configparser import ConfigParser
from datetime import datetime
from io import StringIO, BytesIO

import pytest

# needed to get pretty assertion failures in unit tests:
from borg import helpers, platform, xattr
from borg.archive import Archive
from borg.cache import Cache
from borg.constants import EXIT_SUCCESS, CACHE_TAG_NAME, CACHE_TAG_CONTENTS, ISO_FORMAT
from borg.helpers import bin_to_hex
from borg.manifest import Manifest
from borg.platformflags import is_win32
from borg.repository import Repository

if hasattr(pytest, "register_assert_rewrite"):
    pytest.register_assert_rewrite("borg.testsuite")


import borg.cache  # noqa: E402
from borg.archiver import Archiver
from borg.logger import setup_logging, flush_logging  # noqa: E402

# Ensure that the loggers exist for all tests
setup_logging()

from borg.testsuite import has_lchflags, has_llfuse, has_pyfuse3, are_fifos_supported, changedir  # noqa: E402
from borg.testsuite import are_symlinks_supported, are_hardlinks_supported, is_utime_fully_supported  # noqa: E402
from borg.testsuite.platform import fakeroot_detected  # noqa: E402


@pytest.fixture(autouse=True)
def clean_env(tmpdir_factory, monkeypatch):
    # also avoid to use anything from the outside environment:
    keys = [key for key in os.environ if key.startswith("BORG_") and key not in ("BORG_FUSE_IMPL",)]
    for key in keys:
        monkeypatch.delenv(key, raising=False)
    # avoid that we access / modify the user's normal .config / .cache directory:
    monkeypatch.setenv("BORG_BASE_DIR", str(tmpdir_factory.mktemp("borg-base-dir")))
    # Speed up tests
    monkeypatch.setenv("BORG_TESTONLY_WEAKEN_KDF", "1")


def pytest_report_header(config, startdir):
    tests = {
        "BSD flags": has_lchflags,
        "fuse2": has_llfuse,
        "fuse3": has_pyfuse3,
        "root": not fakeroot_detected(),
        "symlinks": are_symlinks_supported(),
        "hardlinks": are_hardlinks_supported(),
        "atime/mtime": is_utime_fully_supported(),
        "modes": "BORG_TESTS_IGNORE_MODES" not in os.environ,
    }
    enabled = []
    disabled = []
    for test in tests:
        if tests[test]:
            enabled.append(test)
        else:
            disabled.append(test)
    output = "Tests enabled: " + ", ".join(enabled) + "\n"
    output += "Tests disabled: " + ", ".join(disabled)
    return output


class DefaultPatches:
    def __init__(self, request):
        self.org_cache_wipe_cache = borg.cache.LocalCache.wipe_cache

        def wipe_should_not_be_called(*a, **kw):
            raise AssertionError(
                "Cache wipe was triggered, if this is part of the test add " "@pytest.mark.allow_cache_wipe"
            )

        if "allow_cache_wipe" not in request.keywords:
            borg.cache.LocalCache.wipe_cache = wipe_should_not_be_called
        request.addfinalizer(self.undo)

    def undo(self):
        borg.cache.LocalCache.wipe_cache = self.org_cache_wipe_cache


@pytest.fixture(autouse=True)
def default_patches(request):
    return DefaultPatches(request)


@pytest.fixture(scope="session")
def requires_hardlinks():
    if not are_hardlinks_supported():
        pytest.skip("hardlinks not supported")


@pytest.fixture(autouse=True)
def set_env_variables():
    os.environ["BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_PASSPHRASE"] = "waytooeasyonlyfortests"
    os.environ["BORG_SELFTEST"] = "disabled"


class ArchiverSetup:
    RK_ENCRYPTION = "--encryption=repokey-aes-ocb"
    KF_ENCRYPTION = "--encryption=keyfile-chacha20-poly1305"
    PURE_PYTHON_MSGPACK_WARNING = "Using a pure-python msgpack! This will result in lower performance."

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "src", "borg", "archiver"))
    src_file = "archiver/__init__.py"  # relative path of one file in src_dir

    EXE: str = None  # python source based
    FORK_DEFAULT = False
    prefix = ""

    def __init__(self):
        self.archiver = None
        self.tmpdir = str
        self.repository_path = str
        self.repository_location = str
        self.input_path = str
        self.output_path = str
        self.keys_path = str
        self.cache_path = str
        self.exclude_file_path = str
        self.patterns_file_path = str
        self._old_wd = str


@pytest.fixture(autouse=True)
def archiver_setup(tmp_path):
    archiver = ArchiverSetup()
    archiver.archiver = not archiver.FORK_DEFAULT and Archiver() or None
    archiver.tmpdir = tmp_path
    archiver.repository_path = os.fspath(tmp_path / "repository")
    archiver.repository_location = archiver.prefix + archiver.repository_path
    archiver.input_path = os.fspath(tmp_path / "input")
    archiver.output_path = os.fspath(tmp_path / "output")
    archiver.keys_path = os.fspath(tmp_path / "keys")
    archiver.cache_path = os.fspath(tmp_path / "cache")
    archiver.exclude_file_path = os.fspath(tmp_path / "excludes")
    archiver.patterns_file_path = os.fspath(tmp_path / "patterns")
    os.environ["BORG_KEYS_DIR"] = archiver.keys_path
    os.environ["BORG_CACHE_DIR"] = archiver.cache_path
    os.mkdir(archiver.input_path)
    os.chmod(archiver.input_path, 0o777)  # avoid troubles with fakeroot / FUSE
    os.mkdir(archiver.output_path)
    os.mkdir(archiver.keys_path)
    os.mkdir(archiver.cache_path)
    with open(archiver.exclude_file_path, "wb") as fd:
        fd.write(b"input/file2\n# A comment line, then a blank line\n\n")
    with open(archiver.patterns_file_path, "wb") as fd:
        fd.write(b"+input/file_important\n- input/file*\n# A comment line, then a blank line\n\n")
    archiver._old_wd = os.getcwd()
    os.chdir(archiver.tmpdir)
    yield archiver
    os.chdir(archiver._old_wd)


@pytest.fixture
def cmd_fixture(archiver_setup):
    msgpack_warning = archiver_setup.PURE_PYTHON_MSGPACK_WARNING

    def cmd(*args, **kw):
        exit_code = kw.pop("exit_code", 0)
        fork = kw.pop("fork", None)
        binary_output = kw.get("binary_output", False)
        if fork is None:
            fork = archiver_setup.FORK_DEFAULT
        ret, output = exec_cmd(*args, fork=fork, exe=archiver_setup.EXE, archiver=archiver_setup.archiver, **kw)
        if ret != exit_code:
            print(output)
        assert ret == exit_code
        # if tests are run with the pure-python msgpack, there will be warnings about
        # this in the output, which would make a lot of tests fail.
        pp_msg = msgpack_warning.encode() if binary_output else msgpack_warning
        empty = b"" if binary_output else ""
        output = empty.join(line for line in output.splitlines(keepends=True) if pp_msg not in line)
        return output

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
                # Always use utf-8 here, to .decode() below
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
                try:
                    ret = archiver.run(args)  # calls setup_logging internally
                finally:
                    flush_logging()  # usually done via at exit, but we do not exit here
                output_text.flush()
                return ret, output.getvalue() if binary_output else output.getvalue().decode()
            finally:
                sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr

    return cmd


@pytest.fixture()
def create_src_archive(cmd_fixture, archiver_setup):
    repo_location = archiver_setup.repository_location
    source_dir = archiver_setup.src_dir

    def src_archive(name, ts=None):
        if ts:
            cmd_fixture(f"--repo={repo_location}", "create", "--compression=lz4", f"--timestamp={ts}", name, source_dir)
        else:
            cmd_fixture(f"--repo={repo_location}", "create", "--compression=lz4", name, source_dir)

    return src_archive


@pytest.fixture()
def open_archive(archiver_setup):
    def archive_and_repository(name):
        repo_path = archiver_setup.repository_path
        repository = Repository(repo_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(manifest, name)
        return archive, repository

    return archive_and_repository


@pytest.fixture()
def open_repository(self):
    def repo():
        return Repository(self.repository_path, exclusive=True)

    return repo


@pytest.fixture()
def create_regular_file(archiver_setup):
    def regular_file(name, size=0, contents=None):
        assert not (size != 0 and contents and len(contents) != size), "size and contents do not match"
        filename = os.path.join(str(archiver_setup.input_path), str(name))
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, "wb") as fd:
            if contents is None:
                contents = b"X" * size
            fd.write(contents)

    return regular_file


@pytest.fixture()
def create_test_files(archiver_setup, create_regular_file):
    def test_files(create_hardlinks=True):
        # Create a minimal test case including all supported file types
        input_path = str(archiver_setup.input_path)

        # File
        create_regular_file("file1", size=1024 * 80)
        create_regular_file("flagfile", size=1024)
        # Directory
        create_regular_file("dir2/file2", size=1024 * 80)
        # File mode
        os.chmod("input/file1", 0o4755)
        # Hard link
        if are_hardlinks_supported() and create_hardlinks:
            os.link(os.path.join(input_path, "file1"), os.path.join(input_path, "hardlink"))
        # Symlink
        if are_symlinks_supported():
            os.symlink("somewhere", os.path.join(input_path, "link1"))
        create_regular_file("fusexattr", size=1)
        if not xattr.XATTR_FAKEROOT and xattr.is_enabled(archiver_setup.input_path):
            fn = os.fsencode(os.path.join(input_path, "fusexattr"))
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
        # FIFO node
        if are_fifos_supported():
            os.mkfifo(os.path.join(input_path, "fifo1"))
        if has_lchflags:
            platform.set_flags(os.path.join(input_path, "flagfile"), stat.UF_NODUMP)

        if is_win32:
            have_root = False
        else:
            try:
                # Block device
                os.mknod("input/bdev", 0o600 | stat.S_IFBLK, os.makedev(10, 20))
                # Char device
                os.mknod("input/cdev", 0o600 | stat.S_IFCHR, os.makedev(30, 40))
                # File owner
                os.chown("input/file1", 100, 200)  # raises OSError invalid argument on cygwin
                # File mode
                os.chmod("input/dir2", 0o555)  # if we take away write perms, we need root to remove contents
                have_root = True  # we have (fake)root
            except PermissionError:
                have_root = False
            except OSError as e:
                # Note: ENOSYS "Function not implemented" happens as non-root on Win 10 Linux Subsystem.
                if e.errno not in (errno.EINVAL, errno.ENOSYS):
                    raise
                have_root = False
        time.sleep(1)  # "empty" must have newer timestamp than other files
        create_regular_file("empty", size=0)
        return have_root

    return test_files


@pytest.fixture()
def _extract_repository_id(archiver_setup):
    def extract_repo_id():
        with Repository(archiver_setup.repository_path) as repository:
            return repository.id

    return extract_repo_id


@pytest.fixture()
def _set_repository_id(archiver_setup):
    def set_id(path, id):
        config = ConfigParser(interpolation=None)
        config.read(os.path.join(path, "config"))
        config.set("repository", "id", bin_to_hex(id))
        with open(os.path.join(path, "config"), "w") as fd:
            config.write(fd)
        with Repository(archiver_setup.repository_path) as repository:
            return repository.id

    return set_id


@pytest.fixture()
def _extract_hardlinks_setup(archiver_setup, create_regular_file, cmd_fixture):
    def extract_hardlinks_setup():
        input_path = str(archiver_setup.input_path)
        repository_location = archiver_setup.repository_location

        os.mkdir(os.path.join(input_path, "dir1"))
        os.mkdir(os.path.join(input_path, "dir1/subdir"))

        create_regular_file("source", contents=b"123456")
        os.link(os.path.join(input_path, "source"), os.path.join(input_path, "abba"))
        os.link(os.path.join(input_path, "source"), os.path.join(input_path, "dir1/hardlink"))
        os.link(os.path.join(input_path, "source"), os.path.join(input_path, "dir1/subdir/hardlink"))

        create_regular_file("dir1/source2")
        os.link(os.path.join(input_path, "dir1/source2"), os.path.join(input_path, "dir1/aaaa"))

        cmd_fixture(f"--repo={repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
        cmd_fixture(f"--repo={repository_location}", "create", "test", "input")

    return extract_hardlinks_setup


@pytest.fixture()
def _create_test_caches(archiver_setup, cmd_fixture, create_regular_file):
    def create_test_caches():
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
        create_regular_file("file1", size=1024 * 80)
        create_regular_file("cache1/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        create_regular_file("cache2/%s" % CACHE_TAG_NAME, contents=b"invalid signature")
        os.mkdir("input/cache3")
        if are_hardlinks_supported():
            os.link("input/cache1/%s" % CACHE_TAG_NAME, "input/cache3/%s" % CACHE_TAG_NAME)
        else:
            create_regular_file("cache3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")

    return create_test_caches


@pytest.fixture()
def _assert_test_caches(archiver_setup, cmd_fixture):
    def assert_test_caches():
        with changedir("output"):
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test")
        assert sorted(os.listdir("output/input")) == ["cache2", "file1"]
        assert sorted(os.listdir("output/input/cache2")) == [CACHE_TAG_NAME]

    return assert_test_caches


@pytest.fixture()
def _create_test_tagged(archiver_setup, cmd_fixture, create_regular_file):
    def create_test_tagged():
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
        create_regular_file("file1", size=1024 * 80)
        create_regular_file("tagged1/.NOBACKUP")
        create_regular_file("tagged2/00-NOBACKUP")
        create_regular_file("tagged3/.NOBACKUP/file2", size=1024)

    return create_test_tagged


@pytest.fixture()
def _assert_test_tagged(archiver_setup, cmd_fixture):
    def assert_test_tagged():
        with changedir("output"):
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test")
        assert sorted(os.listdir("output/input")) == ["file1"]

    return assert_test_tagged


@pytest.fixture()
def _create_test_keep_tagged(archiver_setup, cmd_fixture, create_regular_file):
    def create_test_keep_tagged():
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
        create_regular_file("file0", size=1024)
        create_regular_file("tagged1/.NOBACKUP1")
        create_regular_file("tagged1/file1", size=1024)
        create_regular_file("tagged2/.NOBACKUP2/subfile1", size=1024)
        create_regular_file("tagged2/file2", size=1024)
        create_regular_file("tagged3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        create_regular_file("tagged3/file3", size=1024)
        create_regular_file("taggedall/.NOBACKUP1")
        create_regular_file("taggedall/.NOBACKUP2/subfile1", size=1024)
        create_regular_file("taggedall/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
        create_regular_file("taggedall/file4", size=1024)

    return create_test_keep_tagged


@pytest.fixture()
def _assert_test_keep_tagged(archiver_setup, cmd_fixture):
    def assert_test_keep_tagged():
        with changedir("output"):
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test")
        assert sorted(os.listdir("output/input")) == ["file0", "tagged1", "tagged2", "tagged3", "taggedall"]
        assert os.listdir("output/input/tagged1") == [".NOBACKUP1"]
        assert os.listdir("output/input/tagged2") == [".NOBACKUP2"]
        assert os.listdir("output/input/tagged3") == [CACHE_TAG_NAME]
        assert sorted(os.listdir("output/input/taggedall")) == [".NOBACKUP1", ".NOBACKUP2", CACHE_TAG_NAME]

    return assert_test_keep_tagged


@pytest.fixture()
def check_cache(archiver_setup, cmd_fixture, open_repository):
    # First run a regular borg check
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "check")
    # Then check that the cache on disk matches exactly what's in the repo.
    with open_repository() as repository:
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


@pytest.fixture()
def remote_prefix(archiver_setup):
    archiver_setup.prefix = "ssh://__testsuite__"


@pytest.fixture()
def archiver_binary_base(archiver_setup):
    archiver_setup.EXE = "borg.exe"
    archiver_setup.FORK_DEFAULT = True


@pytest.fixture()
def checkts(ts):
    def check_ts():
        # check if the timestamp is in the expected format
        assert datetime.strptime(ts, ISO_FORMAT + "%z")  # must not raise

    return check_ts()
