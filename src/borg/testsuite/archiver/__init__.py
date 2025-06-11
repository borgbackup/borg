import errno
import filecmp
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO, StringIO

import pytest

from ... import xattr, platform
from ...archive import Archive
from ...archiver import Archiver, PURE_PYTHON_MSGPACK_WARNING
from ...constants import *  # NOQA
from ...helpers import Location, umount
from ...helpers import EXIT_SUCCESS
from ...helpers import init_ec_warnings
from ...logger import flush_logging
from ...manifest import Manifest
from ...platform import get_flags
from ...remote import RemoteRepository
from ...repository import Repository
from .. import has_lchflags, is_utime_fully_supported, have_fuse_mtime_ns, st_mtime_ns_round, no_selinux
from .. import changedir
from .. import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported
from ..platform.platform_test import is_win32
from ...xattr import get_all

RK_ENCRYPTION = "--encryption=repokey-aes-ocb"
KF_ENCRYPTION = "--encryption=keyfile-chacha20-poly1305"

# this points to src/borg/archiver directory (which is small and has only a few files)
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "archiver"))
src_file = "archiver/__init__.py"  # relative path of one file in src_dir

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
            # Always use utf-8 here, to .decode() below
            output_text = sys.stdout = sys.stderr = io.TextIOWrapper(output, encoding="utf-8")
            if archiver is None:
                archiver = Archiver()
            archiver.prerun_checks = lambda *args: None
            init_ec_warnings()
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
                flush_logging()  # usually done via atexit, but we do not exit here
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
def cmd_fixture(request):
    if request.param == "python":
        exe = None
    elif request.param == "binary":
        exe = "borg.exe"
    else:
        raise ValueError("param must be 'python' or 'binary'")

    def exec_fn(*args, **kw):
        return exec_cmd(*args, exe=exe, fork=True, **kw)

    return exec_fn


def generate_archiver_tests(metafunc, kinds: str):
    # Generate tests for different scenarios: local repository, remote repository, and using the borg binary.
    archivers = []
    for kind in kinds.split(","):
        if kind == "local":
            archivers.append("archiver")
        elif kind == "remote":
            archivers.append("remote_archiver")
        elif kind == "binary":
            archivers.append("binary_archiver")
        else:
            raise ValueError(f"Invalid archiver: Expected local, remote, or binary, received {kind}.")

    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", archivers)


def checkts(ts):
    # check if the timestamp is in the expected format
    assert datetime.strptime(ts, ISO_FORMAT + "%z")  # must not raise


def cmd(archiver, *args, **kw):
    exit_code = kw.pop("exit_code", 0)
    fork = kw.pop("fork", None)
    binary_output = kw.get("binary_output", False)
    if fork is None:
        fork = archiver.FORK_DEFAULT
    ret, output = exec_cmd(
        f"--repo={archiver.repository_location}", *args, archiver=archiver.archiver, fork=fork, exe=archiver.EXE, **kw
    )
    if ret != exit_code:
        print(output)
    assert ret == exit_code
    # if tests are run with the pure-python msgpack, there will be warnings about
    # this in the output, which would make a lot of tests fail.
    pp_msg = PURE_PYTHON_MSGPACK_WARNING.encode() if binary_output else PURE_PYTHON_MSGPACK_WARNING
    empty = b"" if binary_output else ""
    output = empty.join(line for line in output.splitlines(keepends=True) if pp_msg not in line)
    return output


def create_src_archive(archiver, name, ts=None):
    if ts:
        cmd(archiver, "create", "--compression=lz4", f"--timestamp={ts}", name, src_dir)
    else:
        cmd(archiver, "create", "--compression=lz4", name, src_dir)


def open_archive(repo_path, name):
    repository = Repository(repo_path, exclusive=True)
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        archive_info = manifest.archives.get_one([name])
        archive = Archive(manifest, archive_info.id)
    return archive, repository


def open_repository(archiver):
    if archiver.get_kind() == "remote":
        return RemoteRepository(Location(archiver.repository_location))
    else:
        return Repository(archiver.repository_path, exclusive=True)


def create_regular_file(input_path, name, size=0, contents=None):
    assert not (size != 0 and contents and len(contents) != size), "size and contents do not match"
    filename = os.path.join(input_path, name)
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    with open(filename, "wb") as fd:
        if contents is None:
            contents = b"X" * size
        fd.write(contents)


def create_test_files(input_path, create_hardlinks=True):
    """Create a minimal test case including all supported file types"""
    # File
    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "flagfile", size=1024)
    # Directory
    create_regular_file(input_path, "dir2/file2", size=1024 * 80)
    # File mode
    os.chmod("input/file1", 0o4755)
    # Hard link
    if are_hardlinks_supported() and create_hardlinks:
        os.link(os.path.join(input_path, "file1"), os.path.join(input_path, "hardlink"))
    # Symlink
    if are_symlinks_supported():
        os.symlink("somewhere", os.path.join(input_path, "link1"))
    create_regular_file(input_path, "fusexattr", size=1)
    if not xattr.XATTR_FAKEROOT and xattr.is_enabled(input_path):
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
    create_regular_file(input_path, "empty", size=0)
    return have_root


def _extract_repository_id(repo_path):
    with Repository(repo_path) as repository:
        return repository.id


def _set_repository_id(repo_path, id):
    with Repository(repo_path) as repository:
        repository._set_id(id)
        return repository.id


def _extract_hardlinks_setup(archiver):
    input_path = archiver.input_path
    os.mkdir(os.path.join(input_path, "dir1"))
    os.mkdir(os.path.join(input_path, "dir1/subdir"))

    create_regular_file(input_path, "source", contents=b"123456")
    os.link(os.path.join(input_path, "source"), os.path.join(input_path, "abba"))
    os.link(os.path.join(input_path, "source"), os.path.join(input_path, "dir1/hardlink"))
    os.link(os.path.join(input_path, "source"), os.path.join(input_path, "dir1/subdir/hardlink"))

    create_regular_file(input_path, "dir1/source2")
    os.link(os.path.join(input_path, "dir1/source2"), os.path.join(input_path, "dir1/aaaa"))

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")


def _create_test_caches(archiver):
    input_path = archiver.input_path
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "cache1/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
    create_regular_file(input_path, "cache2/%s" % CACHE_TAG_NAME, contents=b"invalid signature")
    os.mkdir("input/cache3")
    if are_hardlinks_supported():
        os.link("input/cache1/%s" % CACHE_TAG_NAME, "input/cache3/%s" % CACHE_TAG_NAME)
    else:
        create_regular_file(input_path, "cache3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")


def _assert_test_caches(archiver):
    with changedir("output"):
        cmd(archiver, "extract", "test")
    assert sorted(os.listdir("output/input")) == ["cache2", "file1"]
    assert sorted(os.listdir("output/input/cache2")) == [CACHE_TAG_NAME]


def _create_test_tagged(archiver):
    input_path = archiver.input_path
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "tagged1/.NOBACKUP")
    create_regular_file(input_path, "tagged2/00-NOBACKUP")
    create_regular_file(input_path, "tagged3/.NOBACKUP/file2", size=1024)


def _assert_test_tagged(archiver):
    with changedir("output"):
        cmd(archiver, "extract", "test")
    assert sorted(os.listdir("output/input")) == ["file1"]


def _create_test_keep_tagged(archiver):
    input_path = archiver.input_path
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(input_path, "file0", size=1024)
    create_regular_file(input_path, "tagged1/.NOBACKUP1")
    create_regular_file(input_path, "tagged1/file1", size=1024)
    create_regular_file(input_path, "tagged2/.NOBACKUP2/subfile1", size=1024)
    create_regular_file(input_path, "tagged2/file2", size=1024)
    create_regular_file(input_path, "tagged3/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
    create_regular_file(input_path, "tagged3/file3", size=1024)
    create_regular_file(input_path, "taggedall/.NOBACKUP1")
    create_regular_file(input_path, "taggedall/.NOBACKUP2/subfile1", size=1024)
    create_regular_file(input_path, "taggedall/%s" % CACHE_TAG_NAME, contents=CACHE_TAG_CONTENTS + b" extra stuff")
    create_regular_file(input_path, "taggedall/file4", size=1024)


def _assert_test_keep_tagged(archiver):
    with changedir("output"):
        cmd(archiver, "extract", "test")
    assert sorted(os.listdir("output/input")), ["file0", "tagged1", "tagged2", "tagged3", "taggedall"]
    assert os.listdir("output/input/tagged1"), [".NOBACKUP1"]
    assert os.listdir("output/input/tagged2"), [".NOBACKUP2"]
    assert os.listdir("output/input/tagged3"), [CACHE_TAG_NAME]
    assert sorted(os.listdir("output/input/taggedall")), [".NOBACKUP1", ".NOBACKUP2", CACHE_TAG_NAME]


@contextmanager
def assert_creates_file(path):
    assert not os.path.exists(path), f"{path} should not exist"
    yield
    assert os.path.exists(path), f"{path} should exist"


def assert_dirs_equal(dir1, dir2, **kwargs):
    diff = filecmp.dircmp(dir1, dir2)
    _assert_dirs_equal_cmp(diff, **kwargs)


def assert_line_exists(lines, expected_regexpr):
    assert any(re.search(expected_regexpr, line) for line in lines), f"no match for {expected_regexpr} in {lines}"


def assert_line_not_exists(lines, expected_regexpr):
    assert not any(
        re.search(expected_regexpr, line) for line in lines
    ), f"unexpected match for {expected_regexpr} in {lines}"


def _assert_dirs_equal_cmp(diff, ignore_flags=False, ignore_xattrs=False, ignore_ns=False):
    assert diff.left_only == []
    assert diff.right_only == []
    assert diff.diff_files == []
    assert diff.funny_files == []
    for filename in diff.common:
        path1 = os.path.join(diff.left, filename)
        path2 = os.path.join(diff.right, filename)
        s1 = os.stat(path1, follow_symlinks=False)
        s2 = os.stat(path2, follow_symlinks=False)
        # Assume path2 is on FUSE if st_dev is different
        fuse = s1.st_dev != s2.st_dev
        attrs = ["st_uid", "st_gid", "st_rdev"]
        if not fuse or not os.path.isdir(path1):
            # dir nlink is always 1 on our FUSE filesystem
            attrs.append("st_nlink")
        d1 = [filename] + [getattr(s1, a) for a in attrs]
        d2 = [filename] + [getattr(s2, a) for a in attrs]
        d1.insert(1, oct(s1.st_mode))
        d2.insert(1, oct(s2.st_mode))
        if not ignore_flags:
            d1.append(get_flags(path1, s1))
            d2.append(get_flags(path2, s2))
        # ignore st_rdev if file is not a block/char device, fixes #203
        if not stat.S_ISCHR(s1.st_mode) and not stat.S_ISBLK(s1.st_mode):
            d1[4] = None
        if not stat.S_ISCHR(s2.st_mode) and not stat.S_ISBLK(s2.st_mode):
            d2[4] = None
        # If utime isn't fully supported, borg can't set mtime.
        # Therefore, we shouldn't test it in that case.
        if is_utime_fully_supported():
            # Older versions of llfuse do not support ns precision properly
            if ignore_ns:
                d1.append(int(s1.st_mtime_ns / 1e9))
                d2.append(int(s2.st_mtime_ns / 1e9))
            elif fuse and not have_fuse_mtime_ns:
                d1.append(round(s1.st_mtime_ns, -4))
                d2.append(round(s2.st_mtime_ns, -4))
            else:
                d1.append(round(s1.st_mtime_ns, st_mtime_ns_round))
                d2.append(round(s2.st_mtime_ns, st_mtime_ns_round))
        if not ignore_xattrs:
            d1.append(no_selinux(get_all(path1, follow_symlinks=False)))
            d2.append(no_selinux(get_all(path2, follow_symlinks=False)))
        assert d1 == d2
    for sub_diff in diff.subdirs.values():
        _assert_dirs_equal_cmp(sub_diff, ignore_flags=ignore_flags, ignore_xattrs=ignore_xattrs, ignore_ns=ignore_ns)


@contextmanager
def read_only(path):
    """Some paths need to be made read-only for testing

    If the tests are executed inside a fakeroot environment, the
    changes from chmod won't affect the real permissions of that
    folder. This issue is circumvented by temporarily disabling
    fakeroot with `LD_PRELOAD=`.

    Using chmod to remove write permissions is not enough if the
    tests are running with root privileges. Instead, the folder is
    rendered immutable with chattr or chflags, respectively.
    """
    if sys.platform.startswith("linux"):
        cmd_immutable = 'chattr +i "%s"' % path
        cmd_mutable = 'chattr -i "%s"' % path
    elif sys.platform.startswith(("darwin", "freebsd", "netbsd", "openbsd")):
        cmd_immutable = 'chflags uchg "%s"' % path
        cmd_mutable = 'chflags nouchg "%s"' % path
    elif sys.platform.startswith("sunos"):  # openindiana
        cmd_immutable = 'chmod S+vimmutable "%s"' % path
        cmd_mutable = 'chmod S-vimmutable "%s"' % path
    else:
        message = "Testing read-only repos is not supported on platform %s" % sys.platform
        pytest.skip(message)
    try:
        os.system('LD_PRELOAD= chmod -R ugo-w "%s"' % path)
        os.system(cmd_immutable)
        yield
    finally:
        # Restore permissions to ensure clean-up doesn't fail
        os.system(cmd_mutable)
        os.system('LD_PRELOAD= chmod -R ugo+w "%s"' % path)


def wait_for_mountstate(mountpoint, *, mounted, timeout=5):
    """Wait until a path meets specified mount point status"""
    timeout += time.time()
    while timeout > time.time():
        if os.path.ismount(mountpoint) == mounted:
            return
        time.sleep(0.1)
    message = "Waiting for {} of {}".format("mount" if mounted else "umount", mountpoint)
    raise TimeoutError(message)


@contextmanager
def fuse_mount(archiver, mountpoint=None, *options, fork=True, os_fork=False, **kwargs):
    # For a successful mount, `fork = True` is required for
    # the borg mount daemon to work properly or the tests
    # will just freeze. Therefore, if argument `fork` is not
    # specified, the default value is `True`, regardless of
    # `FORK_DEFAULT`. However, leaving the possibility to run
    # the command with `fork = False` is still necessary for
    # testing for mount failures, for example attempting to
    # mount a read-only repo.
    #    `os_fork = True` is needed for testing (the absence of)
    # a race condition of the Lock during lock migration when
    # borg mount (local repo) is daemonizing (#4953). This is another
    # example where we need `fork = False`, because the test case
    # needs an OS fork, not a spawning of the fuse mount.
    # `fork = False` is implied if `os_fork = True`.
    if mountpoint is None:
        mountpoint = tempfile.mkdtemp()
    else:
        os.mkdir(mountpoint)
    args = ["mount", mountpoint] + list(options)
    if os_fork:
        # Do not spawn, but actually (OS) fork.
        if os.fork() == 0:
            # The child process.
            # Decouple from parent and fork again.
            # Otherwise, it becomes a zombie and pretends to be alive.
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            # The grandchild process.
            try:
                cmd(archiver, *args, fork=False, **kwargs)  # borg mount not spawning.
            finally:
                # This should never be reached, since it daemonizes,
                # and the grandchild process exits before cmd() returns.
                # However, just in case...
                print("Fatal: borg mount did not daemonize properly. Force exiting.", file=sys.stderr, flush=True)
                os._exit(0)
    else:
        cmd(archiver, *args, fork=fork, **kwargs)
        if kwargs.get("exit_code", EXIT_SUCCESS) == EXIT_ERROR:
            # If argument `exit_code = EXIT_ERROR`, then this call
            # is testing the behavior of an unsuccessful mount, and
            # we must not continue, as there is no mount to work
            # with. The test itself has already failed or succeeded
            # with the call to `cmd`, above.
            yield
            return
    wait_for_mountstate(mountpoint, mounted=True)
    yield
    umount(mountpoint)
    wait_for_mountstate(mountpoint, mounted=False)
    os.rmdir(mountpoint)
    # Give the daemon some time to exit
    time.sleep(0.2)
