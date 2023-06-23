import io
import os
import subprocess
import sys
from io import StringIO, BytesIO

import pytest

# needed to get pretty assertion failures in unit tests:
from borg import helpers
from borg.archive import Archive
from borg.constants import EXIT_SUCCESS
from borg.manifest import Manifest
from borg.repository import Repository

if hasattr(pytest, "register_assert_rewrite"):
    pytest.register_assert_rewrite("borg.testsuite")


import borg.cache  # noqa: E402
from borg.archiver import Archiver
from borg.logger import setup_logging, flush_logging  # noqa: E402

# Ensure that the loggers exist for all tests
setup_logging()

from borg.testsuite import has_lchflags, has_llfuse, has_pyfuse3  # noqa: E402
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
def set_env_variables(monkeypatch):
    os.environ["BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_PASSPHRASE"] = "waytooeasyonlyfortests"
    os.environ["BORG_SELFTEST"] = "disabled"


class ArchiverSetup:
    RK_ENCRYPTION = "--encryption=repokey-aes-ocb"
    KF_ENCRYPTION = "--encryption=keyfile-chacha20-poly1305"
    PURE_PYTHON_MSGPACK_WARNING = "Using a pure-python msgpack! This will result in lower performance."

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "src", "borg", "archiver"))

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
        repository = Repository(repo_path, exclusive=True, create=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(manifest, name)
        return archive, repository

    return archive_and_repository
