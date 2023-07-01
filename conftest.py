import os

import pytest

from borg.testsuite.archiver.utils import exec_cmd

if hasattr(pytest, "register_assert_rewrite"):
    pytest.register_assert_rewrite("borg.testsuite")


import borg.cache  # noqa: E402
from borg.archiver import Archiver
from borg.logger import setup_logging  # noqa: E402

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
    BORG_EXES = []

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
def archiver(tmp_path):
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


@pytest.fixture()
def remote_archiver(archiver):
    archiver.prefix = "ssh://__testsuite__"
    archiver.repository_location = archiver.prefix + archiver.repository_path
    return archiver


@pytest.fixture(autouse=True)
def check_binary_availability(archiver):
    try:
        exec_cmd("help", exe="borg.exe", fork=True)
        archiver.BORG_EXES = ["python", "binary"]
    except FileNotFoundError:
        archiver.BORG_EXES = ["python"]


@pytest.fixture()
def binary_archiver(archiver):
    if "binary" not in archiver.BORG_EXES:
        pytest.skip("No borg.exe binary available")
    archiver.EXE = "borg.exe"
    archiver.FORK_DEFAULT = True
    yield archiver
