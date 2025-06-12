import os

import pytest

if hasattr(pytest, "register_assert_rewrite"):
    pytest.register_assert_rewrite("borg.testsuite")

# Ensure that the loggers exist for all tests
from borg.logger import setup_logging  # noqa: E402

setup_logging()

from borg.archiver import Archiver  # noqa: E402
from borg.testsuite import has_lchflags, has_llfuse, has_pyfuse3  # noqa: E402
from borg.testsuite import are_symlinks_supported, are_hardlinks_supported, is_utime_fully_supported  # noqa: E402
from borg.testsuite.archiver import BORG_EXES
from borg.testsuite.platform.platform_test import fakeroot_detected  # noqa: E402


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
    monkeypatch.setenv("BORG_STORE_DATA_LEVELS", "0")  # flat storage for few objects


def pytest_report_header(config, start_path):
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


@pytest.fixture()
def set_env_variables():
    os.environ["BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    os.environ["BORG_PASSPHRASE"] = "waytooeasyonlyfortests"  # nosec B105
    os.environ["BORG_SELFTEST"] = "disabled"


class ArchiverSetup:
    EXE: str = None  # python source based
    FORK_DEFAULT = False
    BORG_EXES: list[str] = []

    def __init__(self):
        self.archiver = None
        self.tmpdir: str | None = None
        self.repository_path: str | None = None
        self.repository_location: str | None = None
        self.input_path: str | None = None
        self.output_path: str | None = None
        self.keys_path: str | None = None
        self.cache_path: str | None = None
        self.exclude_file_path: str | None = None
        self.patterns_file_path: str | None = None

    def get_kind(self) -> str:
        if self.repository_location.startswith("ssh://__testsuite__"):
            return "remote"
        elif self.EXE == "borg.exe":
            return "binary"
        else:
            return "local"


@pytest.fixture()
def archiver(tmp_path, set_env_variables):
    archiver = ArchiverSetup()
    archiver.archiver = not archiver.FORK_DEFAULT and Archiver() or None
    archiver.tmpdir = tmp_path
    archiver.repository_path = os.fspath(tmp_path / "repository")
    archiver.repository_location = archiver.repository_path
    archiver.input_path = os.fspath(tmp_path / "input")
    archiver.output_path = os.fspath(tmp_path / "output")
    archiver.keys_path = os.fspath(tmp_path / "keys")
    archiver.cache_path = os.fspath(tmp_path / "cache")
    archiver.exclude_file_path = os.fspath(tmp_path / "excludes")
    archiver.patterns_file_path = os.fspath(tmp_path / "patterns")
    os.environ["BORG_KEYS_DIR"] = archiver.keys_path
    os.environ["BORG_CACHE_DIR"] = archiver.cache_path
    os.mkdir(archiver.input_path)
    # avoid troubles with fakeroot / FUSE:
    os.chmod(archiver.input_path, 0o777)  # nosec B103
    os.mkdir(archiver.output_path)
    os.mkdir(archiver.keys_path)
    os.mkdir(archiver.cache_path)
    with open(archiver.exclude_file_path, "wb") as fd:
        fd.write(b"input/file2\n# A comment line, then a blank line\n\n")
    with open(archiver.patterns_file_path, "wb") as fd:
        fd.write(b"+input/file_important\n- input/file*\n# A comment line, then a blank line\n\n")
    old_wd = os.getcwd()
    os.chdir(archiver.tmpdir)
    yield archiver
    os.chdir(old_wd)


@pytest.fixture()
def remote_archiver(archiver):
    archiver.repository_location = "ssh://__testsuite__/" + str(archiver.repository_path)
    yield archiver


@pytest.fixture()
def binary_archiver(archiver):
    if "binary" not in BORG_EXES:
        pytest.skip("No borg.exe binary available")
    archiver.EXE = "borg.exe"
    archiver.FORK_DEFAULT = True
    yield archiver
