import os

import pytest

# needed to get pretty assertion failures in unit tests:
if hasattr(pytest, "register_assert_rewrite"):
    pytest.register_assert_rewrite("borg.testsuite")


import borg.cache  # noqa: E402
from borg.logger import setup_logging  # noqa: E402

# Ensure that the loggers exist for all tests
setup_logging()

from borg.testsuite import has_lchflags, has_llfuse, has_pyfuse3  # noqa: E402
from borg.testsuite import are_symlinks_supported, are_hardlinks_supported, is_utime_fully_supported  # noqa: E402
from borg.testsuite.platform import fakeroot_detected  # noqa: E402


@pytest.fixture(autouse=True)
def clean_env(tmpdir_factory, monkeypatch):
    # avoid that we access / modify the user's normal .config / .cache directory:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmpdir_factory.mktemp("xdg-config-home")))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmpdir_factory.mktemp("xdg-cache-home")))
    # also avoid to use anything from the outside environment:
    keys = [key for key in os.environ if key.startswith("BORG_") and key not in ("BORG_FUSE_IMPL",)]
    for key in keys:
        monkeypatch.delenv(key, raising=False)
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
