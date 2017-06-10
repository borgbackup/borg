import os

import pytest

# IMPORTANT keep this above all other borg imports to avoid inconsistent values
# for `from borg.constants import PBKDF2_ITERATIONS` (or star import) usages before
# this is executed
from borg import constants
# no fixture-based monkey-patching since star-imports are used for the constants module
constants.PBKDF2_ITERATIONS = 1


# needed to get pretty assertion failures in unit tests:
if hasattr(pytest, 'register_assert_rewrite'):
    pytest.register_assert_rewrite('borg.testsuite')


import borg.cache
from borg.logger import setup_logging

# Ensure that the loggers exist for all tests
setup_logging()

from borg.testsuite import has_lchflags, has_llfuse
from borg.testsuite import are_symlinks_supported, are_hardlinks_supported, is_utime_fully_supported
from borg.testsuite.platform import fakeroot_detected, are_acls_working
from borg import xattr


@pytest.fixture(autouse=True)
def clean_env(tmpdir_factory, monkeypatch):
    # avoid that we access / modify the user's normal .config / .cache directory:
    monkeypatch.setenv('XDG_CONFIG_HOME', tmpdir_factory.mktemp('xdg-config-home'))
    monkeypatch.setenv('XDG_CACHE_HOME', tmpdir_factory.mktemp('xdg-cache-home'))
    # also avoid to use anything from the outside environment:
    keys = [key for key in os.environ if key.startswith('BORG_')]
    for key in keys:
        monkeypatch.delenv(key, raising=False)


def pytest_report_header(config, startdir):
    tests = {
        "BSD flags": has_lchflags,
        "fuse": has_llfuse,
        "root": not fakeroot_detected(),
        "symlinks": are_symlinks_supported(),
        "hardlinks": are_hardlinks_supported(),
        "atime/mtime": is_utime_fully_supported(),
        "modes": "BORG_TESTS_IGNORE_MODES" not in os.environ
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
            raise AssertionError("Cache wipe was triggered, if this is part of the test add @pytest.mark.allow_cache_wipe")
        if 'allow_cache_wipe' not in request.keywords:
            borg.cache.LocalCache.wipe_cache = wipe_should_not_be_called
        request.addfinalizer(self.undo)

    def undo(self):
        borg.cache.LocalCache.wipe_cache = self.org_cache_wipe_cache


@pytest.fixture(autouse=True)
def default_patches(request):
    return DefaultPatches(request)
