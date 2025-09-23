from ...platform import swidth
from .platform_test import skipif_not_posix


# set module-level skips
pytestmark = skipif_not_posix


def test_posix_swidth_ascii():
    assert swidth("borg") == 4


def test_posix_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


def test_posix_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2
