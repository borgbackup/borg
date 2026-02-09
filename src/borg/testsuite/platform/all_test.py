from ...platform import swidth


def test_swidth_ascii():
    assert swidth("borg") == 4


def test_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


def test_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2
