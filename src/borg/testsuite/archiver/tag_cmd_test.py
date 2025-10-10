import pytest

from ...constants import *  # NOQA
from . import cmd, generate_archiver_tests, RK_ENCRYPTION
from ...helpers import Error

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def test_tag_set(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    output = cmd(archiver, "tag", "-a", "archive", "--set", "aa")
    assert "tags: aa." in output
    output = cmd(archiver, "tag", "-a", "archive", "--set", "bb")
    assert "tags: bb." in output
    output = cmd(archiver, "tag", "-a", "archive", "--set", "bb", "--set", "aa")
    assert "tags: aa,bb." in output  # sorted!
    output = cmd(archiver, "tag", "-a", "archive", "--set", "")
    assert "tags: ." in output  # no tags!


def test_tag_add_remove(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    output = cmd(archiver, "tag", "-a", "archive", "--add", "aa")
    assert "tags: aa." in output
    output = cmd(archiver, "tag", "-a", "archive", "--add", "bb")
    assert "tags: aa,bb." in output
    output = cmd(archiver, "tag", "-a", "archive", "--remove", "aa")
    assert "tags: bb." in output
    output = cmd(archiver, "tag", "-a", "archive", "--remove", "bb")
    assert "tags: ." in output


def test_tag_set_noclobber_special(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    output = cmd(archiver, "tag", "-a", "archive", "--set", "@PROT")
    assert "tags: @PROT." in output
    # archive now has a special tag.
    # it must not be possible to accidentally erase such special tags by using --set:
    output = cmd(archiver, "tag", "-a", "archive", "--set", "clobber")
    assert "tags: @PROT." in output
    # it is possible though to use --set if the existing special tags are also given:
    output = cmd(archiver, "tag", "-a", "archive", "--set", "noclobber", "--set", "@PROT")
    assert "tags: @PROT,noclobber." in output


def test_tag_only_known_special(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    # user can't set / add / remove unknown special tags
    with pytest.raises(Error):
        cmd(archiver, "tag", "-a", "archive", "--set", "@UNKNOWN")
    with pytest.raises(Error):
        cmd(archiver, "tag", "-a", "archive", "--add", "@UNKNOWN")
    with pytest.raises(Error):
        cmd(archiver, "tag", "-a", "archive", "--remove", "@UNKNOWN")
