import os
from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...helpers import CommandError
from . import cmd, generate_archiver_tests, RK_ENCRYPTION

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
    output = cmd(archiver, "tag", "-a", "archive", "--set", "clobber", exit_code=EXIT_WARNING)
    assert "not setting tags, this would remove special tags @PROT." in output
    assert "tags: @PROT." in output
    # it is possible though to use --set if the existing special tags are also given:
    output = cmd(archiver, "tag", "-a", "archive", "--set", "noclobber", "--set", "@PROT")
    assert "tags: @PROT,noclobber." in output


def test_tag_clear(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    output = cmd(archiver, "tag", "-a", "archive", "--add", "aa", "--add", "bb")
    assert "tags: aa,bb." in output
    output = cmd(archiver, "tag", "-a", "archive", "--clear")
    assert "tags: ." in output  # no tags!
    output = cmd(archiver, "tag", "-a", "archive", "--add", "aa", "--add", "@PROT")
    assert "tags: @PROT,aa." in output
    # --clear must not remove special tags:
    output = cmd(archiver, "tag", "-a", "archive", "--clear")
    assert "tags: @PROT." in output
    # --clear with --add replaces the normal tags:
    cmd(archiver, "tag", "-a", "archive", "--add", "aa")
    output = cmd(archiver, "tag", "-a", "archive", "--clear", "--add", "bb")
    assert "tags: @PROT,bb." in output
    # --clear and --set are mutually exclusive:
    cmd(archiver, "tag", "-a", "archive", "--clear", "--set", "cc", exit_code=EXIT_ERROR)


def test_tag_only_known_special(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    # user can't set / add / remove unknown special tags
    cmd(archiver, "tag", "-a", "archive", "--set", "@UNKNOWN", exit_code=EXIT_ERROR)
    cmd(archiver, "tag", "-a", "archive", "--add", "@UNKNOWN", exit_code=EXIT_ERROR)
    cmd(archiver, "tag", "-a", "archive", "--remove", "@UNKNOWN", exit_code=EXIT_ERROR)


def test_tag_options_before_archive_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    # tag options take one tag each, so they must not swallow the archive name given after them.
    output = cmd(archiver, "tag", "--add", "aa", "--add", "bb", "archive")
    assert "tags: aa,bb." in output
    output = cmd(archiver, "tag", "--remove", "aa", "archive")
    assert "tags: bb." in output
    output = cmd(archiver, "tag", "--set", "cc", "--set", "dd", "archive")
    assert "tags: cc,dd." in output


def test_tag_all_archives_needs_selection(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", archiver.input_path)
    cmd(archiver, "create", "archive2", archiver.input_path)
    cmd(archiver, "tag", "-a", "sh:*", "--add", "aa")
    # Without NAME or archive filters, borg must refuse to change the tags of all archives.
    msg = "if you really want to change the tags of all archives"
    for tag_args in (["--set", "bb"], ["--clear"], ["--add", "bb"], ["--remove", "aa"]):
        if archiver.FORK_DEFAULT:
            output = cmd(archiver, "tag", *tag_args, exit_code=CommandError().exit_code)
            assert msg in output
        else:
            with pytest.raises(CommandError, match=msg):
                cmd(archiver, "tag", *tag_args)
    # just showing the tags of all archives is fine:
    output = cmd(archiver, "tag")
    assert output.count("tags: aa.") == 2
    # an explicit selection of all archives is fine:
    output = cmd(archiver, "tag", "-a", "sh:*", "--clear")
    assert output.count("tags: .") == 2


def test_tag_unchanged_tags_do_not_rewrite_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", archiver.input_path)
    cmd(archiver, "tag", "-a", "archive", "--add", "aa", "--add", "@PROT")
    archives_dir = Path(archiver.repository_path) / "archives"

    def live_entries():
        # the archive entry objects, without soft-deleted ones (having a .del suffix).
        return [p for p in archives_dir.iterdir() if not p.name.endswith(".del")]

    (archive_entry,) = live_entries()
    st_before = os.stat(archive_entry)
    # neither just listing the tags nor a no-op change must rewrite the archive metadata:
    output = cmd(archiver, "tag")
    assert "tags: @PROT,aa." in output
    output = cmd(archiver, "tag", "-a", "archive", "--add", "aa")
    assert "tags: @PROT,aa." in output
    output = cmd(archiver, "tag", "-a", "archive", "--remove", "zz")
    assert "tags: @PROT,aa." in output
    # a refused --set does not change the tags either:
    output = cmd(archiver, "tag", "-a", "archive", "--set", "bb", exit_code=EXIT_WARNING)
    assert "tags: @PROT,aa." in output
    st_after = os.stat(archive_entry)
    assert (st_after.st_mtime_ns, st_after.st_ino) == (st_before.st_mtime_ns, st_before.st_ino)
    assert live_entries() == [archive_entry]
