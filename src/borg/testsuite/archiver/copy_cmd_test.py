from ...archive import Archive
from ...constants import *  # NOQA
from ...helpers import bin_to_hex, CommandError, Error
from ...manifest import Manifest
from .. import changedir
from . import cmd, create_regular_file, assert_dirs_equal, open_repository
from . import generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def archive_id(archiver, name):
    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        return manifest.archives.get_one([name]).id


def test_copy(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    old_id = archive_id(archiver, "test")

    cmd(archiver, "copy", "test", "test.copy")

    # both archives exist now, under different names and with different archive IDs.
    new_id = archive_id(archiver, "test.copy")
    assert new_id != old_id
    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 2
        assert manifest.archives.exists_name_and_id("test", old_id)
        assert manifest.archives.exists_name_and_id("test.copy", new_id)

    # the copy has the same contents as the original archive.
    with changedir("output"):
        cmd(archiver, "extract", "test.copy")
        assert_dirs_equal(archiver.input_path, "input")


def test_copy_by_archive_id(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    old_id = archive_id(archiver, "test")

    cmd(archiver, "copy", f"aid:{bin_to_hex(old_id)[:8]}", "test.copy")

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 2
        assert manifest.archives.exists("test.copy")


def test_copy_shares_item_stream(archivers, request):
    """The copy must reuse the item metadata stream, not rewrite it."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    cmd(archiver, "copy", "test", "test.copy")

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        original = Archive(manifest, manifest.archives.get_one(["test"]).id)
        copied = Archive(manifest, manifest.archives.get_one(["test.copy"]).id)
        assert original.metadata.item_ptrs == copied.metadata.item_ptrs
        assert original.metadata.time == copied.metadata.time
        assert original.metadata.name == "test"
        assert copied.metadata.name == "test.copy"


def test_copy_delete_original(archivers, request):
    """The two archives are independent: deleting and compacting away one keeps the other intact."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    cmd(archiver, "copy", "test", "test.copy")

    cmd(archiver, "delete", "test")
    cmd(archiver, "compact")  # actually free everything the deleted archive was the only referrer of

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 1
        assert manifest.archives.exists("test.copy")

    cmd(archiver, "check")  # no chunks of the surviving archive were freed
    with changedir("output"):
        cmd(archiver, "extract", "test.copy")
        assert_dirs_equal(archiver.input_path, "input")


def test_copy_to_existing_name(archivers, request):
    """Archive names do not need to be unique, so copying into an existing archive series works."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "series", "input")

    cmd(archiver, "copy", "test", "series")

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 3
        assert len(list(manifest.archives.list(match=["series"]))) == 2


def test_copy_to_same_name(archivers, request):
    """Copying to the archive's own name would not create a second archive, so it is refused."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    output = cmd(archiver, "copy", "test", "test", fork=True, exit_code=Error.exit_mcode)
    assert "can not be copied to the same name" in output

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 1


def test_copy_ambiguous_name(archivers, request):
    """OLDNAME must match precisely one archive."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "test", "input")

    output = cmd(archiver, "copy", "test", "test.copy", fork=True, exit_code=CommandError.exit_mcode)
    assert "needed to match precisely one archive" in output

    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 2
