from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_rename(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "test.2", "input")
    cmd(archiver, "extract", "test", "--dry-run")
    cmd(archiver, "extract", "test.2", "--dry-run")
    cmd(archiver, "rename", "test", "test.3")
    cmd(archiver, "extract", "test.2", "--dry-run")
    cmd(archiver, "rename", "test.2", "test.4")
    cmd(archiver, "extract", "test.3", "--dry-run")
    cmd(archiver, "extract", "test.4", "--dry-run")
    # Make sure both archives have been renamed
    with Repository(archiver.repository_path) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 2
        assert manifest.archives.exists("test.3")
        assert manifest.archives.exists("test.4")
