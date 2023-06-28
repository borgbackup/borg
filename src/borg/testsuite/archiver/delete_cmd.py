from ...archive import Archive
from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import src_file


def pytest_generate_tests(metafunc):
    # Generates tests that run on both local and remote repos
    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", ["archiver_setup", "remote_archiver", "binary_archiver"])


def test_delete(archivers, request, cmd_fixture, create_regular_file):
    archiver_setup = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    create_regular_file("file1", size=1024 * 80)
    create_regular_file("dir2/file2", size=1024 * 80)
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "test.3", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "another_test.1", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "another_test.2", "input")
    cmd_fixture(f"--repo={repo_location}", "extract", "test", "--dry-run")
    cmd_fixture(f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    cmd_fixture(f"--repo={repo_location}", "delete", "--match-archives", "sh:another_*")
    cmd_fixture(f"--repo={repo_location}", "delete", "--last", "1")
    cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test")
    cmd_fixture(f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    output = cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test.2", "--stats")
    assert "Original size: -" in output  # negative size == deleted data
    # Make sure all data except the manifest has been deleted
    with Repository(repo_path) as repository:
        assert len(repository) == 1


def test_delete_multiple(archivers, request, cmd_fixture, create_regular_file):
    archiver_setup = request.getfixturevalue(archivers)
    repo_location = archiver_setup.repository_location
    create_regular_file("file1", size=1024 * 80)
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "create", "test1", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "test2", "input")
    cmd_fixture(f"--repo={repo_location}", "create", "test3", "input")
    cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test1")
    cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test2")
    cmd_fixture(f"--repo={repo_location}", "extract", "test3", "--dry-run")
    cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test3")
    assert not cmd_fixture(f"--repo={repo_location}", "rlist")


def test_delete_force(archivers, request, cmd_fixture, create_src_archive):
    archiver_setup = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", "--encryption=none")
    create_src_archive("test")
    with Repository(repo_path, exclusive=True) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        archive = Archive(manifest, "test")
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                repository.delete(item.chunks[-1].id)
                break
        else:
            assert False  # missed the file
        repository.commit(compact=False)
    output = cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test", "--force")
    assert "deleted archive was corrupted" in output
    cmd_fixture(f"--repo={repo_location}", "check", "--repair")
    output = cmd_fixture(f"--repo={repo_location}", "rlist")
    assert "test" not in output


def test_delete_double_force(archivers, request, cmd_fixture, create_src_archive):
    archiver_setup = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", "--encryption=none")
    create_src_archive("test")
    with Repository(repo_path, exclusive=True) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        archive = Archive(manifest, "test")
        id = archive.metadata.items[0]
        repository.put(id, b"corrupted items metadata stream chunk")
        repository.commit(compact=False)
    cmd_fixture(f"--repo={repo_location}", "delete", "-a", "test", "--force", "--force")
    cmd_fixture(f"--repo={repo_location}", "check", "--repair")
    output = cmd_fixture(f"--repo={repo_location}", "rlist")
    assert "test" not in output
