from ...archive import Archive
from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, create_regular_file, src_file, create_src_archive, generate_archiver_tests, RK_ENCRYPTION

# Tests that include the 'archivers' argument will generate a tests for each kind of archivers specified.
pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_delete(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path, input_path = archiver.repository_location, archiver.repository_path, archiver.input_path

    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test.2", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test.3", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "another_test.1", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "another_test.2", "input")
    cmd(archiver, f"--repo={repo_location}", "extract", "test", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "delete", "--match-archives", "sh:another_*")
    cmd(archiver, f"--repo={repo_location}", "delete", "--last", "1")
    cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    output = cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test.2", "--stats")
    assert "Original size: -" in output  # negative size == deleted data
    # Make sure all data except the manifest has been deleted
    with Repository(repo_path) as repository:
        assert len(repository) == 1


def test_delete_multiple(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path

    create_regular_file(input_path, "file1", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test1", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test2", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test3", "input")
    cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test1")
    cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test2")
    cmd(archiver, f"--repo={repo_location}", "extract", "test3", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test3")
    assert not cmd(archiver, f"--repo={repo_location}", "rlist")


def test_delete_force(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path

    cmd(archiver, f"--repo={repo_location}", "rcreate", "--encryption=none")
    create_src_archive(archiver, "test")
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
    output = cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test", "--force")
    assert "deleted archive was corrupted" in output

    cmd(archiver, f"--repo={repo_location}", "check", "--repair")
    output = cmd(archiver, f"--repo={repo_location}", "rlist")
    assert "test" not in output


def test_delete_double_force(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path

    cmd(archiver, f"--repo={repo_location}", "rcreate", "--encryption=none")
    create_src_archive(archiver, "test")
    with Repository(repo_path, exclusive=True) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        archive = Archive(manifest, "test")
        id = archive.metadata.items[0]
        repository.put(id, b"corrupted items metadata stream chunk")
        repository.commit(compact=False)
    cmd(archiver, f"--repo={repo_location}", "delete", "-a", "test", "--force", "--force")
    cmd(archiver, f"--repo={repo_location}", "check", "--repair")
    output = cmd(archiver, f"--repo={repo_location}", "rlist")
    assert "test" not in output
