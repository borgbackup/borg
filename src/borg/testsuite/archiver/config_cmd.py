import os

from ...constants import *  # NOQA
from . import RK_ENCRYPTION, create_test_files, cmd, generate_archiver_tests

# Tests that include the 'archivers' argument will generate a tests for each kind of archivers specified.
pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_config(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    output = cmd(archiver, f"--repo={repo_location}", "config", "--list")
    assert "[repository]" in output
    assert "version" in output
    assert "segments_per_dir" in output
    assert "storage_quota" in output
    assert "append_only" in output
    assert "additional_free_space" in output
    assert "id" in output
    assert "last_segment_checked" not in output

    output = cmd(archiver, f"--repo={repo_location}", "config", "last_segment_checked", exit_code=1)
    assert "No option " in output
    cmd(archiver, f"--repo={repo_location}", "config", "last_segment_checked", "123")
    output = cmd(archiver, f"--repo={repo_location}", "config", "last_segment_checked")
    assert output == "123" + os.linesep
    output = cmd(archiver, f"--repo={repo_location}", "config", "--list")
    assert "last_segment_checked" in output
    cmd(archiver, f"--repo={repo_location}", "config", "--delete", "last_segment_checked")

    for cfg_key, cfg_value in [("additional_free_space", "2G"), ("repository.append_only", "1")]:
        output = cmd(archiver, f"--repo={repo_location}", "config", cfg_key)
        assert output == "0" + os.linesep
        cmd(archiver, f"--repo={repo_location}", "config", cfg_key, cfg_value)
        output = cmd(archiver, f"--repo={repo_location}", "config", cfg_key)
        assert output == cfg_value + os.linesep
        cmd(archiver, f"--repo={repo_location}", "config", "--delete", cfg_key)
        cmd(archiver, f"--repo={repo_location}", "config", cfg_key, exit_code=1)

    cmd(archiver, f"--repo={repo_location}", "config", "--list", "--delete", exit_code=2)
    cmd(archiver, f"--repo={repo_location}", "config", exit_code=2)
    cmd(archiver, f"--repo={repo_location}", "config", "invalid-option", exit_code=1)
