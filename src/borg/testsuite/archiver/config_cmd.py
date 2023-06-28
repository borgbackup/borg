import os

from ...constants import *  # NOQA


def pytest_generate_tests(metafunc):
    # Generates tests that run on both local and remote repos
    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", ["archiver_setup", "archiver_binary"])


def test_config(archivers, request, create_test_files, cmd_fixture):
    archiver_setup = request.getfixturevalue(archivers)
    repo_location = archiver_setup.repository_location
    create_test_files()
    os.unlink("input/flagfile")
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    output = cmd_fixture(f"--repo={repo_location}", "config", "--list")
    assert "[repository]" in output
    assert "version" in output
    assert "segments_per_dir" in output
    assert "storage_quota" in output
    assert "append_only" in output
    assert "additional_free_space" in output
    assert "id" in output
    assert "last_segment_checked" not in output

    output = cmd_fixture(f"--repo={repo_location}", "config", "last_segment_checked", exit_code=1)
    assert "No option " in output
    cmd_fixture(f"--repo={repo_location}", "config", "last_segment_checked", "123")
    output = cmd_fixture(f"--repo={repo_location}", "config", "last_segment_checked")
    assert output == "123" + os.linesep
    output = cmd_fixture(f"--repo={repo_location}", "config", "--list")
    assert "last_segment_checked" in output
    cmd_fixture(f"--repo={repo_location}", "config", "--delete", "last_segment_checked")

    for cfg_key, cfg_value in [("additional_free_space", "2G"), ("repository.append_only", "1")]:
        output = cmd_fixture(f"--repo={repo_location}", "config", cfg_key)
        assert output == "0" + os.linesep
        cmd_fixture(f"--repo={repo_location}", "config", cfg_key, cfg_value)
        output = cmd_fixture(f"--repo={repo_location}", "config", cfg_key)
        assert output == cfg_value + os.linesep
        cmd_fixture(f"--repo={repo_location}", "config", "--delete", cfg_key)
        cmd_fixture(f"--repo={repo_location}", "config", cfg_key, exit_code=1)

    cmd_fixture(f"--repo={repo_location}", "config", "--list", "--delete", exit_code=2)
    cmd_fixture(f"--repo={repo_location}", "config", exit_code=2)
    cmd_fixture(f"--repo={repo_location}", "config", "invalid-option", exit_code=1)
