import os
import pytest

from ...constants import *  # NOQA
from . import RK_ENCRYPTION, create_test_files, cmd, generate_archiver_tests
from ...helpers import CommandError, Error

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_config(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    output = cmd(archiver, "config", "--list")
    assert "[repository]" in output
    assert "version" in output
    assert "segments_per_dir" in output
    assert "storage_quota" in output
    assert "append_only" in output
    assert "additional_free_space" in output
    assert "id" in output
    assert "last_segment_checked" not in output

    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "config", "last_segment_checked", exit_code=2)
        assert "No option " in output
    else:
        with pytest.raises(Error):
            cmd(archiver, "config", "last_segment_checked")

    cmd(archiver, "config", "last_segment_checked", "123")
    output = cmd(archiver, "config", "last_segment_checked")
    assert output == "123" + os.linesep
    output = cmd(archiver, "config", "--list")
    assert "last_segment_checked" in output
    cmd(archiver, "config", "--delete", "last_segment_checked")

    for cfg_key, cfg_value in [("additional_free_space", "2G"), ("repository.append_only", "1")]:
        output = cmd(archiver, "config", cfg_key)
        assert output == "0" + os.linesep
        cmd(archiver, "config", cfg_key, cfg_value)
        output = cmd(archiver, "config", cfg_key)
        assert output == cfg_value + os.linesep
        cmd(archiver, "config", "--delete", cfg_key)
        if archiver.FORK_DEFAULT:
            cmd(archiver, "config", cfg_key, exit_code=2)
        else:
            with pytest.raises(Error):
                cmd(archiver, "config", cfg_key)

    cmd(archiver, "config", "--list", "--delete", exit_code=2)
    if archiver.FORK_DEFAULT:
        cmd(archiver, "config", exit_code=2)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "config")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "config", "invalid-option", exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, "config", "invalid-option")
