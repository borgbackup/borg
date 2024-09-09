from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION


def test_benchmark_crud(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    cmd(archiver, "benchmark", "crud", archiver.input_path)
