from ...constants import *  # NOQA
from .. import environment_variable
from . import cmd, RK_ENCRYPTION


def test_benchmark_crud(archiver):
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    with environment_variable(_BORG_BENCHMARK_CRUD_TEST="YES"):
        cmd(archiver, "benchmark", "crud", archiver.input_path)
