from ...constants import *  # NOQA
from . import environment_variable
from .utils import cmd


def test_benchmark_crud(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", archiver.RK_ENCRYPTION)
    with environment_variable(_BORG_BENCHMARK_CRUD_TEST="YES"):
        cmd(archiver, f"--repo={archiver.repository_location}", "benchmark", "crud", archiver.input_path)
