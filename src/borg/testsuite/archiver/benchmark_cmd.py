from ...constants import *  # NOQA
from . import environment_variable


def test_benchmark_crud(archiver_setup, cmd_fixture):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    with environment_variable(_BORG_BENCHMARK_CRUD_TEST="YES"):
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "benchmark", "crud", archiver_setup.input_path)
