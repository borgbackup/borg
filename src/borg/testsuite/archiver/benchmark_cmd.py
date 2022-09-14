from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION, environment_variable


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_benchmark_crud(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        with environment_variable(_BORG_BENCHMARK_CRUD_TEST="YES"):
            self.cmd(f"--repo={self.repository_location}", "benchmark", "crud", self.input_path)
