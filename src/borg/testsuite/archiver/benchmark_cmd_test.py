from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION


def test_benchmark_crud(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    cmd(archiver, "benchmark", "crud", archiver.input_path)
    
def test_benchmark_crud_info_progress_logjson_lockwait(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")


    cmd(
        archiver,
        "benchmark",
        "--info",
        "--progress",
        "--log-json",
        "--lock-wait", "10",
        "crud",
        archiver.input_path,
    )

def test_benchmark_cpu(archiver):
    cmd(archiver, "benchmark", "cpu")

def test_benchmark_crud_full_tests(archiver, monkeypatch):
    """Test that the full benchmark test suite is defined when not in test mode."""
    # Ensure the environment variable is NOT set, so we hit lines 106-113
    monkeypatch.delenv("_BORG_BENCHMARK_CRUD_TEST", raising=False)
    
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # We'll run the benchmark, but since it will execute the full tests (which take forever),
    # we only do this to ensure the code path is covered.
    # The actual benchmark will run, so this might take a bit longer.
    cmd(archiver, "benchmark", "crud", archiver.input_path)

def test_benchmark_crud_remote_options(archiver, monkeypatch):
    """Test benchmark crud with --rsh and --remote-path options to cover lines 24 and 26."""
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    
    # Test with --rsh option (covers line 24)
    cmd(archiver, "--rsh", "ssh -o StrictHostKeyChecking=no", "benchmark", "crud", archiver.input_path)
    
    # Test with --remote-path option (covers line 26)
    cmd(archiver, "--remote-path", "borg", "benchmark", "crud", archiver.input_path)
    
    # Test with both options
    cmd(
        archiver,
        "--rsh", "ssh",
        "--remote-path", "borg",
        "benchmark",
        "crud",
        archiver.input_path
    )
