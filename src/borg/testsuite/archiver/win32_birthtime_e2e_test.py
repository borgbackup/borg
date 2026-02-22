import os
import pytest
from ...platform import set_birthtime, get_birthtime_ns
from ...platformflags import is_win32
from . import cmd, generate_archiver_tests, changedir


def pytest_generate_tests(metafunc):
    generate_archiver_tests(metafunc, kinds="local")


@pytest.mark.skipif(not is_win32, reason="Windows only test")
def test_birthtime_restore(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=none")

    # Create a file in input directory
    input_file = os.path.join(archiver.input_path, "test_file")
    if not os.path.exists(archiver.input_path):
        os.makedirs(archiver.input_path)
    with open(input_file, "w") as f:
        f.write("data")

    st = os.stat(input_file)
    original_birthtime = get_birthtime_ns(st, input_file)

    # Set an old birthtime (10 years ago)
    # 10 years * 365 days * 24 hours * 3600 seconds * 10^9 ns/s
    old_birthtime_ns = original_birthtime - 10 * 365 * 24 * 3600 * 10**9
    # Ensure it's 100ns aligned (Windows precision)
    old_birthtime_ns = (old_birthtime_ns // 100) * 100
    set_birthtime(input_file, old_birthtime_ns)

    # Verify it was set correctly initially
    st_verify = os.stat(input_file)
    assert get_birthtime_ns(st_verify, input_file) == old_birthtime_ns

    # Archive it
    cmd(archiver, "create", "test", "input")

    # Extract it to a different location
    if not os.path.exists("output"):
        os.makedirs("output")
    with changedir("output"):
        cmd(archiver, "extract", "test")

    # Check restored birthtime
    restored_file = os.path.join("output", "input", "test_file")
    st_restored = os.stat(restored_file)
    restored_birthtime = get_birthtime_ns(st_restored, restored_file)

    assert restored_birthtime == old_birthtime_ns
