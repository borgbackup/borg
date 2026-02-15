import os
import pytest
from ...platformflags import is_win32
from ...platform import set_birthtime, get_birthtime_ns


@pytest.mark.skipif(not is_win32, reason="Windows only test")
def test_set_birthtime(tmpdir):
    test_file = str(tmpdir.join("test_birthtime.txt"))
    with open(test_file, "w") as f:
        f.write("content")

    st = os.stat(test_file)
    original_birthtime = get_birthtime_ns(st, test_file)
    assert original_birthtime is not None

    # Set a new birthtime (e.g., 1 hour ago)
    # We use a value that is clearly different from 'now'
    new_birthtime_ns = original_birthtime - 3600 * 10**9

    set_birthtime(test_file, new_birthtime_ns)

    st_new = os.stat(test_file)
    restored_birthtime = get_birthtime_ns(st_new, test_file)

    # Windows FILETIME has 100ns precision.
    # Our set_birthtime implementation handles this.
    # We check if it matches (allowing for the 100ns granularity if needed,
    # but here we subtracted exactly 1 hour which is a multiple of 100ns)
    assert restored_birthtime == new_birthtime_ns
