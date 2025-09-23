import sys
import pytest

from ...helpers.msgpack import is_slow_msgpack
from ...platform import is_cygwin


def expected_py_mp_slow_combination():
    """Do we expect msgpack to be slow in this environment?"""
    # We need to import the upstream msgpack package here, not helpers.msgpack:
    import msgpack

    # msgpack is slow on Cygwin
    if is_cygwin:
        return True
    # msgpack < 1.0.6 did not have Python 3.12 wheels
    if sys.version_info[:2] == (3, 12) and msgpack.version < (1, 0, 6):
        return True
    # Otherwise, we expect msgpack to be fast!
    return False


@pytest.mark.skipif(expected_py_mp_slow_combination(), reason="ignore expected slow msgpack")
def test_is_slow_msgpack():
    # we need to import upstream msgpack package here, not helpers.msgpack:
    import msgpack
    import msgpack.fallback

    saved_packer = msgpack.Packer
    try:
        msgpack.Packer = msgpack.fallback.Packer
        assert is_slow_msgpack()
    finally:
        msgpack.Packer = saved_packer
    # This tests that we have fast msgpack on the test platform:
    assert not is_slow_msgpack()
