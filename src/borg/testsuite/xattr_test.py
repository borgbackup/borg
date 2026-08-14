import os

import pytest

from ..platform.xattr import buffer, split_lstring
from ..xattr import is_enabled, getxattr, setxattr, listxattr, XATTR_FAKEROOT
from ..platformflags import is_linux, is_sunos

# Whether xattrs can be set on a symlink itself:
# Linux does not allow setting user.* xattrs on symlinks; on illumos/Solaris,
# symlinks cannot have extended attributes at all.
symlink_xattrs = not is_linux and not is_sunos


@pytest.fixture()
def tempfile_symlink(tmp_path):
    if not is_enabled(tmp_path):
        pytest.skip("xattrs not enabled on the filesystem")
    with open(os.fspath(tmp_path / "xattr"), "w") as temp_file:
        symlink = temp_file.name + ".symlink"
        os.symlink(temp_file.name, symlink)
        yield temp_file, symlink


def assert_equal_se(is_x, want_x):
    # Check two xattr lists for equality, but ignore the security.selinux attribute.
    is_x = set(is_x) - {b"security.selinux", b"com.apple.provenance"}
    want_x = set(want_x)
    assert is_x == want_x


def test(tempfile_symlink):
    temp_file, symlink = tempfile_symlink
    tmp_fn = os.fsencode(temp_file.name)
    tmp_lfn = os.fsencode(symlink)
    tmp_fd = temp_file.fileno()
    assert_equal_se(listxattr(tmp_fn), [])
    assert_equal_se(listxattr(tmp_fd), [])
    assert_equal_se(listxattr(tmp_lfn), [])
    setxattr(tmp_fn, b"user.foo", b"bar")
    setxattr(tmp_fd, b"user.bar", b"foo")
    setxattr(tmp_fn, b"user.empty", b"")
    if symlink_xattrs:
        setxattr(tmp_lfn, b"user.linkxattr", b"baz")
    assert_equal_se(listxattr(tmp_fn), [b"user.foo", b"user.bar", b"user.empty"])
    assert_equal_se(listxattr(tmp_fd), [b"user.foo", b"user.bar", b"user.empty"])
    assert_equal_se(listxattr(tmp_lfn, follow_symlinks=True), [b"user.foo", b"user.bar", b"user.empty"])
    if symlink_xattrs:
        assert_equal_se(listxattr(tmp_lfn), [b"user.linkxattr"])
    assert getxattr(tmp_fn, b"user.foo") == b"bar"
    assert getxattr(tmp_fd, b"user.foo") == b"bar"
    assert getxattr(tmp_lfn, b"user.foo", follow_symlinks=True) == b"bar"
    if symlink_xattrs:
        assert getxattr(tmp_lfn, b"user.linkxattr") == b"baz"
    assert getxattr(tmp_fn, b"user.empty") == b""


@pytest.mark.skipif(is_sunos, reason="the illumos/Solaris xattr backend does not use the shared buffer")
def test_listxattr_buffer_growth(tempfile_symlink):
    temp_file, symlink = tempfile_symlink
    tmp_fn = os.fsencode(temp_file.name)
    # Make it work even with ext4, which imposes relatively low limits.
    buffer.resize(size=64, init=True)
    # The raw xattr key list will be > 64.
    keys = [b"user.attr%d" % i for i in range(20)]
    for key in keys:
        setxattr(tmp_fn, key, b"x")
    got_keys = listxattr(tmp_fn)
    assert_equal_se(got_keys, keys)
    assert len(buffer) > 64


@pytest.mark.skipif(is_sunos, reason="the illumos/Solaris xattr backend does not use the shared buffer")
def test_getxattr_buffer_growth(tempfile_symlink):
    temp_file, symlink = tempfile_symlink
    tmp_fn = os.fsencode(temp_file.name)
    # Make it work even with ext4, which imposes relatively low limits.
    buffer.resize(size=64, init=True)
    value = b"x" * 126
    setxattr(tmp_fn, b"user.big", value)
    got_value = getxattr(tmp_fn, b"user.big")
    assert value == got_value
    assert len(buffer) == 128


@pytest.mark.parametrize(
    "lstring, expected", [(b"", []), (b"\x00", [b""]), (b"\x01a", [b"a"]), (b"\x01a\x02cd", [b"a", b"cd"])]
)
def test_split_lstring(lstring, expected):
    assert split_lstring(lstring) == expected


def test_xattr_fakeroot_flag():
    """XATTR_FAKEROOT must be False when not on Linux or when fakeroot is not active."""
    if not is_linux:
        assert XATTR_FAKEROOT is False
    if "FAKEROOTKEY" not in os.environ:
        assert XATTR_FAKEROOT is False
