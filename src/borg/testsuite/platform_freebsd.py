"""Dummy file for now, will eventually contain FreeBSD ACL tests."""
import pytest

from .platform import skipif_not_freebsd

# set module-level skips
pytestmark = [skipif_not_freebsd]


def get_acl():
    return


def get_set_acl():
    return


@pytest.mark.skip(reason="not yet implemented")
def test_access_acl():
    pass


@pytest.mark.skip(reason="not yet implemented")
def test_default_acl():
    pass


@pytest.mark.skip(reason="not yet implemented")
def test_nfs4_acl():
    pass
