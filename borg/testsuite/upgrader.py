import os

import pytest

try:
    import attic.repository
    import attic.key
    import attic.helpers
except ImportError:
    attic = None

from ..upgrader import AtticRepositoryUpgrader, AtticKeyfileKey
from ..helpers import get_keys_dir
from ..key import KeyfileKey
from ..archiver import UMASK_DEFAULT
from ..repository import Repository


def repo_valid(path):
    """
    utility function to check if borg can open a repository

    :param path: the path to the repository
    :returns: if borg can check the repository
    """
    with Repository(str(path), exclusive=True, create=False) as repository:
        # can't check raises() because check() handles the error
        return repository.check()


def key_valid(path):
    """
    check that the new keyfile is alright

    :param path: the path to the key file
    :returns: if the file starts with the borg magic string
    """
    keyfile = os.path.join(get_keys_dir(),
                           os.path.basename(path))
    with open(keyfile, 'r') as f:
        return f.read().startswith(KeyfileKey.FILE_ID)


@pytest.fixture()
def attic_repo(tmpdir):
    """
    create an attic repo with some stuff in it

    :param tmpdir: path to the repository to be created
    :returns: a attic.repository.Repository object
    """
    attic_repo = attic.repository.Repository(str(tmpdir), create=True)
    # throw some stuff in that repo, copied from `RepositoryTestCase.test1`
    for x in range(100):
        attic_repo.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
    attic_repo.commit()
    attic_repo.close()
    return attic_repo


@pytest.fixture(params=[True, False])
def inplace(request):
    return request.param


@pytest.mark.skipif(attic is None, reason='cannot find an attic install')
def test_convert_segments(tmpdir, attic_repo, inplace):
    """test segment conversion

    this will load the given attic repository, list all the segments
    then convert them one at a time. we need to close the repo before
    conversion otherwise we have errors from borg

    :param tmpdir: a temporary directory to run the test in (builtin
    fixture)
    :param attic_repo: a populated attic repository (fixture)
    """
    # check should fail because of magic number
    assert not repo_valid(tmpdir)
    repository = AtticRepositoryUpgrader(str(tmpdir), create=False)
    with repository:
        segments = [filename for i, filename in repository.io.segment_iterator()]
    repository.convert_segments(segments, dryrun=False, inplace=inplace)
    repository.convert_cache(dryrun=False)
    assert repo_valid(tmpdir)


class MockArgs:
    """
    mock attic location

    this is used to simulate a key location with a properly loaded
    repository object to create a key file
    """
    def __init__(self, path):
        self.repository = attic.helpers.Location(path)


@pytest.fixture()
def attic_key_file(attic_repo, tmpdir, monkeypatch):
    """
    create an attic key file from the given repo, in the keys
    subdirectory of the given tmpdir

    :param attic_repo: an attic.repository.Repository object (fixture
    define above)
    :param tmpdir: a temporary directory (a builtin fixture)
    :returns: the KeyfileKey object as returned by
    attic.key.KeyfileKey.create()
    """
    keys_dir = str(tmpdir.mkdir('keys'))

    # we use the repo dir for the created keyfile, because we do
    # not want to clutter existing keyfiles
    monkeypatch.setenv('ATTIC_KEYS_DIR', keys_dir)

    # we use the same directory for the converted files, which
    # will clutter the previously created one, which we don't care
    # about anyways. in real runs, the original key will be retained.
    monkeypatch.setenv('BORG_KEYS_DIR', keys_dir)
    monkeypatch.setenv('ATTIC_PASSPHRASE', 'test')
    return attic.key.KeyfileKey.create(attic_repo,
                                       MockArgs(keys_dir))


@pytest.mark.skipif(attic is None, reason='cannot find an attic install')
def test_keys(tmpdir, attic_repo, attic_key_file):
    """test key conversion

    test that we can convert the given key to a properly formatted
    borg key. assumes that the ATTIC_KEYS_DIR and BORG_KEYS_DIR have
    been properly populated by the attic_key_file fixture.

    :param tmpdir: a temporary directory (a builtin fixture)
    :param attic_repo: an attic.repository.Repository object (fixture
    define above)
    :param attic_key_file: an attic.key.KeyfileKey (fixture created above)
    """
    with AtticRepositoryUpgrader(str(tmpdir), create=False) as repository:
        keyfile = AtticKeyfileKey.find_key_file(repository)
        AtticRepositoryUpgrader.convert_keyfiles(keyfile, dryrun=False)
    assert key_valid(attic_key_file.path)


@pytest.mark.skipif(attic is None, reason='cannot find an attic install')
def test_convert_all(tmpdir, attic_repo, attic_key_file, inplace):
    """test all conversion steps

    this runs everything. mostly redundant test, since everything is
    done above. yet we expect a NotImplementedError because we do not
    convert caches yet.

    :param tmpdir: a temporary directory (a builtin fixture)
    :param attic_repo: an attic.repository.Repository object (fixture
    define above)
    :param attic_key_file: an attic.key.KeyfileKey (fixture created above)
    """
    # check should fail because of magic number
    assert not repo_valid(tmpdir)

    def stat_segment(path):
        return os.stat(os.path.join(path, 'data', '0', '0'))

    def first_inode(path):
        return stat_segment(path).st_ino

    orig_inode = first_inode(attic_repo.path)
    with AtticRepositoryUpgrader(str(tmpdir), create=False) as repository:
        # replicate command dispatch, partly
        os.umask(UMASK_DEFAULT)
        backup = repository.upgrade(dryrun=False, inplace=inplace)
        if inplace:
            assert backup is None
            assert first_inode(repository.path) == orig_inode
        else:
            assert backup
            assert first_inode(repository.path) != first_inode(backup)
            # i have seen cases where the copied tree has world-readable
            # permissions, which is wrong
            assert stat_segment(backup).st_mode & UMASK_DEFAULT == 0

    assert key_valid(attic_key_file.path)
    assert repo_valid(tmpdir)


def test_hardlink(tmpdir, inplace):
    """test that we handle hard links properly

    that is, if we are in "inplace" mode, hardlinks should *not*
    change (ie. we write to the file directly, so we do not rewrite the
    whole file, and we do not re-create the file).

    if we are *not* in inplace mode, then the inode should change, as
    we are supposed to leave the original inode alone."""
    a = str(tmpdir.join('a'))
    with open(a, 'wb') as tmp:
        tmp.write(b'aXXX')
    b = str(tmpdir.join('b'))
    os.link(a, b)
    AtticRepositoryUpgrader.header_replace(b, b'a', b'b', inplace=inplace)
    if not inplace:
        assert os.stat(a).st_ino != os.stat(b).st_ino
    else:
        assert os.stat(a).st_ino == os.stat(b).st_ino
    with open(b, 'rb') as tmp:
        assert tmp.read() == b'bXXX'
