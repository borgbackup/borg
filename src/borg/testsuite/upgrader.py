import os
import tarfile

import pytest

from ..constants import *  # NOQA
from ..crypto.key import KeyfileKey
from ..upgrader import AtticRepositoryUpgrader, AtticKeyfileKey
from ..helpers import get_keys_dir
from ..repository import Repository
from . import are_hardlinks_supported


# tar with a repo and repo keyfile from attic
ATTIC_TAR = os.path.join(os.path.dirname(__file__), 'attic.tar.gz')


def untar(tarfname, path, what):
    """
    Extract the <tarfname> tar archive to <path>, including all entries starting with <what>.

    Return the path to <what>.
    """

    def files(members):
        for tarinfo in members:
            if tarinfo.name.startswith(what):
                yield tarinfo

    with tarfile.open(tarfname, 'r') as tf:
        tf.extractall(path, members=files(tf))

    return os.path.join(path, what)


def repo_valid(path):
    """
    Utility function to check if Borg can open a repository.

    :param path: the path to the repository
    :returns: whether Borg can check the repository
    """
    with Repository(str(path), exclusive=True, create=False) as repository:
        # can't check raises() because check() handles the error
        return repository.check()


def key_valid(path):
    """
    Check that the new key file is valid.

    :param path: the path to the key file
    :returns: whether the file starts with the Borg magic string
    """
    keyfile = os.path.join(get_keys_dir(),
                           os.path.basename(path))
    with open(keyfile) as f:
        return f.read().startswith(KeyfileKey.FILE_ID)


def make_attic_repo(dir):
    """
    Create an Attic repo with some content in it.

    :param dir: path to the repository to be created
    :returns: path to the Attic repository
    """
    # there is some stuff in that repo, copied from `RepositoryTestCase.test1`
    return untar(ATTIC_TAR, str(dir), 'repo')


@pytest.fixture()
def attic_repo(tmpdir):
    return make_attic_repo(tmpdir)


@pytest.fixture(params=[True, False])
def inplace(request):
    return request.param


def test_convert_segments(attic_repo, inplace):
    """Test segment conversion.

    This will load the given Attic repository, list all the segments,
    then convert them one at a time. We need to close the repo before
    conversion; otherwise we have errors from Borg.

    :param attic_repo: a populated Attic repository (fixture)
    """
    repo_path = attic_repo
    with pytest.raises(Repository.AtticRepository):
        repo_valid(repo_path)
    repository = AtticRepositoryUpgrader(repo_path, create=False)
    with repository:
        segments = [filename for i, filename in repository.io.segment_iterator()]
    repository.convert_segments(segments, dryrun=False, inplace=inplace)
    repository.convert_cache(dryrun=False)
    assert repo_valid(repo_path)


@pytest.fixture()
def attic_key_file(tmpdir, monkeypatch):
    """
    Create an Attic key file from the given repo, in the keys
    subdirectory of the given tmpdir.

    :param tmpdir: a temporary directory (a built-in fixture)
    :returns: path to the key file
    """
    keys_dir = untar(ATTIC_TAR, str(tmpdir), 'keys')

    # We use the repo dir for the created key file, because we do
    # not want to clutter existing key files.
    monkeypatch.setenv('ATTIC_KEYS_DIR', keys_dir)

    # We use the same directory for the converted files, which
    # will clutter the previously created one—which we don't care
    # about anyway. In real runs, the original key will be retained.
    monkeypatch.setenv('BORG_KEYS_DIR', keys_dir)
    monkeypatch.setenv('ATTIC_PASSPHRASE', 'test')

    return os.path.join(keys_dir, 'repo')


def test_keys(attic_repo, attic_key_file):
    """test key conversion

    test that we can convert the given key to a properly formatted
    borg key. assumes that the ATTIC_KEYS_DIR and BORG_KEYS_DIR have
    been properly populated by the attic_key_file fixture.

    :param attic_repo: path to an attic repository (fixture defined above)
    :param attic_key_file: path to an attic key file (fixture defined above)
    """
    keyfile_path = attic_key_file
    assert not key_valid(keyfile_path)  # not upgraded yet
    with AtticRepositoryUpgrader(attic_repo, create=False) as repository:
        keyfile = AtticKeyfileKey.find_key_file(repository)
        AtticRepositoryUpgrader.convert_keyfiles(keyfile, dryrun=False)
    assert key_valid(keyfile_path)


@pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
def test_convert_all(attic_repo, attic_key_file, inplace):
    """test all conversion steps

    this runs everything. mostly redundant test, since everything is
    done above. yet we expect a NotImplementedError because we do not
    convert caches yet.

    :param attic_repo: path to an attic repository (fixture defined above)
    :param attic_key_file: path to an attic key file (fixture defined above)
    """
    repo_path = attic_repo

    with pytest.raises(Repository.AtticRepository):
        repo_valid(repo_path)

    def stat_segment(path):
        return os.stat(os.path.join(path, 'data', '0', '0'))

    def first_inode(path):
        return stat_segment(path).st_ino

    orig_inode = first_inode(repo_path)
    with AtticRepositoryUpgrader(repo_path, create=False) as repository:
        # replicate command dispatch, partly
        os.umask(UMASK_DEFAULT)
        backup = repository.upgrade(dryrun=False, inplace=inplace)  # note: uses hardlinks internally
        if inplace:
            assert backup is None
            assert first_inode(repository.path) == orig_inode
        else:
            assert backup
            assert first_inode(repository.path) != first_inode(backup)
            # i have seen cases where the copied tree has world-readable
            # permissions, which is wrong
            if 'BORG_TESTS_IGNORE_MODES' not in os.environ:
                assert stat_segment(backup).st_mode & UMASK_DEFAULT == 0

    assert key_valid(attic_key_file)
    assert repo_valid(repo_path)


@pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
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
