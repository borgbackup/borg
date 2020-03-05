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
    extract <tarfname> tar archive to <path>, all stuff starting with <what>.

    return path to <what>.
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


def make_attic_repo(dir):
    """
    create an attic repo with some stuff in it

    :param dir: path to the repository to be created
    :returns: path to attic repository
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
    """test segment conversion

    this will load the given attic repository, list all the segments
    then convert them one at a time. we need to close the repo before
    conversion otherwise we have errors from borg

    :param attic_repo: a populated attic repository (fixture)
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
    create an attic key file from the given repo, in the keys
    subdirectory of the given tmpdir

    :param tmpdir: a temporary directory (a builtin fixture)
    :returns: path to key file
    """
    keys_dir = untar(ATTIC_TAR, str(tmpdir), 'keys')

    # we use the repo dir for the created keyfile, because we do
    # not want to clutter existing keyfiles
    monkeypatch.setenv('ATTIC_KEYS_DIR', keys_dir)

    # we use the same directory for the converted files, which
    # will clutter the previously created one, which we don't care
    # about anyways. in real runs, the original key will be retained.
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
