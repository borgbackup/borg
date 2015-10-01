import os
import shutil
import tempfile

import pytest

try:
    import attic.repository
    import attic.key
    import attic.helpers
except ImportError:
    attic = None

from ..converter import AtticRepositoryConverter, AtticKeyfileKey
from ..helpers import get_keys_dir
from ..key import KeyfileKey
from ..repository import Repository, MAGIC

pytestmark = pytest.mark.skipif(attic is None,
                                reason='cannot find an attic install')

def repo_open(path, repo_type=Repository, create=False):
    return repo_type(os.path.join(str(path), 'repository'), create=create)

def repo_valid(path):
    repository = repo_open(str(path))
    # can't check raises() because check() handles the error
    state = repository.check()
    repository.close()
    return state

@pytest.fixture(autouse=True)
def attic_repo(tmpdir):
    attic_repo = repo_open(str(tmpdir),
                                repo_type=attic.repository.Repository,
                                create=True)
    # throw some stuff in that repo, copied from `RepositoryTestCase.test1`
    for x in range(100):
        attic_repo.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
    attic_repo.close()
    return attic_repo

@pytest.mark.usefixtures("tmpdir")
def test_convert_segments(tmpdir, attic_repo):
    # check should fail because of magic number
    assert not repo_valid(tmpdir)
    print("opening attic repository with borg and converting")
    repo = repo_open(tmpdir, repo_type=AtticRepositoryConverter)
    segments = [filename for i, filename in repo.io.segment_iterator()]
    repo.close()
    repo.convert_segments(segments, dryrun=False)
    assert repo_valid(tmpdir)

class MockArgs:
    def __init__(self, path):
        self.repository = attic.helpers.Location(path)

@pytest.fixture()
def attic_key_file(attic_repo, tmpdir):
    keys_dir = str(tmpdir.mkdir('keys'))

    # we use the repo dir for the created keyfile, because we do
    # not want to clutter existing keyfiles
    os.environ['ATTIC_KEYS_DIR'] = keys_dir

    # we use the same directory for the converted files, which
    # will clutter the previously created one, which we don't care
    # about anyways. in real runs, the original key will be retained.
    os.environ['BORG_KEYS_DIR'] = keys_dir
    os.environ['ATTIC_PASSPHRASE'] = 'test'
    return attic.key.KeyfileKey.create(attic_repo,
                                       MockArgs(keys_dir))

def test_keys(tmpdir, attic_repo, attic_key_file):
    repository = repo_open(tmpdir,
                           repo_type=AtticRepositoryConverter)
    keyfile = AtticKeyfileKey.find_key_file(repository)
    AtticRepositoryConverter.convert_keyfiles(keyfile, dryrun=False)

    # check that the new keyfile is alright
    keyfile = os.path.join(get_keys_dir(),
                           os.path.basename(attic_key_file.path))
    with open(keyfile, 'r') as f:
        assert f.read().startswith(KeyfileKey.FILE_ID)

def test_convert_all(tmpdir, attic_repo, attic_key_file):
    # check should fail because of magic number
    assert not repo_valid(tmpdir)
    print("opening attic repository with borg and converting")
    repo = repo_open(tmpdir, repo_type=AtticRepositoryConverter)
    with pytest.raises(NotImplementedError):
        repo.convert(dryrun=False)
    # check that the new keyfile is alright
    keyfile = os.path.join(get_keys_dir(),
                           os.path.basename(attic_key_file.path))
    with open(keyfile, 'r') as f:
        assert f.read().startswith(KeyfileKey.FILE_ID)
    assert repo_valid(tmpdir)
