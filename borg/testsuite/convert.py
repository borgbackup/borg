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
pytestmark = pytest.mark.skipif(attic is None,
                                reason='cannot find an attic install')

from ..converter import AtticRepositoryConverter, AtticKeyfileKey
from ..helpers import get_keys_dir
from ..key import KeyfileKey
from ..repository import Repository, MAGIC
from . import BaseTestCase


class ConversionTestCase(BaseTestCase):

    def open(self, path, repo_type=Repository, create=False):
        return repo_type(os.path.join(path, 'repository'), create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.attic_repo = self.open(self.tmppath,
                                    repo_type=attic.repository.Repository,
                                    create=True)
        # throw some stuff in that repo, copied from `RepositoryTestCase.test1`
        for x in range(100):
            self.attic_repo.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
        self.attic_repo.close()

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    def repo_valid(self,):
        repository = self.open(self.tmppath)
        # can't check raises() because check() handles the error
        state = repository.check()
        repository.close()
        return state

    def test_convert_segments(self):
        # check should fail because of magic number
        assert not self.repo_valid()
        print("opening attic repository with borg and converting")
        repo = self.open(self.tmppath, repo_type=AtticRepositoryConverter)
        segments = [filename for i, filename in repo.io.segment_iterator()]
        repo.close()
        repo.convert_segments(segments, dryrun=False)
        assert self.repo_valid()


class EncryptedConversionTestCase(ConversionTestCase):
    class MockArgs:
        def __init__(self, path):
            self.repository = attic.helpers.Location(path)

    def setUp(self):
        super().setUp()

        # we use the repo dir for the created keyfile, because we do
        # not want to clutter existing keyfiles
        os.environ['ATTIC_KEYS_DIR'] = self.tmppath

        # we use the same directory for the converted files, which
        # will clutter the previously created one, which we don't care
        # about anyways. in real runs, the original key will be retained.
        os.environ['BORG_KEYS_DIR'] = self.tmppath
        os.environ['ATTIC_PASSPHRASE'] = 'test'
        self.key = attic.key.KeyfileKey.create(self.attic_repo,
                                               self.MockArgs(self.tmppath))

    def test_keys(self):
        repository = self.open(self.tmppath,
                               repo_type=AtticRepositoryConverter)
        keyfile = AtticKeyfileKey.find_key_file(repository)
        AtticRepositoryConverter.convert_keyfiles(keyfile, dryrun=False)

        # check that the new keyfile is alright
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(self.key.path))
        with open(keyfile, 'r') as f:
            assert f.read().startswith(KeyfileKey.FILE_ID)

    def test_convert_all(self):
        # check should fail because of magic number
        assert not self.repo_valid()
        print("opening attic repository with borg and converting")
        repo = self.open(self.tmppath, repo_type=AtticRepositoryConverter)
        with pytest.raises(NotImplementedError):
            repo.convert(dryrun=False)
        # check that the new keyfile is alright
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(self.key.path))
        with open(keyfile, 'r') as f:
            assert f.read().startswith(KeyfileKey.FILE_ID)
        assert self.repo_valid()
