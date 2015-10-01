import os
import pytest
import shutil
import tempfile

try:
    import attic.repository
    import attic.key
    import attic.helpers
except ImportError:
    attic = None
pytestmark = pytest.mark.skipif(attic is None,
                                reason = 'cannot find an attic install')

from ..converter import AtticRepositoryConverter, NotImplementedException
from ..helpers import get_keys_dir
from ..key import KeyfileKey
from ..repository import Repository, MAGIC
from . import BaseTestCase

class ConversionTestCase(BaseTestCase):

    class MockArgs:
        def __init__(self, path):
            self.repository = attic.helpers.Location(path)

    def open(self, path, repo_type  = Repository, create=False):
        return repo_type(os.path.join(path, 'repository'), create = create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.attic_repo = self.open(self.tmppath,
                                    repo_type = attic.repository.Repository,
                                    create = True)
        # throw some stuff in that repo, copied from `RepositoryTestCase.test1`_
        for x in range(100):
            self.attic_repo.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
        self.attic_repo.close()

        # we use the repo dir for the created keyfile, because we do
        # not want to clutter existing keyfiles
        os.environ['ATTIC_KEYS_DIR'] = self.tmppath

        # we use the same directory for the converted files, which
        # will clutter the previously created one, which we don't care
        # about anyways. in real runs, the original key will be retained.
        os.environ['BORG_KEYS_DIR'] = self.tmppath
        os.environ['ATTIC_PASSPHRASE'] = 'test'
        self.key = attic.key.KeyfileKey.create(self.attic_repo, self.MockArgs(self.tmppath))

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    def check_repo(self, state = True):
        if not state:
            print("this will show an error, this is expected")
        self.repository = self.open(self.tmppath)
        assert self.repository.check() is state # can't check raises() because check() handles the error
        self.repository.close()

    def test_convert(self):
        # check should fail because of magic number
        self.check_repo(False)
        print("opening attic repository with borg and converting")
        with pytest.raises(NotImplementedException):
            self.open(self.tmppath, repo_type = AtticRepositoryConverter).convert(dryrun=False)
        # check that the new keyfile is alright
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(self.key.path))
        with open(keyfile, 'r') as f:
            assert f.read().startswith(KeyfileKey.FILE_ID)
        self.check_repo()
