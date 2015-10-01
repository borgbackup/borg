import binascii
import os
import pytest
import shutil
import tempfile

import attic.repository

from ..helpers import IntegrityError
from ..repository import Repository, MAGIC
from . import BaseTestCase

class NotImplementedException(Exception):
    pass

class ConversionTestCase(BaseTestCase):

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

    def test_convert(self):
        self.repository = self.open(self.tmppath)
        # check should fail because of magic number
        assert not self.repository.check() # can't check raises() because check() handles the error
        self.repository.close()
        self.convert()
        self.repository = self.open(self.tmppath)
        assert self.repository.check() # can't check raises() because check() handles the error
        self.repository.close()

    def convert(self):
        '''convert an attic repository to a borg repository

        those are the files that need to be converted here, from most
        important to least important: segments, key files, and various
        caches, the latter being optional, as they will be rebuilt if
        missing.'''
        self.convert_segments()
        with pytest.raises(NotImplementedException):
            self.convert_keyfiles()
        with pytest.raises(NotImplementedException):
            self.convert_cache()

    def convert_segments(self):
        '''convert repository segments from attic to borg

        replacement pattern is `s/ATTICSEG/BORG_SEG/` in files in
        `$ATTIC_REPO/data/**`.

        luckily the segment length didn't change so we can just
        replace the 8 first bytes of all regular files in there.

        `Repository.segment_iterator()` could be used here.'''
        self.repository = self.open(self.tmppath)
        segs = [ filename for i, filename in self.repository.io.segment_iterator() ]
        self.repository.close()
        for filename in segs:
            print("converting segment %s..." % filename)
            with open(filename, 'r+b') as segment:
                segment.seek(0)
                segment.write(MAGIC)

    def convert_keyfiles(self):
        '''convert key files from attic to borg

        replacement pattern is `s/ATTIC KEY/BORG_KEY/` in
        `get_keys_dir()`, that is `$ATTIC_KEYS_DIR` or
        `$HOME/.attic/keys`, and moved to `$BORG_KEYS_DIR` or
        `$HOME/.borg/keys`.

        the keyfiles are loaded by `KeyfileKey.find_key_file()`. that
        finds the keys with the right identifier for the repo, no need
        to decrypt to convert. will need to rewrite the whole key file
        because magic number length changed.'''
        raise NotImplementedException('not implemented')

    def convert_cache(self):
        '''convert caches from attic to borg

        those are all hash indexes, so we need to
        `s/ATTICIDX/BORG_IDX/` in a few locations:
        
        * the repository index (in `$ATTIC_REPO/index.%d`, where `%d`
          is the `Repository.get_index_transaction_id()`), which we
          should probably update, with a lock, see
          `Repository.open()`, which i'm not sure we should use
          because it may write data on `Repository.close()`...

        * the `files` and `chunks` cache (in
          `$HOME/.cache/attic/<repoid>/`), which we could just drop,
          but if we'd want to convert, we could open it with the
          `Cache.open()`, edit in place and then `Cache.close()` to
          make sure we have locking right
        '''
        raise NotImplementedException('not implemented')

    def tearDown(self):
        shutil.rmtree(self.tmppath)
