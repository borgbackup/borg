import binascii
import os
import pytest
import shutil
import tempfile

import attic.repository
import attic.key
import attic.helpers

from ..helpers import IntegrityError, get_keys_dir
from ..repository import Repository, MAGIC
from ..key import KeyfileKey, KeyfileNotFoundError
from . import BaseTestCase

class NotImplementedException(Exception):
    pass

class AtticKeyfileKey(KeyfileKey):
    '''backwards compatible Attick key file parser'''
    FILE_ID = 'ATTIC KEY'

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
        self.keysdir = self.MockArgs(self.tmppath)
        os.environ['ATTIC_KEYS_DIR'] = self.tmppath
        os.environ['ATTIC_PASSPHRASE'] = 'test'
        self.key = attic.key.KeyfileKey.create(self.attic_repo, self.keysdir)
        self.attic_repo.close()

    def test_convert(self):
        self.repository = self.open(self.tmppath)
        # check should fail because of magic number
        assert not self.repository.check() # can't check raises() because check() handles the error
        self.repository.close()
        os.environ['BORG_KEYS_DIR'] = self.tmppath
        self.convert()
        # check that the new keyfile is alright
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(self.key.path))
        with open(keyfile, 'r') as f:
            assert f.read().startswith(KeyfileKey.FILE_ID)
        self.repository = self.open(self.tmppath)
        assert self.repository.check()
        self.repository.close()

    def convert(self):
        '''convert an attic repository to a borg repository

        those are the files that need to be converted here, from most
        important to least important: segments, key files, and various
        caches, the latter being optional, as they will be rebuilt if
        missing.'''
        self.repository = self.open(self.tmppath)
        segments = [ filename for i, filename in self.repository.io.segment_iterator() ]
        try:
            keyfile = self.find_attic_keyfile()
        except KeyfileNotFoundError:
            print("no key file found for repository, not converting")
        else:
            self.convert_keyfiles(keyfile)
        self.repository.close()
        self.convert_segments(segments)
        with pytest.raises(NotImplementedException):
            self.convert_cache()

    def convert_segments(self, segments):
        '''convert repository segments from attic to borg

        replacement pattern is `s/ATTICSEG/BORG_SEG/` in files in
        `$ATTIC_REPO/data/**`.

        luckily the segment length didn't change so we can just
        replace the 8 first bytes of all regular files in there.'''
        for filename in segments:
            print("converting segment %s..." % filename)
            with open(filename, 'r+b') as segment:
                segment.seek(0)
                segment.write(MAGIC)

    def find_attic_keyfile(self):
        '''find the attic keyfiles

        this is expected to look into $HOME/.attic/keys or
        $ATTIC_KEYS_DIR for key files matching the given Borg
        repository.

        it is expected to raise an exception (KeyfileNotFoundError) if
        no key is found. whether that exception is from Borg or Attic
        is unclear.

        this is split in a separate function in case we want to
        reimplement the attic code here.
        '''
        self.repository._location = attic.helpers.Location(self.tmppath)
        return attic.key.KeyfileKey().find_key_file(self.repository)

    def convert_keyfiles(self, keyfile):

        '''convert key files from attic to borg

        replacement pattern is `s/ATTIC KEY/BORG_KEY/` in
        `get_keys_dir()`, that is `$ATTIC_KEYS_DIR` or
        `$HOME/.attic/keys`, and moved to `$BORG_KEYS_DIR` or
        `$HOME/.borg/keys`.

        the keyfiles are loaded by `KeyfileKey.find_key_file()`. that
        finds the keys with the right identifier for the repo, no need
        to decrypt to convert. will need to rewrite the whole key file
        because magic number length changed.'''
        print("converting keyfile %s" % keyfile)
        with open(keyfile, 'r') as f:
            data = f.read()
        data = data.replace(AtticKeyfileKey.FILE_ID,
                            KeyfileKey.FILE_ID,
                            1)
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(keyfile))
        print("writing borg keyfile to %s" % keyfile)
        with open(keyfile, 'w') as f:
            f.write(data)
        with open(keyfile, 'r') as f:
            data = f.read()
        assert data.startswith(KeyfileKey.FILE_ID)

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
