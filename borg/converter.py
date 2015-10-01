from binascii import hexlify
import os
import time

from .helpers import get_keys_dir
from .locking import UpgradableLock
from .repository import Repository, MAGIC
from .key import KeyfileKey, KeyfileNotFoundError

class AtticRepositoryConverter(Repository):
    def convert(self, dryrun=True):
        """convert an attic repository to a borg repository

        those are the files that need to be converted here, from most
        important to least important: segments, key files, and various
        caches, the latter being optional, as they will be rebuilt if
        missing."""
        print("reading segments from attic repository using borg")
        segments = [ filename for i, filename in self.io.segment_iterator() ]
        try:
            keyfile = self.find_attic_keyfile()
        except KeyfileNotFoundError:
            print("no key file found for repository")
        else:
            self.convert_keyfiles(keyfile, dryrun)
        self.close()
        # partial open: just hold on to the lock
        self.lock = UpgradableLock(os.path.join(self.path, 'lock'),
                                   exclusive=True).acquire()
        self.convert_segments(segments, dryrun)
        self.lock.release()
        self.lock = None
        self.convert_cache(dryrun)

    @staticmethod
    def convert_segments(segments, dryrun):
        """convert repository segments from attic to borg

        replacement pattern is `s/ATTICSEG/BORG_SEG/` in files in
        `$ATTIC_REPO/data/**`.

        luckily the magic string length didn't change so we can just
        replace the 8 first bytes of all regular files in there."""
        print("converting %d segments..." % len(segments))
        i = 0
        for filename in segments:
            print("\rconverting segment %d/%d in place, %.2f%% done (%s)"
                  % (i, len(segments), float(i)/len(segments), filename), end='')
            i += 1
            if dryrun:
                time.sleep(0.001)
            else:
                with open(filename, 'r+b') as segment:
                    segment.seek(0)
                    segment.write(MAGIC)
        print()

    def find_attic_keyfile(self):
        """find the attic keyfiles

        the keyfiles are loaded by `KeyfileKey.find_key_file()`. that
        finds the keys with the right identifier for the repo.

        this is expected to look into $HOME/.attic/keys or
        $ATTIC_KEYS_DIR for key files matching the given Borg
        repository.

        it is expected to raise an exception (KeyfileNotFoundError) if
        no key is found. whether that exception is from Borg or Attic
        is unclear.

        this is split in a separate function in case we want to use
        the attic code here directly, instead of our local
        implementation."""
        return AtticKeyfileKey.find_key_file(self)

    @staticmethod
    def convert_keyfiles(keyfile, dryrun):

        """convert key files from attic to borg

        replacement pattern is `s/ATTIC KEY/BORG_KEY/` in
        `get_keys_dir()`, that is `$ATTIC_KEYS_DIR` or
        `$HOME/.attic/keys`, and moved to `$BORG_KEYS_DIR` or
        `$HOME/.borg/keys`.

        no need to decrypt to convert. we need to rewrite the whole
        key file because magic string length changed, but that's not a
        problem because the keyfiles are small (compared to, say,
        all the segments)."""
        print("converting keyfile %s" % keyfile)
        with open(keyfile, 'r') as f:
            data = f.read()
        data = data.replace(AtticKeyfileKey.FILE_ID,
                            KeyfileKey.FILE_ID,
                            1)
        keyfile = os.path.join(get_keys_dir(),
                               os.path.basename(keyfile))
        print("writing borg keyfile to %s" % keyfile)
        if not dryrun:
            with open(keyfile, 'w') as f:
                f.write(data)

    def convert_cache(self, dryrun):
        """convert caches from attic to borg

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
        """
        raise NotImplementedError('cache conversion not implemented, next borg backup will take longer to rebuild those caches. use borg check --repair to rebuild now')

class AtticKeyfileKey(KeyfileKey):
    """backwards compatible Attic key file parser"""
    FILE_ID = 'ATTIC KEY'

    # verbatim copy from attic
    @staticmethod
    def get_keys_dir():
        """Determine where to repository keys and cache"""
        return os.environ.get('ATTIC_KEYS_DIR',
                              os.path.join(os.path.expanduser('~'), '.attic', 'keys'))

    @classmethod
    def find_key_file(cls, repository):
        """copy of attic's `find_key_file`_

        this has two small modifications:

        1. it uses the above `get_keys_dir`_ instead of the global one,
           assumed to be borg's

        2. it uses `repository.path`_ instead of
           `repository._location.canonical_path`_ because we can't
           assume the repository has been opened by the archiver yet
        """
        get_keys_dir = cls.get_keys_dir
        id = hexlify(repository.id).decode('ascii')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[10:] == id:
                    return filename
        raise KeyfileNotFoundError(repository.path, get_keys_dir())
