import datetime
import os
import shutil
import time

from .crypto.key import KeyfileKey, KeyfileNotFoundError
from .constants import REPOSITORY_README
from .helpers import ProgressIndicatorPercent
from .helpers import get_base_dir, get_keys_dir, get_cache_dir
from .locking import Lock
from .logger import create_logger
from .repository import MAGIC
from .repositories.local import LocalRepository

logger = create_logger(__name__)

ATTIC_MAGIC = b'ATTICSEG'


class AtticRepositoryUpgrader(LocalRepository):
    def __init__(self, *args, **kw):
        kw['lock'] = False  # do not create borg lock files (now) in attic repo
        kw['check_segment_magic'] = False  # skip the Attic check when upgrading
        super().__init__(*args, **kw)

    def upgrade(self, dryrun=True, inplace=False, progress=False):
        """convert an attic repository to a borg repository

        those are the files that need to be upgraded here, from most
        important to least important: segments, key files, and various
        caches, the latter being optional, as they will be rebuilt if
        missing.

        we nevertheless do the order in reverse, as we prefer to do
        the fast stuff first, to improve interactivity.
        """
        with self:
            backup = None
            if not inplace:
                backup = '{}.before-upgrade-{:%Y-%m-%d-%H:%M:%S}'.format(self.path, datetime.datetime.now())
                logger.info('making a hardlink copy in %s', backup)
                if not dryrun:
                    shutil.copytree(self.path, backup, copy_function=os.link)
            logger.info("opening attic repository with borg and converting")
            # now lock the repo, after we have made the copy
            self.lock = Lock(os.path.join(self.path, 'lock'), exclusive=True, timeout=1.0).acquire()
            segments = [filename for i, filename in self.io.segment_iterator()]
            try:
                keyfile = self.find_attic_keyfile()
            except KeyfileNotFoundError:
                logger.warning("no key file found for repository")
            else:
                self.convert_keyfiles(keyfile, dryrun)
        # partial open: just hold on to the lock
        self.lock = Lock(os.path.join(self.path, 'lock'), exclusive=True).acquire()
        try:
            self.convert_cache(dryrun)
            self.convert_repo_index(dryrun=dryrun, inplace=inplace)
            self.convert_segments(segments, dryrun=dryrun, inplace=inplace, progress=progress)
            self.borg_readme()
        finally:
            self.lock.release()
            self.lock = None
        return backup

    def borg_readme(self):
        readme = os.path.join(self.path, 'README')
        os.remove(readme)
        with open(readme, 'w') as fd:
            fd.write(REPOSITORY_README)

    @staticmethod
    def convert_segments(segments, dryrun=True, inplace=False, progress=False):
        """convert repository segments from attic to borg

        replacement pattern is `s/ATTICSEG/BORG_SEG/` in files in
        `$ATTIC_REPO/data/**`.

        luckily the magic string length didn't change so we can just
        replace the 8 first bytes of all regular files in there."""
        logger.info("converting %d segments..." % len(segments))
        segment_count = len(segments)
        pi = ProgressIndicatorPercent(total=segment_count, msg="Converting segments %3.0f%%")
        for i, filename in enumerate(segments):
            if progress:
                pi.show(i)
            if dryrun:
                time.sleep(0.001)
            else:
                AtticRepositoryUpgrader.header_replace(filename, ATTIC_MAGIC, MAGIC, inplace=inplace)
        if progress:
            pi.finish()

    @staticmethod
    def header_replace(filename, old_magic, new_magic, inplace=True):
        with open(filename, 'r+b') as segment:
            segment.seek(0)
            # only write if necessary
            if segment.read(len(old_magic)) == old_magic:
                if inplace:
                    segment.seek(0)
                    segment.write(new_magic)
                else:
                    # rename the hardlink and rewrite the file. this works
                    # because the file is still open. so even though the file
                    # is renamed, we can still read it until it is closed.
                    os.rename(filename, filename + '.tmp')
                    with open(filename, 'wb') as new_segment:
                        new_segment.write(new_magic)
                        new_segment.write(segment.read())
                    # the little dance with the .tmp file is necessary
                    # because Windows won't allow overwriting an open file.
                    os.unlink(filename + '.tmp')

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
        `$HOME/.config/borg/keys`.

        no need to decrypt to convert. we need to rewrite the whole
        key file because magic string length changed, but that's not a
        problem because the keyfiles are small (compared to, say,
        all the segments)."""
        logger.info("converting keyfile %s" % keyfile)
        with open(keyfile, 'r') as f:
            data = f.read()
        data = data.replace(AtticKeyfileKey.FILE_ID, KeyfileKey.FILE_ID, 1)
        keyfile = os.path.join(get_keys_dir(), os.path.basename(keyfile))
        logger.info("writing borg keyfile to %s" % keyfile)
        if not dryrun:
            with open(keyfile, 'w') as f:
                f.write(data)

    def convert_repo_index(self, dryrun, inplace):
        """convert some repo files

        those are all hash indexes, so we need to
        `s/ATTICIDX/BORG_IDX/` in a few locations:

        * the repository index (in `$ATTIC_REPO/index.%d`, where `%d`
          is the `LocalRepository.get_index_transaction_id()`), which we
          should probably update, with a lock, see
          `LocalRepository.open()`, which i'm not sure we should use
          because it may write data on `LocalRepository.close()`...
        """
        transaction_id = self.get_index_transaction_id()
        if transaction_id is None:
            logger.warning('no index file found for repository %s' % self.path)
        else:
            index = os.path.join(self.path, 'index.%d' % transaction_id)
            logger.info("converting repo index %s" % index)
            if not dryrun:
                AtticRepositoryUpgrader.header_replace(index, b'ATTICIDX', b'BORG_IDX', inplace=inplace)

    def convert_cache(self, dryrun):
        """convert caches from attic to borg

        those are all hash indexes, so we need to
        `s/ATTICIDX/BORG_IDX/` in a few locations:

        * the `files` and `chunks` cache (in `$ATTIC_CACHE_DIR` or
          `$HOME/.cache/attic/<repoid>/`), which we could just drop,
          but if we'd want to convert, we could open it with the
          `Cache.open()`, edit in place and then `Cache.close()` to
          make sure we have locking right
        """
        # copy of attic's get_cache_dir()
        attic_cache_dir = os.environ.get('ATTIC_CACHE_DIR',
                                         os.path.join(get_base_dir(),
                                                      '.cache', 'attic'))
        attic_cache_dir = os.path.join(attic_cache_dir, self.id_str)
        borg_cache_dir = os.path.join(get_cache_dir(), self.id_str)

        def copy_cache_file(path):
            """copy the given attic cache path into the borg directory

            does nothing if dryrun is True. also expects
            attic_cache_dir and borg_cache_dir to be set in the parent
            scope, to the directories path including the repository
            identifier.

            :params path: the basename of the cache file to copy
            (example: "files" or "chunks") as a string

            :returns: the borg file that was created or None if no
            Attic cache file was found.

            """
            attic_file = os.path.join(attic_cache_dir, path)
            if os.path.exists(attic_file):
                borg_file = os.path.join(borg_cache_dir, path)
                if os.path.exists(borg_file):
                    logger.warning("borg cache file already exists in %s, not copying from Attic", borg_file)
                else:
                    logger.info("copying attic cache file from %s to %s" % (attic_file, borg_file))
                    if not dryrun:
                        shutil.copyfile(attic_file, borg_file)
                return borg_file
            else:
                logger.warning("no %s cache file found in %s" % (path, attic_file))
                return None

        # XXX: untested, because generating cache files is a PITA, see
        # Archiver.do_create() for proof
        if os.path.exists(attic_cache_dir):
            if not os.path.exists(borg_cache_dir):
                os.makedirs(borg_cache_dir)

            # file that we don't have a header to convert, just copy
            for cache in ['config', 'files']:
                copy_cache_file(cache)

            # we need to convert the headers of those files, copy first
            for cache in ['chunks']:
                cache = copy_cache_file(cache)
                logger.info("converting cache %s" % cache)
                if not dryrun:
                    AtticRepositoryUpgrader.header_replace(cache, b'ATTICIDX', b'BORG_IDX')


class AtticKeyfileKey(KeyfileKey):
    """backwards compatible Attic key file parser"""
    FILE_ID = 'ATTIC KEY'

    # verbatim copy from attic
    @staticmethod
    def get_keys_dir():
        """Determine where to repository keys and cache"""
        return os.environ.get('ATTIC_KEYS_DIR',
                              os.path.join(get_base_dir(), '.attic', 'keys'))

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
        keys_dir = get_keys_dir()
        if not os.path.exists(keys_dir):
            raise KeyfileNotFoundError(repository.path, keys_dir)
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[10:] == repository.id_str:
                    return filename
        raise KeyfileNotFoundError(repository.path, keys_dir)


class BorgRepositoryUpgrader(LocalRepository):
    def upgrade(self, dryrun=True, inplace=False, progress=False):
        """convert an old borg repository to a current borg repository
        """
        logger.info("converting borg 0.xx to borg current")
        with self:
            try:
                keyfile = self.find_borg0xx_keyfile()
            except KeyfileNotFoundError:
                logger.warning("no key file found for repository")
            else:
                self.move_keyfiles(keyfile, dryrun)

    def find_borg0xx_keyfile(self):
        return Borg0xxKeyfileKey.find_key_file(self)

    def move_keyfiles(self, keyfile, dryrun):
        filename = os.path.basename(keyfile)
        new_keyfile = os.path.join(get_keys_dir(), filename)
        try:
            os.rename(keyfile, new_keyfile)
        except FileExistsError:
            # likely the attic -> borg upgrader already put it in the final location
            pass


class Borg0xxKeyfileKey(KeyfileKey):
    """backwards compatible borg 0.xx key file parser"""

    @staticmethod
    def get_keys_dir():
        return os.environ.get('BORG_KEYS_DIR',
                              os.path.join(get_base_dir(), '.borg', 'keys'))

    @classmethod
    def find_key_file(cls, repository):
        get_keys_dir = cls.get_keys_dir
        keys_dir = get_keys_dir()
        if not os.path.exists(keys_dir):
            raise KeyfileNotFoundError(repository.path, keys_dir)
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[len(cls.FILE_ID) + 1:] == repository.id_str:
                    return filename
        raise KeyfileNotFoundError(repository.path, keys_dir)
