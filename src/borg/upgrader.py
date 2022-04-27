import os

from .crypto.key import KeyfileKey, KeyfileNotFoundError
from .helpers import get_base_dir, get_keys_dir
from .logger import create_logger
from .repository import Repository

logger = create_logger(__name__)


class BorgRepositoryUpgrader(Repository):
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
            with open(filename) as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[len(cls.FILE_ID) + 1:] == repository.id_str:
                    return filename
        raise KeyfileNotFoundError(repository.path, keys_dir)
