import fcntl

from borg.helpers import Error


class UpgradableLock:

    class ReadLockFailed(Error):
        """Failed to acquire read lock on {}"""

    class WriteLockFailed(Error):
        """Failed to acquire write lock on {}"""

    def __init__(self, path, exclusive=False):
        self.path = path
        try:
            self.fd = open(path, 'r+')
        except IOError:
            self.fd = open(path, 'r')
        try:
            if exclusive:
                fcntl.lockf(self.fd, fcntl.LOCK_EX)
            else:
                fcntl.lockf(self.fd, fcntl.LOCK_SH)
        # Python 3.2 raises IOError, Python3.3+ raises OSError
        except (IOError, OSError):
            if exclusive:
                raise self.WriteLockFailed(self.path)
            else:
                raise self.ReadLockFailed(self.path)
        self.is_exclusive = exclusive

    def upgrade(self):
        try:
            fcntl.lockf(self.fd, fcntl.LOCK_EX)
        # Python 3.2 raises IOError, Python3.3+ raises OSError
        except (IOError, OSError):
            raise self.WriteLockFailed(self.path)
        self.is_exclusive = True

    def release(self):
        fcntl.lockf(self.fd, fcntl.LOCK_UN)
        self.fd.close()
