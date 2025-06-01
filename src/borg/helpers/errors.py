import os

from ..constants import *  # NOQA

from ..crypto.low_level import IntegrityError as IntegrityErrorBase


modern_ec = os.environ.get("BORG_EXIT_CODES", "modern") == "modern"  # "legacy" was used by borg < 2


class ErrorBase(Exception):
    """ErrorBase: {}"""

    # Error base class

    # if we raise such an Error and it is only caught by the uppermost
    # exception handler (that exits short after with the given exit_code),
    # it is always a (fatal and abrupt) error, never just a warning.
    exit_mcode = EXIT_ERROR  # modern, more specific exit code (defaults to EXIT_ERROR)

    # show a traceback?
    traceback = False

    def __init__(self, *args):
        super().__init__(*args)
        self.args = args

    def get_message(self):
        return type(self).__doc__.format(*self.args)

    __str__ = get_message

    @property
    def exit_code(self):
        # legacy: borg used to always use rc 2 (EXIT_ERROR) for all errors.
        # modern: users can opt in to more specific return codes, using BORG_EXIT_CODES:
        return self.exit_mcode if modern_ec else EXIT_ERROR


class Error(ErrorBase):
    """Error: {}"""


class ErrorWithTraceback(Error):
    """Error: {}"""

    # like Error, but show a traceback also
    traceback = True


class IntegrityError(ErrorWithTraceback, IntegrityErrorBase):
    """Data integrity error: {}"""

    exit_mcode = 90


class DecompressionError(IntegrityError):
    """Decompression error: {}"""

    exit_mcode = 92


class CancelledByUser(Error):
    """Cancelled by user."""

    exit_mcode = 3


class RTError(Error):
    """Runtime Error: {}"""


class CommandError(Error):
    """Command Error: {}"""

    exit_mcode = 4


class BorgWarning:
    """Warning: {}"""

    # Warning base class

    # please note that this class and its subclasses are NOT exceptions, we do not raise them.
    # so this is just to have inheritance, inspectability and the exit_code property.
    exit_mcode = EXIT_WARNING  # modern, more specific exit code (defaults to EXIT_WARNING)

    def __init__(self, *args):
        self.args = args

    def get_message(self):
        return type(self).__doc__.format(*self.args)

    __str__ = get_message

    @property
    def exit_code(self):
        # legacy: borg used to always use rc 1 (EXIT_WARNING) for all warnings.
        # modern: users can opt in to more specific return codes, using BORG_EXIT_CODES:
        return self.exit_mcode if modern_ec else EXIT_WARNING


class FileChangedWarning(BorgWarning):
    """{}: file changed while we backed it up"""

    exit_mcode = 100


class IncludePatternNeverMatchedWarning(BorgWarning):
    """Include pattern '{}' never matched."""

    exit_mcode = 101


class BackupWarning(BorgWarning):
    """{}: {}"""

    # this is to wrap a caught BackupError exception, so it can be given to print_warning_instance

    @property
    def exit_code(self):
        if not modern_ec:
            return EXIT_WARNING
        exc = self.args[1]
        assert isinstance(exc, BackupError)
        return exc.exit_mcode


class BackupError(ErrorBase):
    """{}: backup error"""

    # Exception raised for non-OSError-based exceptions while accessing backup files.
    exit_mcode = 102


class BackupRaceConditionError(BackupError):
    """{}: file type or inode changed while we backed it up (race condition, skipped file)"""

    # Exception raised when encountering a critical race condition while trying to back up a file.
    exit_mcode = 103


class BackupOSError(BackupError):
    """{}: {}"""

    # Wrapper for OSError raised while accessing backup files.
    #
    # Borg does different kinds of IO, and IO failures have different consequences.
    # This wrapper represents failures of input file or extraction IO.
    # These are non-critical and are only reported (warnings).
    #
    # Any unwrapped IO error is critical and aborts execution (for example repository IO failure).
    exit_mcode = 104

    def __init__(self, op, os_error):
        self.op = op
        self.os_error = os_error
        self.errno = os_error.errno
        self.strerror = os_error.strerror
        self.filename = os_error.filename

    def __str__(self):
        if self.op:
            return f"{self.op}: {self.os_error}"
        else:
            return str(self.os_error)


class BackupPermissionError(BackupOSError):
    """{}: {}"""

    exit_mcode = 105


class BackupIOError(BackupOSError):
    """{}: {}"""

    exit_mcode = 106


class BackupFileNotFoundError(BackupOSError):
    """{}: {}"""

    exit_mcode = 107


class BackupItemExcluded(Exception):
    """used internally to skip an item from processing, when it is excluded."""
