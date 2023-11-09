import os

from ..constants import *  # NOQA

from ..crypto.low_level import IntegrityError as IntegrityErrorBase


class Error(Exception):
    """Error: {}"""

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
        # modern: users can opt in to more specific return codes, using BORG_RC_STYLE:
        modern = os.environ.get("BORG_EXIT_CODES", "legacy") == "modern"
        return self.exit_mcode if modern else EXIT_ERROR


class ErrorWithTraceback(Error):
    """Error: {}"""

    # like Error, but show a traceback also
    traceback = True


class IntegrityError(ErrorWithTraceback, IntegrityErrorBase):
    """Data integrity error: {}"""


class DecompressionError(IntegrityError):
    """Decompression error: {}"""
