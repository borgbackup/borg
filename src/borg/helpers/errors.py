from ..constants import *  # NOQA

from ..crypto.low_level import IntegrityError as IntegrityErrorBase


class Error(Exception):
    """Error: {}"""

    # Error base class

    # if we raise such an Error and it is only caught by the uppermost
    # exception handler (that exits short after with the given exit_code),
    # it is always a (fatal and abrupt) EXIT_ERROR, never just a warning.
    exit_code = EXIT_ERROR
    # show a traceback?
    traceback = False

    def __init__(self, *args):
        super().__init__(*args)
        self.args = args

    def get_message(self):
        return type(self).__doc__.format(*self.args)

    __str__ = get_message


class ErrorWithTraceback(Error):
    """Error: {}"""

    # like Error, but show a traceback also
    traceback = True


class IntegrityError(ErrorWithTraceback, IntegrityErrorBase):
    """Data integrity error: {}"""


class DecompressionError(IntegrityError):
    """Decompression error: {}"""
