import traceback

from ..constants import *  # NOQA

import borg.crypto.low_level


class Error(Exception):
    """Error base class"""

    # if we raise such an Error and it is only catched by the uppermost
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

    def get_msgid(self):
        return type(self).__qualname__

    def format_exc(self):
        return traceback.format_exc()

    __str__ = get_message


class ErrorWithTraceback(Error):
    """like Error, but show a traceback also"""
    traceback = True


class IntegrityError(ErrorWithTraceback, borg.crypto.low_level.IntegrityError):
    """Data integrity error: {}"""


class DecompressionError(IntegrityError):
    """Decompression error: {}"""
