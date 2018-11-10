import os
import sys

from .errors import Error
from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin


class PythonLibcTooOld(Error):
    """FATAL: this Python was compiled for a too old (g)libc and misses required functionality."""


def check_python():
    if is_win32:
        required_funcs = {os.stat}
    else:
        required_funcs = {os.stat, os.utime, os.chown}
    if not os.supports_follow_symlinks.issuperset(required_funcs):
        raise PythonLibcTooOld


class ExtensionModuleError(Error):
    """The Borg binary extension modules do not seem to be properly installed."""


def check_extension_modules():
    import borg.crypto.low_level
    from .. import platform, compress, item, chunker, hashindex
    if hashindex.API_VERSION != '1.1_07':
        raise ExtensionModuleError
    if chunker.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if compress.API_VERSION != '1.1_06':
        raise ExtensionModuleError
    if borg.crypto.low_level.API_VERSION != '1.1_02':
        raise ExtensionModuleError
    if platform.API_VERSION != platform.OS_API_VERSION or platform.API_VERSION != '1.2_02':
        raise ExtensionModuleError
    if item.API_VERSION != '1.1_03':
        raise ExtensionModuleError
