import os
import sys

from .errors import RTError
from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin


def check_python():
    if is_win32:
        required_funcs = {os.stat}
    else:
        required_funcs = {os.stat, os.utime, os.chown}
    if not os.supports_follow_symlinks.issuperset(required_funcs):
        raise RTError("""FATAL: this Python was compiled for a too old (g)libc and misses required functionality.""")


def check_extension_modules():
    import borg.crypto.low_level
    from .. import platform, compress, item, chunker, hashindex
    msg = """The Borg binary extension modules do not seem to be properly installed."""
    if hashindex.API_VERSION != '1.4_01':
        raise RTError(msg)
    if chunker.API_VERSION != '1.4_01':
        raise RTError(msg)
    if compress.API_VERSION != '1.4_01':
        raise RTError(msg)
    if borg.crypto.low_level.API_VERSION != '1.4_01':
        raise RTError(msg)
    if item.API_VERSION != '1.4_01':
        raise RTError(msg)
    if platform.API_VERSION != platform.OS_API_VERSION or platform.API_VERSION != '1.4_01':
        raise RTError(msg)
