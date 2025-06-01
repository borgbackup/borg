"""
This package contains all sorts of small helper / utility functionality,
that did not fit better elsewhere.

Code used to be in borg/helpers.py but was split into the modules in this
package, which are imported into here for compatibility.
"""

import os
from typing import List
from collections import namedtuple

from ..constants import *  # NOQA
from .checks import check_extension_modules, check_python
from .datastruct import StableDict, Buffer, EfficientCollectionQueue
from .errors import Error, ErrorWithTraceback, IntegrityError, DecompressionError, CancelledByUser, CommandError
from .errors import RTError, modern_ec
from .errors import BorgWarning, FileChangedWarning, BackupWarning, IncludePatternNeverMatchedWarning
from .errors import BackupError, BackupOSError, BackupRaceConditionError, BackupItemExcluded
from .errors import BackupPermissionError, BackupIOError, BackupFileNotFoundError
from .fs import ensure_dir, join_base_dir, get_socket_filename
from .fs import get_security_dir, get_keys_dir, get_base_dir, get_cache_dir, get_config_dir, get_runtime_dir
from .fs import dir_is_tagged, dir_is_cachedir, remove_dotdot_prefixes, make_path_safe, scandir_inorder
from .fs import secure_erase, safe_unlink, dash_open, os_open, os_stat, get_strip_prefix, umount
from .fs import O_, flags_dir, flags_special_follow, flags_special, flags_base, flags_normal, flags_noatime
from .fs import HardLinkManager
from .misc import sysinfo, log_multi, consume
from .misc import ChunkIteratorFileWrapper, open_item, chunkit, iter_separated, ErrorIgnoringTextIOWrapper
from .parseformat import bin_to_hex, hex_to_bin, safe_encode, safe_decode
from .parseformat import text_to_json, binary_to_json, remove_surrogates, join_cmd
from .parseformat import eval_escapes, decode_dict, positive_int_validator, interval
from .parseformat import PathSpec, SortBySpec, ChunkerParams, FilesCacheMode, partial_format, DatetimeWrapper
from .parseformat import format_file_size, parse_file_size, FileSize
from .parseformat import sizeof_fmt, sizeof_fmt_iec, sizeof_fmt_decimal, Location, text_validator
from .parseformat import format_line, replace_placeholders, PlaceholderError, relative_time_marker_validator
from .parseformat import format_archive, parse_stringified_list, clean_lines
from .parseformat import location_validator, archivename_validator, comment_validator, tag_validator
from .parseformat import BaseFormatter, ArchiveFormatter, ItemFormatter, DiffFormatter, file_status
from .parseformat import swidth_slice, ellipsis_truncate
from .parseformat import BorgJsonEncoder, basic_json_data, json_print, json_dump, prepare_dump_dict
from .parseformat import Highlander, MakePathSafeAction
from .process import daemonize, daemonizing, ThreadRunner
from .process import signal_handler, raising_signal_handler, sig_int, ignore_sigint, SigHup, SigTerm
from .process import popen_with_error_handling, is_terminal, prepare_subprocess_env, create_filter_process
from .progress import ProgressIndicatorPercent, ProgressIndicatorMessage
from .time import parse_timestamp, timestamp, safe_timestamp, safe_s, safe_ns, MAX_S, SUPPORT_32BIT_PLATFORMS
from .time import format_time, format_timedelta, OutputTimestamp, archive_ts_now
from .yes_no import yes, TRUISH, FALSISH, DEFAULTISH

from .msgpack import is_slow_msgpack, is_supported_msgpack, get_limited_unpacker
from . import msgpack

from ..logger import create_logger

logger = create_logger()


# generic mechanism to enable users to invoke workarounds by setting the
# BORG_WORKAROUNDS environment variable to a list of comma-separated strings.
# see the docs for a list of known workaround strings.
workarounds = tuple(os.environ.get("BORG_WORKAROUNDS", "").split(","))


# element data type for warnings_list:
warning_info = namedtuple("warning_info", "wc,msg,args,wt")

"""
The global warnings_list variable is used to collect warning_info elements while borg is running.
"""
_warnings_list: list[warning_info] = []


def add_warning(msg, *args, **kwargs):
    global _warnings_list
    warning_code = kwargs.get("wc", EXIT_WARNING)
    assert isinstance(warning_code, int)
    warning_type = kwargs.get("wt", "percent")
    assert warning_type in ("percent", "curly")
    _warnings_list.append(warning_info(warning_code, msg, args, warning_type))


"""
The global exit_code variable is used so that modules other than archiver can increase the program exit code if a
warning or error occurred during their operation.
"""
_exit_code = EXIT_SUCCESS


def classify_ec(ec):
    if not isinstance(ec, int):
        raise TypeError("ec must be of type int")
    if EXIT_SIGNAL_BASE <= ec <= 255:
        return "signal"
    elif ec == EXIT_ERROR or EXIT_ERROR_BASE <= ec < EXIT_WARNING_BASE:
        return "error"
    elif ec == EXIT_WARNING or EXIT_WARNING_BASE <= ec < EXIT_SIGNAL_BASE:
        return "warning"
    elif ec == EXIT_SUCCESS:
        return "success"
    else:
        raise ValueError(f"invalid error code: {ec}")


def max_ec(ec1, ec2):
    """return the more severe error code of ec1 and ec2"""
    # note: usually, there can be only 1 error-class ec, the other ec is then either success or warning.
    ec1_class = classify_ec(ec1)
    ec2_class = classify_ec(ec2)
    if ec1_class == "signal":
        return ec1
    if ec2_class == "signal":
        return ec2
    if ec1_class == "error":
        return ec1
    if ec2_class == "error":
        return ec2
    if ec1_class == "warning":
        return ec1
    if ec2_class == "warning":
        return ec2
    assert ec1 == ec2 == EXIT_SUCCESS
    return EXIT_SUCCESS


def set_ec(ec):
    """
    Sets the exit code of the program to ec IF ec is more severe than the current exit code.
    """
    global _exit_code
    _exit_code = max_ec(_exit_code, ec)


def init_ec_warnings(ec=EXIT_SUCCESS, warnings=None):
    """
    (Re-)Init the globals for the exit code and the warnings list.
    """
    global _exit_code, _warnings_list
    _exit_code = ec
    warnings = [] if warnings is None else warnings
    assert isinstance(warnings, list)
    _warnings_list = warnings


def get_ec(ec=None):
    """
    compute the final return code of the borg process
    """
    if ec is not None:
        set_ec(ec)

    global _exit_code
    exit_code_class = classify_ec(_exit_code)
    if exit_code_class in ("signal", "error", "warning"):
        # there was a signal/error/warning, return its exit code
        return _exit_code
    assert exit_code_class == "success"
    global _warnings_list
    if not _warnings_list:
        # we do not have any warnings in warnings list, return success exit code
        return _exit_code
    # looks like we have some warning(s)
    rcs = sorted({w_info.wc for w_info in _warnings_list})
    logger.debug(f"rcs: {rcs!r}")
    if len(rcs) == 1:
        # easy: there was only one kind of warning, so we can be specific
        return rcs[0]
    # there were different kinds of warnings
    return EXIT_WARNING  # generic warning rc, user has to look into the logs


def get_reset_ec(ec=None):
    """Like get_ec, but re-initialize ec/warnings afterwards."""
    rc = get_ec(ec)
    init_ec_warnings()
    return rc
