"""
This package contains all sorts of small helper / utility functionality,
that did not fit better elsewhere.

Code used to be in borg/helpers.py but was split into the modules in this
package, which are imported into here for compatibility.
"""
import os

from ..constants import *  # NOQA
from .checks import check_extension_modules, check_python
from .datastruct import StableDict, Buffer, EfficientCollectionQueue
from .errors import Error, ErrorWithTraceback, IntegrityError, DecompressionError
from .fs import ensure_dir, get_security_dir, get_keys_dir, get_base_dir, get_cache_dir, get_config_dir
from .fs import dir_is_tagged, dir_is_cachedir, make_path_safe, scandir_inorder
from .fs import secure_erase, safe_unlink, dash_open, os_open, os_stat, umount
from .fs import O_, flags_root, flags_dir, flags_special_follow, flags_special, flags_base, flags_normal, flags_noatime
from .fs import HardLinkManager
from .manifest import Manifest, NoManifestError, MandatoryFeatureUnsupported, AI_HUMAN_SORT_KEYS
from .misc import prune_within, prune_split, PRUNING_PATTERNS, sysinfo, log_multi, consume, get_tar_filter
from .misc import ChunkIteratorFileWrapper, open_item, chunkit, iter_separated, ErrorIgnoringTextIOWrapper
from .parseformat import bin_to_hex, safe_encode, safe_decode
from .parseformat import remove_surrogates, eval_escapes, decode_dict, positive_int_validator, interval
from .parseformat import ChunkerParams, FilesCacheMode, partial_format, DatetimeWrapper
from .parseformat import format_file_size, parse_file_size, FileSize, parse_storage_quota
from .parseformat import sizeof_fmt, sizeof_fmt_iec, sizeof_fmt_decimal
from .parseformat import format_line, replace_placeholders, PlaceholderError
from .parseformat import PrefixSpec, GlobSpec, CommentSpec, SortBySpec, NameSpec
from .parseformat import format_archive, parse_stringified_list, clean_lines
from .parseformat import Location, location_validator, archivename_validator
from .parseformat import BaseFormatter, ArchiveFormatter, ItemFormatter, file_status
from .parseformat import swidth_slice, ellipsis_truncate
from .parseformat import BorgJsonEncoder, basic_json_data, json_print, json_dump, prepare_dump_dict
from .process import daemonize, daemonizing
from .process import signal_handler, raising_signal_handler, sig_int, ignore_sigint, SigHup, SigTerm
from .process import popen_with_error_handling, is_terminal, prepare_subprocess_env, create_filter_process
from .progress import ProgressIndicatorPercent, ProgressIndicatorEndless, ProgressIndicatorMessage
from .time import parse_timestamp, timestamp, safe_timestamp, safe_s, safe_ns, MAX_S, SUPPORT_32BIT_PLATFORMS
from .time import format_time, format_timedelta, isoformat_time, to_localtime, OutputTimestamp
from .yes_no import yes, TRUISH, FALSISH, DEFAULTISH

from .msgpack import is_slow_msgpack, is_supported_msgpack, get_limited_unpacker
from . import msgpack

# generic mechanism to enable users to invoke workarounds by setting the
# BORG_WORKAROUNDS environment variable to a list of comma-separated strings.
# see the docs for a list of known workaround strings.
workarounds = tuple(os.environ.get("BORG_WORKAROUNDS", "").split(","))

"""
The global exit_code variable is used so that modules other than archiver can increase the program exit code if a
warning or error occurred during their operation. This is different from archiver.exit_code, which is only accessible
from the archiver object.

Note: keep this in helpers/__init__.py as the code expects to be able to assign to helpers.exit_code.
"""
exit_code = EXIT_SUCCESS


def set_ec(ec):
    """
    Sets the exit code of the program, if an exit code higher or equal than this is set, this does nothing. This
    makes EXIT_ERROR override EXIT_WARNING, etc..

    ec: exit code to set
    """
    global exit_code
    exit_code = max(exit_code, ec)
    return exit_code
