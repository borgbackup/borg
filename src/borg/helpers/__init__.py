"""
This package contains all sorts of small helper / utility functionality,
that did not fit better elsewhere.

Code used to be in borg/helpers.py but was split into the modules in this
package, which are imported into here for compatibility.
"""

from .checks import *  # NOQA
from .datastruct import *  # NOQA
from .errors import *  # NOQA
from .fs import *  # NOQA
from .manifest import *  # NOQA
from .misc import *  # NOQA
from .parseformat import *  # NOQA
from .process import *  # NOQA
from .progress import *  # NOQA
from .time import *  # NOQA
from .yes import *  # NOQA

from .msgpack import is_slow_msgpack, is_supported_msgpack, int_to_bigint, bigint_to_int, get_limited_unpacker
from . import msgpack

# generic mechanism to enable users to invoke workarounds by setting the
# BORG_WORKAROUNDS environment variable to a list of comma-separated strings.
# see the docs for a list of known workaround strings.
workarounds = tuple(os.environ.get('BORG_WORKAROUNDS', '').split(','))


# element data type for warnings_list:
warning_info = namedtuple("warning_info", "wc,msg,args,wt")

"""
The global warnings_list variable is used to collect warning_info elements while borg is running.

Note: keep this in helpers/__init__.py as the code expects to be able to assign to helpers.warnings_list.
"""
warnings_list = []


def add_warning(msg, *args, **kwargs):
    global warnings_list
    warning_code = kwargs.get("wc", EXIT_WARNING)
    assert isinstance(warning_code, int)
    warning_type = kwargs.get("wt", "percent")
    assert warning_type in ("percent", "curly")
    warnings_list.append(warning_info(warning_code, msg, args, warning_type))


"""
The global exit_code variable is used so that modules other than archiver can increase the program exit code if a
warning or error occurred during their operation.

Note: keep this in helpers/__init__.py as the code expects to be able to assign to helpers.exit_code.
"""
exit_code = EXIT_SUCCESS


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
    global exit_code
    exit_code = max_ec(exit_code, ec)


def get_ec(ec=None):
    """
    compute the final return code of the borg process
    """
    if ec is not None:
        set_ec(ec)

    global exit_code
    exit_code_class = classify_ec(exit_code)
    if exit_code_class in ("signal", "error", "warning"):
        # there was a signal/error/warning, return its exit code
        return exit_code
    assert exit_code_class == "success"
    global warnings_list
    if not warnings_list:
        # we do not have any warnings in warnings list, return success exit code
        return exit_code
    # looks like we have some warning(s)
    rcs = sorted(set(w_info.wc for w_info in warnings_list))
    logger.debug(f"rcs: {rcs!r}")
    if len(rcs) == 1:
        # easy: there was only one kind of warning, so we can be specific
        return rcs[0]
    # there were different kinds of warnings
    return EXIT_WARNING  # generic warning rc, user has to look into the logs
