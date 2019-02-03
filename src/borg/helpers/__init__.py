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
