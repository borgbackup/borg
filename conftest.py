import os.path
import sys

# This is a hack to fix path problems because "borg" (the package) is in the source root.
# When importing the conftest an "import borg" can incorrectly import the borg from the
# source root instead of the one installed in the environment.
# The workaround is to remove entries pointing there from the path and check whether "borg"
# is still importable. If it is not, then it has not been installed in the environment
# and the entries are put back.
#
# TODO: After moving the package to src/: remove this.

original_path = list(sys.path)
for entry in original_path:
    if entry == '' or entry == os.path.dirname(__file__):
        sys.path.remove(entry)

try:
    import borg
except ImportError:
    sys.path = original_path

from borg.logger import setup_logging

# Ensure that the loggers exist for all tests
setup_logging()

from borg.testsuite import has_lchflags, no_lchlfags_because, has_llfuse
from borg.testsuite.platform import fakeroot_detected
from borg import xattr


def pytest_report_header(config, startdir):
    yesno = ['no', 'yes']
    flags = 'Testing BSD-style flags: %s %s' % (yesno[has_lchflags], no_lchlfags_because)
    fakeroot = 'fakeroot: %s (>=1.20.2: %s)' % (
        yesno[fakeroot_detected()],
        yesno[xattr.XATTR_FAKEROOT])
    llfuse = 'Testing fuse: %s' % yesno[has_llfuse]
    return '\n'.join((flags, llfuse, fakeroot))
