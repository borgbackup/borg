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
