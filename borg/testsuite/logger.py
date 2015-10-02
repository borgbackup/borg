import logging
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import pytest

def test_mod_logger():
    logger = logging.getLogger(__name__)
    io = StringIO()

    ch = logging.StreamHandler(io)
    ch.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    logger.addHandler(ch)
    logger.setLevel(logging.DEBUG)
    logger.info('hello world')
    assert io.getvalue() == "borg.testsuite.logger: hello world\n"
