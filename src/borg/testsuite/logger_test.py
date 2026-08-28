import logging
from io import StringIO

import pytest

from ..logger import find_parent_module, create_logger, setup_logging

logger = create_logger()


@pytest.fixture()
def io_logger():
    io = StringIO()
    handler = setup_logging(stream=io, env_var=None)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logger.setLevel(logging.DEBUG)
    return io


def test_setup_logging(io_logger):
    logger.info("hello world")
    assert io_logger.getvalue() == "borg.testsuite.logger_test: hello world\n"


def test_multiple_loggers(io_logger):
    logger = logging.getLogger(__name__)
    logger.info("hello world 1")
    assert io_logger.getvalue() == "borg.testsuite.logger_test: hello world 1\n"
    logger = logging.getLogger("borg.testsuite.logger_test")
    logger.info("hello world 2")
    assert (
        io_logger.getvalue() == "borg.testsuite.logger_test: hello world 1\nborg.testsuite.logger_test: hello world 2\n"
    )
    io_logger.truncate(0)
    io_logger.seek(0)
    logger = logging.getLogger("borg.testsuite.logger_test")
    logger.info("hello world 2")
    assert io_logger.getvalue() == "borg.testsuite.logger_test: hello world 2\n"


def test_setup_logging_json_attribute():
    # the yes() prompt function decides between plain text and JSON output ("question_*"
    # objects) by looking at the "json" attribute of the "borg" logger, so setup_logging()
    # must set it according to log_json (i.e. whether --log-json was given).
    # test True before False, so the logging configuration left behind matches
    # what the other tests in this module leave behind.
    for log_json in (True, False):
        setup_logging(stream=StringIO(), env_var=None, log_json=log_json)
        assert logging.getLogger("borg").json is log_json


def test_parent_module():
    assert find_parent_module() == __name__


def test_lazy_logger():
    # Just calling all the methods of the proxy.
    logger.setLevel(logging.DEBUG)
    logger.debug("debug")
    logger.info("info")
    logger.warning("warning")
    logger.error("error")
    logger.critical("critical")
    logger.log(logging.INFO, "info")
    try:
        raise Exception
    except Exception:
        logger.exception("exception")
