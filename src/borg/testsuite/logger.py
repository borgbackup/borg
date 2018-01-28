import logging
from io import StringIO
import os

import pytest

from ..logger import find_parent_module, create_logger, setup_logging
from .. import logger as _logger
logger = create_logger()


def reset_logging():
    global logger
    import importlib
    # otherwise we'd need to reset the root logger and delete all other loggerss
    importlib.reload(logging)
    _logger.configured = False
    logger = create_logger()


def teardown_function(function):
    reset_logging()


@pytest.fixture()
def io_logger():
    io = StringIO()
    handler = setup_logging(stream=io, env_var=None)
    handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    logger.setLevel(logging.DEBUG)
    return io


@pytest.fixture(scope='function')
def loggingconfigfile(request, tmpdir):
    logging_conf = """
[loggers]
keys=root

[logger_root]
handlers=stderr,file
level=%(level_root)s

[handlers]
keys=file,stderr

[handler_file]
class=FileHandler
level=%(level_file)s
formatter=file
args=('%(logfile_path)s',)

[handler_stderr]
class=StreamHandler
formatter=stream
level=%(level_stderr)s
args=(sys.stderr,)

[formatters]
keys=stream,file

# name: module, e.g. borg.archiver
[formatter_stream]
format=%%(levelname)s: %%(message)s

[formatter_file]
format=FILE %%(levelname)s: %%(message)s
"""
    logfile = tmpdir.join('borg.log')
    # touch the file
    logfile.open(mode='w')

    class context:
        cfg = {
            'level_root': 'NOTSET',
            'level_stderr': 'NOTSET',
            'level_file': 'INFO',
            'logfile_path': str(logfile),
        }
        logging_config_file = tmpdir.join('borg_logging.conf')
        stream = StringIO()

        @classmethod
        def write_logging_conf(cls):
            data = logging_conf % cls.cfg
            cls.logging_config_file.write(data)

        @classmethod
        def logfile_contents(cls):
            return open(cls.cfg['logfile_path']).read()
    os.environ['BORG_LOGGING_CONF'] = str(context.logging_config_file)
    yield context
    del os.environ['BORG_LOGGING_CONF']


def test_setup_logging(io_logger):
    logger.info('hello world')
    assert io_logger.getvalue() == "borg.testsuite.logger: hello world\n"


@pytest.mark.parametrize(
    "level_arg,level_stderr,expected_stderr_level, expected_file_level", [
        (None, 'NOTSET', logging.DEBUG, logging.INFO),
        (None, 'INFO', logging.INFO, logging.INFO),
        ('warning', 'NOTSET', logging.WARNING, logging.INFO),
    ]
)
def test_setup_logging_configfile(level_arg, level_stderr, expected_stderr_level, expected_file_level,
                                  loggingconfigfile):
    loggingconfigfile.cfg.update(level_stderr=level_stderr)
    loggingconfigfile.write_logging_conf()
    stream = loggingconfigfile.stream
    logfile_contents = loggingconfigfile.logfile_contents
    setup_logging(stream=stream, level=level_arg)
    # stream should default to warning
    logger.debug('hello debug')
    txt = "DEBUG: hello debug\n"
    if expected_stderr_level <= logging.DEBUG:
        assert txt in stream.getvalue()
    else:
        assert txt not in stream.getvalue()
    if expected_file_level <= logging.DEBUG:
        assert txt in logfile_contents()
    else:
        assert txt not in logfile_contents()
    logger.info('hello info')
    txt = "INFO: hello info\n"
    if expected_stderr_level <= logging.INFO:
        assert txt in stream.getvalue()
    else:
        assert txt not in stream.getvalue()
    if expected_file_level <= logging.INFO:
        assert txt in logfile_contents()
    else:
        assert txt not in logfile_contents()
    logger.warning('hello warning')
    txt = "WARNING: hello warning\n"
    if expected_stderr_level <= logging.WARNING:
        assert txt in stream.getvalue()
    else:
        assert txt not in stream.getvalue()
    if expected_file_level <= logging.WARNING:
        assert txt in logfile_contents()
    else:
        assert txt not in logfile_contents()


def test_multiple_loggers(io_logger):
    logger = logging.getLogger(__name__)
    logger.info('hello world 1')
    assert io_logger.getvalue() == "borg.testsuite.logger: hello world 1\n"
    logger = logging.getLogger('borg.testsuite.logger')
    logger.info('hello world 2')
    assert io_logger.getvalue() == "borg.testsuite.logger: hello world 1\nborg.testsuite.logger: hello world 2\n"
    io_logger.truncate(0)
    io_logger.seek(0)
    logger = logging.getLogger('borg.testsuite.logger')
    logger.info('hello world 2')
    assert io_logger.getvalue() == "borg.testsuite.logger: hello world 2\n"


def test_parent_module():
    assert find_parent_module() == __name__


def test_lazy_logger(io_logger):
    # just calling all the methods of the proxy
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


def test_lazy_logger_not_setup():
    # just calling all the methods of the proxy
    with pytest.raises(Exception) as exc:
        logger.debug("debug")
    assert 'tried to call a logger before setup_logging() was called' \
        in str(exc.value)
