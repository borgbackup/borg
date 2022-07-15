import logging
import json
import sys
import time
from shutil import get_terminal_size

from ..logger import create_logger

logger = create_logger()

from .parseformat import ellipsis_truncate


def justify_to_terminal_size(message):
    terminal_space = get_terminal_size(fallback=(-1, -1))[0]
    # justify only if we are outputting to a terminal
    if terminal_space != -1:
        return message.ljust(terminal_space)
    return message


class ProgressIndicatorBase:
    LOGGER = "borg.output.progress"
    JSON_TYPE: str = None
    json = False

    operation_id_counter = 0

    @classmethod
    def operation_id(cls):
        """Unique number, can be used by receiving applications to distinguish different operations."""
        cls.operation_id_counter += 1
        return cls.operation_id_counter

    def __init__(self, msgid=None):
        self.handler = None
        self.logger = logging.getLogger(self.LOGGER)
        self.id = self.operation_id()
        self.msgid = msgid

        # If there are no handlers, set one up explicitly because the
        # terminator and propagation needs to be set.  If there are,
        # they must have been set up by BORG_LOGGING_CONF: skip setup.
        if not self.logger.handlers:
            self.handler = logging.StreamHandler(stream=sys.stderr)
            self.handler.setLevel(logging.INFO)
            logger = logging.getLogger("borg")
            # Some special attributes on the borg logger, created by setup_logging
            # But also be able to work without that
            try:
                formatter = logger.formatter
                terminator = "\n" if logger.json else "\r"
                self.json = logger.json
            except AttributeError:
                terminator = "\r"
            else:
                self.handler.setFormatter(formatter)
            self.handler.terminator = terminator

            self.logger.addHandler(self.handler)
            if self.logger.level == logging.NOTSET:
                self.logger.setLevel(logging.WARN)
            self.logger.propagate = False

        # If --progress is not set then the progress logger level will be WARN
        # due to setup_implied_logging (it may be NOTSET with a logging config file,
        # but the interactions there are generally unclear), so self.emit becomes
        # False, which is correct.
        # If --progress is set then the level will be INFO as per setup_implied_logging;
        # note that this is always the case for serve processes due to a "args.progress |= is_serve".
        # In this case self.emit is True.
        self.emit = self.logger.getEffectiveLevel() == logging.INFO

    def __del__(self):
        if self.handler is not None:
            self.logger.removeHandler(self.handler)
            self.handler.close()

    def output_json(self, *, finished=False, **kwargs):
        assert self.json
        if not self.emit:
            return
        kwargs.update(
            dict(operation=self.id, msgid=self.msgid, type=self.JSON_TYPE, finished=finished, time=time.time())
        )
        print(json.dumps(kwargs), file=sys.stderr, flush=True)

    def finish(self):
        if self.json:
            self.output_json(finished=True)
        else:
            self.output("")


class ProgressIndicatorMessage(ProgressIndicatorBase):
    JSON_TYPE = "progress_message"

    def output(self, msg):
        if self.json:
            self.output_json(message=msg)
        else:
            self.logger.info(justify_to_terminal_size(msg))


class ProgressIndicatorPercent(ProgressIndicatorBase):
    JSON_TYPE = "progress_percent"

    def __init__(self, total=0, step=5, start=0, msg="%3.0f%%", msgid=None):
        """
        Percentage-based progress indicator

        :param total: total amount of items
        :param step: step size in percent
        :param start: at which percent value to start
        :param msg: output message, must contain one %f placeholder for the percentage
        """
        self.counter = 0  # 0 .. (total-1)
        self.total = total
        self.trigger_at = start  # output next percentage value when reaching (at least) this
        self.step = step
        self.msg = msg

        super().__init__(msgid=msgid)

    def progress(self, current=None, increase=1):
        if current is not None:
            self.counter = current
        pct = self.counter * 100 / self.total
        self.counter += increase
        if pct >= self.trigger_at:
            self.trigger_at += self.step
            return pct

    def show(self, current=None, increase=1, info=None):
        """
        Show and output the progress message

        :param current: set the current percentage [None]
        :param increase: increase the current percentage [None]
        :param info: array of strings to be formatted with msg [None]
        """
        pct = self.progress(current, increase)
        if pct is not None:
            # truncate the last argument, if no space is available
            if info is not None:
                if not self.json:
                    # no need to truncate if we're not outputting to a terminal
                    terminal_space = get_terminal_size(fallback=(-1, -1))[0]
                    if terminal_space != -1:
                        space = terminal_space - len(self.msg % tuple([pct] + info[:-1] + [""]))
                        info[-1] = ellipsis_truncate(info[-1], space)
                return self.output(self.msg % tuple([pct] + info), justify=False, info=info)

            return self.output(self.msg % pct)

    def output(self, message, justify=True, info=None):
        if self.json:
            self.output_json(message=message, current=self.counter, total=self.total, info=info)
        else:
            if justify:
                message = justify_to_terminal_size(message)
            self.logger.info(message)


class ProgressIndicatorEndless:
    def __init__(self, step=10, file=None):
        """
        Progress indicator (long row of dots)

        :param step: every Nth call, call the func
        :param file: output file, default: sys.stderr
        """
        self.counter = 0  # call counter
        self.triggered = 0  # increases 1 per trigger event
        self.step = step  # trigger every <step> calls
        if file is None:
            file = sys.stderr
        self.file = file

    def progress(self):
        self.counter += 1
        trigger = self.counter % self.step == 0
        if trigger:
            self.triggered += 1
        return trigger

    def show(self):
        trigger = self.progress()
        if trigger:
            return self.output(self.triggered)

    def output(self, triggered):
        print(".", end="", file=self.file, flush=True)

    def finish(self):
        print(file=self.file)
