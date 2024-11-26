import logging
import json
import time
import typing

from ..logger import create_logger

logger = create_logger()


class ProgressIndicatorBase:
    LOGGER = "borg.output.progress"
    JSON_TYPE: str = None

    operation_id_counter = 0

    @classmethod
    def operation_id(cls):
        """Unique number, can be used by receiving applications to distinguish different operations."""
        cls.operation_id_counter += 1
        return cls.operation_id_counter

    def __init__(self, msgid=None):
        self.logger = logging.getLogger(self.LOGGER)
        self.id = self.operation_id()
        self.msgid = msgid

    def make_json(self, *, finished=False, override_time: typing.Optional[float] = None, **kwargs):
        kwargs.update(
            dict(
                operation=self.id,
                msgid=self.msgid,
                type=self.JSON_TYPE,
                finished=finished,
                time=override_time or time.time(),
            )
        )
        return json.dumps(kwargs)

    def finish(self):
        j = self.make_json(message="", finished=True)
        self.logger.info(j)


class ProgressIndicatorMessage(ProgressIndicatorBase):
    JSON_TYPE = "progress_message"

    def output(self, msg):
        j = self.make_json(message=msg)
        self.logger.info(j)


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
            if info is not None:
                return self.output(self.msg % tuple([pct] + info), info=info)
            else:
                return self.output(self.msg % pct)

    def output(self, message, info=None):
        j = self.make_json(message=message, current=self.counter, total=self.total, info=info)
        self.logger.info(j)
