"""Pydantic models that can parse borg 1.x's JSON output.

The two top-level models are:

- `BorgLogLine`, which parses any line of borg's logging output,
- all `Borg*Result` classes, which parse the final JSON output of some borg commands.

The different types of log lines are defined in the other models.
"""

import json
import logging
import typing
from datetime import datetime
from pathlib import Path

import pydantic

_log = logging.getLogger(__name__)


class BaseBorgLogLine(pydantic.BaseModel):
    def get_level(self) -> int:
        """Get the log level for this line as a `logging` level value.

        If this is a log message with a levelname, use it.
        Otherwise, progress messages get `DEBUG` level, and other messages get `INFO`.
        """
        return logging.DEBUG


class ArchiveProgressLogLine(BaseBorgLogLine):
    original_size: int
    compressed_size: int
    deduplicated_size: int
    nfiles: int
    path: Path
    time: float


class FinishedArchiveProgress(BaseBorgLogLine):
    """JSON object printed on stdout when an archive is finished."""

    time: float
    type: typing.Literal["archive_progress"]
    finished: bool


class ProgressMessage(BaseBorgLogLine):
    operation: int
    msgid: typing.Optional[str]
    finished: bool
    message: typing.Optional[str]
    time: float


class ProgressPercent(BaseBorgLogLine):
    operation: int
    msgid: typing.Optional[str] = pydantic.Field(None)
    finished: bool
    message: typing.Optional[str] = pydantic.Field(None)
    current: typing.Optional[float] = pydantic.Field(None)
    info: list[str] | None = pydantic.Field(None)
    total: typing.Optional[float] = pydantic.Field(None)
    time: float

    @pydantic.model_validator(mode="after")
    def fields_depending_on_finished(self) -> typing.Self:
        if self.finished:
            if self.message is not None:
                raise ValueError("message must be None if finished is True")
            if self.current != self.total:
                raise ValueError("current must be equal to total if finished is True")
            if self.info is not None:
                raise ValueError("info must be None if finished is True")
            if self.total is not None:
                raise ValueError("total must be None if finished is True")
        else:
            if self.message is None:
                raise ValueError("message must not be None if finished is False")
            if self.current is None:
                raise ValueError("current must not be None if finished is False")
            if self.info is None:
                raise ValueError("info must not be None if finished is False")
            if self.total is None:
                raise ValueError("total must not be None if finished is False")
        return self


class FileStatus(BaseBorgLogLine):
    status: str
    path: Path


class LogMessage(BaseBorgLogLine):
    time: float
    levelname: typing.Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    name: str
    message: str
    msgid: typing.Optional[str]

    def get_level(self) -> int:
        try:
            return getattr(logging, self.levelname)
        except AttributeError:
            _log.warning(
                "could not find log level %s, giving the following message WARNING level: %s",
                self.levelname,
                json.dumps(self),
            )
            return logging.WARNING


_BorgLogLinePossibleTypes = (
    ArchiveProgressLogLine | FinishedArchiveProgress | ProgressMessage | ProgressPercent | FileStatus | LogMessage
)


class BorgLogLine(pydantic.RootModel[_BorgLogLinePossibleTypes]):
    """A log line from Borg with the `--log-json` argument."""

    def get_level(self) -> int:
        return self.root.get_level()


class _BorgArchive(pydantic.BaseModel):
    """Basic archive attributes."""

    name: str
    id: str
    start: datetime


class _BorgArchiveStatistics(pydantic.BaseModel):
    """Statistics of an archive."""

    original_size: int
    compressed_size: int
    deduplicated_size: int
    nfiles: int


class _BorgLimitUsage(pydantic.BaseModel):
    """Usage of borg limits by an archive."""

    max_archive_size: float


class _BorgDetailedArchive(_BorgArchive):
    """Archive attributes, as printed by `json info` or `json create`."""

    end: datetime
    duration: float
    stats: _BorgArchiveStatistics
    limits: _BorgLimitUsage
    command_line: typing.List[str]
    chunker_params: typing.Optional[typing.Any] = None


class BorgCreateResult(pydantic.BaseModel):
    """JSON object printed at the end of `borg create`."""

    archive: _BorgDetailedArchive


class BorgListResult(pydantic.BaseModel):
    """JSON object printed at the end of `borg list`."""

    archives: typing.List[_BorgArchive]
