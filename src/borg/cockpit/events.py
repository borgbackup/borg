"""
Borg Cockpit - typed events.

The runner turns the JSON lines borg writes to stderr with --log-json into the event objects defined
here (see docs/internals/frontends.rst for the JSON API), so that the rest of the cockpit never deals
with raw dicts. Everything else the runner observes (stdout lines, non-JSON stderr lines, the process
exit) is an event as well.
"""

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Event:
    """Base class of everything the runner hands to the application."""


@dataclass(frozen=True)
class LogMessage(Event):
    """log_message: regular log output (--info, --debug, warnings, errors)."""

    message: str
    levelname: str = "INFO"
    name: str = ""
    msgid: str | None = None
    time: float = 0.0


@dataclass(frozen=True)
class ProgressMessage(Event):
    """progress_message: what borg is working on, without a quantitative progress."""

    operation: int
    message: str
    msgid: str | None = None
    finished: bool = False
    time: float = 0.0


@dataclass(frozen=True)
class ProgressPercent(Event):
    """progress_percent: progress with a current and a total value."""

    operation: int
    message: str
    current: int | None = None
    total: int | None = None
    info: list | None = None
    msgid: str | None = None
    finished: bool = False
    time: float = 0.0


@dataclass(frozen=True)
class ArchiveProgress(Event):
    """archive_progress: statistics while an archive is being created (create, import-tar, recreate, transfer)."""

    original_size: int = 0
    deduplicated_size: int = 0
    nfiles: int = 0
    hashing_time: float = 0.0
    chunking_time: float = 0.0
    files_stats: dict = field(default_factory=dict)
    path: str | None = None
    finished: bool = False
    time: float = 0.0


@dataclass(frozen=True)
class FileStatus(Event):
    """file_status: one line of the --list output of create, import-tar and recreate."""

    status: str
    path: str


@dataclass(frozen=True)
class ArchiveStatus(Event):
    """archive_status: one archive listed by prune, kept or pruned."""

    name: str
    kept: bool
    message: str  # the text line of the listing
    data: dict = field(default_factory=dict)  # the whole object, see the frontends docs for its keys


@dataclass(frozen=True)
class Question(Event):
    """question_*: a yes/no prompt (kind "prompt" / "prompt_retry") or a message about how a prompt was answered."""

    kind: str
    message: str
    msgid: str | None = None
    env_var: str | None = None

    @property
    def needs_answer(self):
        """Is borg waiting for an answer on stdin?"""
        return self.kind in ("prompt", "prompt_retry")


@dataclass(frozen=True)
class UnknownJson(Event):
    """A JSON object with a type the cockpit does not know."""

    data: dict


@dataclass(frozen=True)
class RawLine(Event):
    """A line that is not a JSON object: stdout output, or stderr output written outside of --log-json."""

    stream: str  # "stdout" or "stderr"
    line: str
    partial: bool = False  # True: not terminated by a newline (yet), e.g. a prompt waiting for input


@dataclass(frozen=True)
class ProcessFinished(Event):
    """The borg process has exited (or could not be started: rc -1 and an error message)."""

    rc: int
    error: str | None = None


def _opt_int(value):
    """An int for JSON numbers, None for anything else (missing, null, ...)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _float(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _opt_str(value):
    return value if isinstance(value, str) else None


def parse_json_line(line):
    """
    Parse one line of borg's --log-json output into an Event.

    Returns None if the line is not a JSON object with a "type" key, so that the caller can pass it
    on as a RawLine. Unknown types give an UnknownJson event, missing keys get defaults: the cockpit
    must keep working with older and newer borg versions.
    """
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("type"), str):
        return None
    msg_type = data["type"]
    message = _opt_str(data.get("message")) or ""
    msgid = _opt_str(data.get("msgid"))
    timestamp = _float(data.get("time"))
    finished = bool(data.get("finished", False))
    if msg_type == "log_message":
        return LogMessage(
            message=message,
            levelname=_opt_str(data.get("levelname")) or "INFO",
            name=_opt_str(data.get("name")) or "",
            msgid=msgid,
            time=timestamp,
        )
    if msg_type == "progress_message":
        return ProgressMessage(
            operation=_opt_int(data.get("operation")) or 0,
            message=message,
            msgid=msgid,
            finished=finished,
            time=timestamp,
        )
    if msg_type == "progress_percent":
        info = data.get("info")
        return ProgressPercent(
            operation=_opt_int(data.get("operation")) or 0,
            message=message,
            current=_opt_int(data.get("current")),
            total=_opt_int(data.get("total")),
            info=list(info) if isinstance(info, list) else None,
            msgid=msgid,
            finished=finished,
            time=timestamp,
        )
    if msg_type == "archive_progress":
        files_stats = data.get("files_stats")
        if not isinstance(files_stats, dict):
            files_stats = {}
        return ArchiveProgress(
            original_size=_opt_int(data.get("original_size")) or 0,
            deduplicated_size=_opt_int(data.get("deduplicated_size")) or 0,
            nfiles=_opt_int(data.get("nfiles")) or 0,
            hashing_time=_float(data.get("hashing_time")),
            chunking_time=_float(data.get("chunking_time")),
            files_stats={status: count for status, count in files_stats.items() if isinstance(count, int)},
            path=_opt_str(data.get("path")),
            finished=finished,
            time=timestamp,
        )
    if msg_type == "file_status":
        return FileStatus(status=_opt_str(data.get("status")) or "?", path=_opt_str(data.get("path")) or "")
    if msg_type == "archive_status":
        return ArchiveStatus(
            name=_opt_str(data.get("name")) or "", kept=bool(data.get("kept")), message=message, data=data
        )
    if msg_type.startswith("question_"):
        return Question(
            kind=msg_type[len("question_") :], message=message, msgid=msgid, env_var=_opt_str(data.get("env_var"))
        )
    return UnknownJson(data)
