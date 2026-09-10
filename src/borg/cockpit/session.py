"""
Borg Cockpit - the state of one borg run.

A Session is fed with the events the runner produces and is read by the widgets. It has no Textual
dependency, so it can be tested by replaying recorded JSON lines. All counting happens here and the
buffers are bounded, so that a flood of events (e.g. --list over millions of files) costs little more
than the JSON parsing; the widgets render what is in here at their own pace.
"""

import json
import time
from collections import Counter, deque
from dataclasses import dataclass

from .events import (
    ArchiveProgress,
    FileStatus,
    LogMessage,
    ProcessFinished,
    ProgressMessage,
    ProgressPercent,
    Question,
    RawLine,
    UnknownJson,
)

# The status characters of --list output, see "Item flags" in the borg create help.
LIST_STATUSES = "AMUCEdbchsf+-ix?"

# extract, export-tar and prune have no file_status JSON type (yet): their --list lines arrive as
# log_message objects of this logger, with the status character in front, like for borg create --list.
# TODO: remove this shim when borg emits file_status objects for them.
LIST_LOGGER = "borg.output.list"

# Python's getpass() prints this when it can not use a terminal (the runner starts borg without one)
# and falls back to reading the passphrase from stdin, which the cockpit does not support (yet).
PASSPHRASE_FALLBACK_WARNING = "Warning: Password input may be echoed."
PASSPHRASE_HINT = (
    "borg waits for a passphrase, but the cockpit can not enter one. "
    "Quit, set BORG_PASSPHRASE, BORG_PASSCOMMAND or BORG_PASSPHRASE_FD and start again."
)


@dataclass
class Line:
    """One line for the log panel."""

    text: str
    kind: str  # "status": a --list line, tag is the status char. "log": tag is the level name. "raw", "hint".
    tag: str = ""


@dataclass
class Phase:
    """One progress operation of borg (progress_percent / progress_message), identified by its operation id."""

    operation: int
    msgid: str | None
    message: str = ""
    current: int | None = None
    total: int | None = None
    finished: bool = False

    @property
    def fraction(self):
        """Progress as 0.0 .. 1.0, None if unknown."""
        if not self.total or self.current is None:
            return None
        return min(max(self.current / self.total, 0.0), 1.0)


class Session:
    LINES_MAX = 200  # log lines buffered between two drains, older lines are dropped (and counted)

    def __init__(self):
        self.started = time.monotonic()
        self.finished_at = None
        self.rc = None  # exit code of borg, None while it runs
        self.error = None  # why borg could not be run, if so
        self.archive_progress = None  # the latest ArchiveProgress carrying statistics
        self.archive_finished = False
        self.status_counts = Counter()  # status char -> count, from the --list lines
        self.phases = {}  # operation id -> Phase, in order of appearance
        self.progress_text = ""  # what borg works on right now: the current path or progress message
        self.pending_question = None  # the Question borg waits for an answer to
        self.passphrase_needed = False
        self._lines = deque(maxlen=self.LINES_MAX)
        self._dropped = 0
        self._sample = (self.started, 0, 0, 0)  # time, nfiles, original_size, deduplicated_size
        self.files_per_second = 0.0
        self.original_bytes_per_second = 0.0
        self.deduplicated_bytes_per_second = 0.0

    # derived values for the widgets

    @property
    def running(self):
        return self.rc is None

    @property
    def elapsed(self):
        """Seconds since the start of the run, frozen when it has finished."""
        end = time.monotonic() if self.finished_at is None else self.finished_at
        return end - self.started

    # The --list lines are exact and complete, so they are preferred as the source of the item counts.
    # archive_progress is rate limited and its final object carries no statistics, so its counts can be
    # a little behind at the end of a run (and stay at zero for a run shorter than the update interval).

    @property
    def nfiles(self):
        """Number of items listed (--list), or of regular files processed (archive_progress) without a list."""
        if self.status_counts:
            return sum(self.status_counts.values())
        if self.archive_progress is not None:
            return self.archive_progress.nfiles
        return 0

    @property
    def files_stats(self):
        """status char -> count, from the --list lines if there are any, else from archive_progress."""
        if self.status_counts:
            return dict(self.status_counts)
        if self.archive_progress is not None:
            return dict(self.archive_progress.files_stats)
        return {}

    def count(self, statuses):
        """Number of items having one of the given status characters."""
        stats = self.files_stats
        return sum(stats.get(status, 0) for status in statuses)

    @property
    def original_size(self):
        return None if self.archive_progress is None else self.archive_progress.original_size

    @property
    def deduplicated_size(self):
        return None if self.archive_progress is None else self.archive_progress.deduplicated_size

    # feeding

    def feed(self, event):
        """Update the state with one event from the runner."""
        match event:
            case LogMessage():
                self._feed_log_message(event)
            case FileStatus():
                self._add_status(event.status, event.path)
            case ArchiveProgress():
                if event.finished:
                    # the final object carries no statistics, keep the previous ones.
                    self.archive_finished = True
                    self.progress_text = ""
                else:
                    self.archive_progress = event
                    self.progress_text = event.path or ""
            case ProgressPercent() | ProgressMessage():
                self._feed_phase(event)
            case Question():
                self._feed_question(event)
            case RawLine():
                self._add_line(Line(event.line, "raw", event.stream))
                if event.stream == "stderr" and event.line == PASSPHRASE_FALLBACK_WARNING:
                    self.passphrase_needed = True
                    self._add_line(Line(PASSPHRASE_HINT, "hint"))
            case UnknownJson():
                self._add_line(Line(json.dumps(event.data), "raw", "stderr"))
            case ProcessFinished():
                self.rc = event.rc
                self.error = event.error
                self.finished_at = time.monotonic()
                self.pending_question = None
                self.progress_text = ""
                if event.error:
                    self._add_line(Line(event.error, "log", "ERROR"))

    def _feed_log_message(self, event):
        message = event.message
        if event.name == LIST_LOGGER and len(message) >= 2 and message[1] == " " and message[0] in LIST_STATUSES:
            self._add_status(message[0], message[2:])
        else:
            self._add_line(Line(message, "log", event.levelname))

    def _add_status(self, status, path):
        self.status_counts[status] += 1
        self._add_line(Line(f"{status} {path}", "status", status))

    def _feed_phase(self, event):
        phase = self.phases.get(event.operation)
        if phase is None:
            phase = self.phases[event.operation] = Phase(event.operation, event.msgid)
        phase.finished = event.finished
        if not event.finished:
            phase.message = event.message
            if isinstance(event, ProgressPercent):
                phase.current = event.current
                phase.total = event.total
        self.progress_text = "" if event.finished else event.message

    def _feed_question(self, event):
        if event.needs_answer:
            self.pending_question = event
            self._add_line(Line(event.message, "log", "PROMPT"))
        else:
            self.pending_question = None
            self._add_line(Line(event.message, "log", "INFO"))

    def _add_line(self, line):
        if len(self._lines) == self._lines.maxlen:
            self._dropped += 1
        self._lines.append(line)

    def drain(self):
        """Take the buffered log lines: (lines, number of older lines dropped since the previous drain)."""
        lines, dropped = list(self._lines), self._dropped
        self._lines.clear()
        self._dropped = 0
        return lines, dropped

    def sample(self, now=None):
        """Compute the rates (files/s, bytes/s) from the progress since the previous sample() call."""
        now = time.monotonic() if now is None else now
        then, nfiles, original_size, deduplicated_size = self._sample
        dt = now - then
        if dt <= 0:
            return
        current = (self.nfiles, self.original_size or 0, self.deduplicated_size or 0)
        self.files_per_second = max(current[0] - nfiles, 0) / dt
        self.original_bytes_per_second = max(current[1] - original_size, 0) / dt
        self.deduplicated_bytes_per_second = max(current[2] - deduplicated_size, 0) / dt
        self._sample = (now, *current)
