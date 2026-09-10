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
from datetime import timedelta

from ..helpers import format_file_size, format_timedelta
from .events import (
    ArchiveProgress,
    ArchiveStatus,
    FileStatus,
    LogMessage,
    ProcessFinished,
    ProgressMessage,
    ProgressPercent,
    Question,
    RawLine,
    UnknownJson,
)

# Python's getpass() prints this when it can not use a terminal (the runner starts borg without one)
# and falls back to reading the passphrase from stdin, which the cockpit does not support (yet).
# (The names avoid the word "pass", which makes bandit see hardcoded passwords in these messages.)
NO_TERMINAL_WARNING = "Warning: Password input may be echoed."
NO_TERMINAL_HINT = (
    "borg waits for a passphrase, but the cockpit can not enter one. "
    "Quit, set BORG_PASSPHRASE, BORG_PASSCOMMAND or BORG_PASSPHRASE_FD and start again."
)


@dataclass
class Line:
    """One line for the log panel."""

    text: str
    kind: str  # "status": a --list line, tag is the status char. "archive": tag is kept / pruned / deleted / ...
    # "log": tag is the level name. "raw", "hint".
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
    rate: float = 0.0  # increase of current per second, see Session.sample()
    sampled_current: int | None = None  # current at the previous Session.sample()

    @property
    def fraction(self):
        """Progress as 0.0 .. 1.0, None if unknown."""
        if not self.total or self.current is None:
            return None
        return min(max(self.current / self.total, 0.0), 1.0)


class Session:
    LINES_MAX = 200  # log lines buffered between two drains, older lines are dropped (and counted)

    def __init__(self, command=None, capture_stdout=False):
        """
        :param command: the borg subcommand that runs, e.g. "create" [None: unknown].
        :param capture_stdout: collect stdout instead of logging it: it carries the --json output, see final_json.
        """
        self.command = command
        self.capture_stdout = capture_stdout
        self.stdout_lines = []  # the captured stdout lines
        self.final_json = None  # the --json output of borg (create, import-tar), parsed when borg has finished
        self.started = time.monotonic()
        self.finished_at = None
        self.rc = None  # exit code of borg, None while it runs
        self.error = None  # why borg could not be run, if so
        self.archive_progress = None  # the latest ArchiveProgress carrying statistics
        self.archive_finished = False
        self.status_counts = Counter()  # status char -> count, from the --list lines
        self.archive_counts = Counter()  # status -> count, the archives listed by prune / delete / undelete
        self.phases = {}  # operation id -> Phase, in order of appearance
        self._active_phase = None  # operation id of the phase updated last
        self.progress_text = ""  # what borg works on right now: the current path or progress message
        self.pending_question = None  # the Question borg waits for an answer to
        self.passphrase_needed = False
        self.warnings = 0  # WARNING log messages
        self.errors = 0  # ERROR and CRITICAL log messages
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

    @property
    def final_stats(self):
        """The archive statistics from the --json output, None until borg has finished (and only for some commands)."""
        if not isinstance(self.final_json, dict):
            return None
        archive = self.final_json.get("archive")
        # create --dry-run creates no archive and has its (reduced) stats at the top level.
        stats = archive.get("stats") if isinstance(archive, dict) else self.final_json.get("stats")
        return stats if isinstance(stats, dict) else None

    def _final_archive(self, key):
        archive = self.final_json.get("archive") if isinstance(self.final_json, dict) else None
        return archive.get(key) if isinstance(archive, dict) else None

    @property
    def archive_name(self):
        """The name of the created archive, from the --json output."""
        name = self._final_archive("name")
        return name if isinstance(name, str) else None

    @property
    def archive_duration(self):
        """The duration of the archive creation [seconds], from the --json output."""
        duration = self._final_archive("duration")
        return float(duration) if isinstance(duration, (int, float)) else None

    def _final_stat(self, key, types=int):
        stats = self.final_stats
        value = stats.get(key) if stats else None
        return value if isinstance(value, types) and not isinstance(value, bool) else None

    # The final statistics (exact) are preferred over the --list lines (exact, but subject to --filter),
    # which are preferred over archive_progress: that one is rate limited and its final object carries no
    # statistics, so its counts can be a little behind at the end of a run (and stay at zero for a run
    # shorter than the update interval).

    @property
    def nfiles(self):
        """Number of regular files (final stats, archive_progress) or of all listed items (--list lines)."""
        nfiles = self._final_stat("nfiles")
        if nfiles is not None:
            return nfiles
        if self.status_counts:
            return sum(self.status_counts.values())
        if self.archive_progress is not None:
            return self.archive_progress.nfiles
        return 0

    @property
    def files_stats(self):
        """status char -> count, from the final stats, the --list lines or archive_progress."""
        files_stats = self._final_stat("files_stats", dict)
        if files_stats is not None:
            return dict(files_stats)
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
        size = self._final_stat("original_size")
        if size is not None:
            return size
        return None if self.archive_progress is None else self.archive_progress.original_size

    @property
    def deduplicated_size(self):
        size = self._final_stat("deduplicated_size")
        if size is not None:
            return size
        return None if self.archive_progress is None else self.archive_progress.deduplicated_size

    @property
    def active_phase(self):
        """The unfinished phase that was updated last, None if there is none."""
        phase = self.phases.get(self._active_phase)
        return None if phase is None or phase.finished else phase

    def phase(self, msgid):
        """The phase with the given msgid (the last one, if there are several), None if there is none."""
        for phase in reversed(self.phases.values()):
            if phase.msgid == msgid:
                return phase
        return None

    # feeding

    def feed(self, event):
        """Update the state with one event from the runner."""
        match event:
            case LogMessage():
                self._feed_log_message(event)
            case FileStatus():
                self._add_status(event.status, event.path)
            case ArchiveStatus():
                self.archive_counts[event.status] += 1
                self._add_line(Line(event.message, "archive", event.status))
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
                self._feed_raw_line(event)
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
                if self.stdout_lines:
                    self._parse_stdout()

    def _feed_log_message(self, event):
        if event.levelname == "WARNING":
            self.warnings += 1
        elif event.levelname in ("ERROR", "CRITICAL"):
            self.errors += 1
        self._add_line(Line(event.message, "log", event.levelname))

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
        self._active_phase = event.operation
        self.progress_text = "" if event.finished else event.message

    def _feed_question(self, event):
        if event.needs_answer:
            self.pending_question = event
            self._add_line(Line(event.message, "log", "PROMPT"))
        else:
            self.pending_question = None
            self._add_line(Line(event.message, "log", "INFO"))

    def _feed_raw_line(self, event):
        if event.stream == "stdout" and self.capture_stdout:
            self.stdout_lines.append(event.line)
            return
        self._add_line(Line(event.line, "raw", event.stream))
        if event.stream == "stderr" and event.line == NO_TERMINAL_WARNING:
            self.passphrase_needed = True
            self._add_line(Line(NO_TERMINAL_HINT, "hint"))

    def _parse_stdout(self):
        """The captured stdout is the --json output: keep it and log its statistics like --stats would."""
        try:
            data = json.loads("\n".join(self.stdout_lines))
        except ValueError:
            data = None
        if isinstance(data, dict):
            self.final_json = data
            for text in self.final_stats_lines():
                self._add_line(Line(text, "log", "STATS"))
        else:  # not what we expected, show it as it is
            for line in self.stdout_lines:
                self._add_line(Line(line, "raw", "stdout"))

    def final_stats_lines(self):
        """The statistics from the --json output as text lines, like the --stats output of borg."""
        lines = []
        name, fingerprint = self.archive_name, self._final_archive("id")
        if name is not None:
            lines.append(f"Archive name: {name}")
        if isinstance(fingerprint, str):
            lines.append(f"Archive fingerprint: {fingerprint}")
        duration = self.archive_duration
        if duration is not None:
            lines.append(f"Duration: {format_timedelta(timedelta(seconds=duration))}")
        if isinstance(self.final_json, dict) and self.final_json.get("dry_run"):
            lines.append("Dry run: no archive was created.")
        nfiles = self._final_stat("nfiles")
        if nfiles is not None:
            lines.append(f"Number of files: {nfiles}")
        for key, label in (("original_size", "Original size"), ("deduplicated_size", "Deduplicated size")):
            size = self._final_stat(key)
            if size is not None:
                lines.append(f"{label}: {format_file_size(size)}")
        for key, label in (("hashing_time", "Time spent in hashing"), ("chunking_time", "Time spent in chunking")):
            seconds = self._final_stat(key, (int, float))
            if seconds is not None:
                lines.append(f"{label}: {format_timedelta(timedelta(seconds=seconds))}")
        files_stats = self._final_stat("files_stats", dict)
        if files_stats is not None:
            for status, label in (
                ("A", "Added files"),
                ("U", "Unchanged files"),
                ("M", "Modified files"),
                ("E", "Error files"),
                ("C", "Files changed while reading"),
            ):
                lines.append(f"{label}: {files_stats.get(status, 0)}")
        store_stats = self._final_stat("store_stats", dict)
        if store_stats:
            from ..archive import format_store_stats

            lines.extend(format_store_stats(store_stats).splitlines())
        return lines

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
        """Compute the rates (files/s, bytes/s, progress of the phases) since the previous sample() call."""
        now = time.monotonic() if now is None else now
        then, nfiles, original_size, deduplicated_size = self._sample
        dt = now - then
        if dt <= 0:
            return
        if not self.running:  # nothing moves anymore
            self.files_per_second = self.original_bytes_per_second = self.deduplicated_bytes_per_second = 0.0
            for phase in self.phases.values():
                phase.rate = 0.0
            return
        current = (self.nfiles, self.original_size or 0, self.deduplicated_size or 0)
        self.files_per_second = max(current[0] - nfiles, 0) / dt
        self.original_bytes_per_second = max(current[1] - original_size, 0) / dt
        self.deduplicated_bytes_per_second = max(current[2] - deduplicated_size, 0) / dt
        self._sample = (now, *current)
        for phase in self.phases.values():
            if phase.finished or phase.current is None:
                phase.rate = 0.0
            elif phase.sampled_current is not None:
                phase.rate = max(phase.current - phase.sampled_current, 0) / dt
            phase.sampled_current = phase.current
