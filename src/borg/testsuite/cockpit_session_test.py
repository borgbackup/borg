"""Tests for the cockpit's event parsing, session model and borg runner. They do not need Textual."""

import asyncio
import sys
import time

import pytest

from borg.cockpit.events import (
    ArchiveProgress,
    FileStatus,
    LogMessage,
    ProcessFinished,
    ProgressMessage,
    ProgressPercent,
    Question,
    RawLine,
    UnknownJson,
    parse_json_line,
)
from borg.cockpit.runner import INJECTED_OPTIONS, BorgRunner, borg_command
from borg.cockpit.session import LIST_LOGGER, PASSPHRASE_FALLBACK_WARNING, PASSPHRASE_HINT, Session

# JSON lines as documented in docs/internals/frontends.rst
ARCHIVE_PROGRESS = (
    '{"original_size": 250012, "deduplicated_size": 250012, "nfiles": 3, "hashing_time": 0.5, "chunking_time": 0.25, '
    '"files_stats": {"A": 3, "d": 3}, "store_stats": {}, "path": "src/linux/file1", "time": 1787900398.684961, '
    '"type": "archive_progress", "finished": false}'
)
ARCHIVE_PROGRESS_FINISHED = '{"time": 1787900398.686938, "type": "archive_progress", "finished": true}'
FILE_STATUS = '{"type": "file_status", "status": "A", "path": "src/linux/baz/file2"}'
PROGRESS_PERCENT = (
    '{"message": " 20.0% Extracting: src/linux/baz/file3", "current": 50012, "total": 250012, '
    '"info": ["src/linux/baz/file3"], "operation": 1, "msgid": "extract", "type": "progress_percent", '
    '"finished": false, "time": 1787900399.5558112}'
)
PROGRESS_PERCENT_FINISHED = (
    '{"message": "", "operation": 1, "msgid": "extract", "type": "progress_percent", "finished": true, '
    '"time": 1787900399.556339}'
)
PROGRESS_MESSAGE = (
    '{"message": "Saving files cache", "operation": 2, "msgid": "cache.close", "type": "progress_message", '
    '"finished": false, "time": 1787900398.719723}'
)
LOG_MESSAGE = (
    '{"type": "log_message", "time": 1787900383.5105972, "message": "Repository does not exist.", '
    '"levelname": "ERROR", "name": "borg.archiver", "msgid": "Repository.DoesNotExist"}'
)
QUESTION_PROMPT = (
    '{"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", '
    '"message": "This is a potentially dangerous function.\\n'
    "Type 'YES' if you understand this and want to continue: \"}"
)
QUESTION_ENV_ANSWER = (
    '{"env_var": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "type": "question_env_answer", '
    '"msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "message": "NO (from BORG_CHECK_I_KNOW_WHAT_I_AM_DOING)"}'
)


def test_parse_log_message():
    event = parse_json_line(LOG_MESSAGE)
    assert event == LogMessage(
        message="Repository does not exist.",
        levelname="ERROR",
        name="borg.archiver",
        msgid="Repository.DoesNotExist",
        time=1787900383.5105972,
    )


def test_parse_progress_percent():
    event = parse_json_line(PROGRESS_PERCENT)
    assert isinstance(event, ProgressPercent)
    assert (event.operation, event.msgid, event.current, event.total) == (1, "extract", 50012, 250012)
    assert event.info == ["src/linux/baz/file3"]
    assert event.message.endswith("src/linux/baz/file3")
    assert not event.finished
    finished = parse_json_line(PROGRESS_PERCENT_FINISHED)
    assert isinstance(finished, ProgressPercent)
    assert finished.finished and finished.current is None and finished.total is None and finished.message == ""


def test_parse_progress_message():
    event = parse_json_line(PROGRESS_MESSAGE)
    assert event == ProgressMessage(
        operation=2, message="Saving files cache", msgid="cache.close", finished=False, time=1787900398.719723
    )


def test_parse_archive_progress():
    event = parse_json_line(ARCHIVE_PROGRESS)
    assert isinstance(event, ArchiveProgress)
    assert (event.original_size, event.deduplicated_size, event.nfiles) == (250012, 250012, 3)
    assert (event.hashing_time, event.chunking_time) == (0.5, 0.25)
    assert event.files_stats == {"A": 3, "d": 3}
    assert event.path == "src/linux/file1"
    assert not event.finished
    finished = parse_json_line(ARCHIVE_PROGRESS_FINISHED)
    assert isinstance(finished, ArchiveProgress)
    assert finished.finished and finished.path is None and finished.nfiles == 0


def test_parse_file_status():
    assert parse_json_line(FILE_STATUS) == FileStatus(status="A", path="src/linux/baz/file2")


def test_parse_question():
    prompt = parse_json_line(QUESTION_PROMPT)
    assert isinstance(prompt, Question)
    assert prompt.kind == "prompt" and prompt.needs_answer
    assert prompt.msgid == "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"
    assert prompt.message.startswith("This is a potentially dangerous function.\n")
    env_answer = parse_json_line(QUESTION_ENV_ANSWER)
    assert isinstance(env_answer, Question)
    assert env_answer.kind == "env_answer" and not env_answer.needs_answer
    assert env_answer.env_var == "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING"


def test_parse_unknown_type_and_missing_keys():
    assert parse_json_line('{"type": "something_new", "x": 1}') == UnknownJson({"type": "something_new", "x": 1})
    # no crash on missing / odd keys, defaults are used
    assert parse_json_line('{"type": "log_message"}') == LogMessage(message="")
    assert parse_json_line('{"type": "archive_progress", "files_stats": null, "nfiles": "3"}') == ArchiveProgress()
    assert parse_json_line('{"type": "progress_percent", "operation": 7, "current": null}') == ProgressPercent(
        operation=7, message=""
    )


@pytest.mark.parametrize("line", ["", "not json", "42", "[1, 2]", '"text"', '{"no": "type"}', '{"type": 5}'])
def test_parse_not_an_event(line):
    assert parse_json_line(line) is None


def feed_lines(session, lines):
    for line in lines:
        event = parse_json_line(line)
        session.feed(event if event is not None else RawLine(stream="stderr", line=line))


def test_session_archive_progress():
    session = Session()
    assert session.running and session.nfiles == 0 and session.original_size is None
    feed_lines(session, [ARCHIVE_PROGRESS])
    assert session.nfiles == 3
    assert session.original_size == 250012 and session.deduplicated_size == 250012
    assert session.files_stats == {"A": 3, "d": 3}
    assert session.count("A") == 3 and session.count("dbcs") == 3 and session.count("U-") == 0
    assert session.progress_text == "src/linux/file1"
    feed_lines(session, [ARCHIVE_PROGRESS_FINISHED])
    # the final object carries no statistics, the previous ones stay
    assert session.archive_finished
    assert session.nfiles == 3 and session.original_size == 250012
    assert session.progress_text == ""


def test_session_counts_list_lines():
    session = Session()
    session.feed(FileStatus(status="A", path="a"))
    session.feed(FileStatus(status="A", path="b"))
    session.feed(FileStatus(status="d", path="dir"))
    session.feed(FileStatus(status="E", path="broken"))
    assert session.nfiles == 4  # all listed items
    assert session.files_stats == {"A": 2, "d": 1, "E": 1}
    lines, dropped = session.drain()
    assert dropped == 0
    assert [(line.kind, line.tag, line.text) for line in lines] == [
        ("status", "A", "A a"),
        ("status", "A", "A b"),
        ("status", "d", "d dir"),
        ("status", "E", "E broken"),
    ]
    # the list lines stay the source of the counts, archive_progress (rate limited, can lag behind) only gives the sizes
    session.feed(ArchiveProgress(nfiles=3, original_size=1000, deduplicated_size=10, files_stats={"A": 1, "d": 1}))
    assert session.nfiles == 4 and session.files_stats == {"A": 2, "d": 1, "E": 1}
    assert session.original_size == 1000 and session.deduplicated_size == 10


def test_session_list_logger_shim():
    session = Session()
    session.feed(LogMessage(message="+ extracted/file", name=LIST_LOGGER))
    session.feed(LogMessage(message="- excluded/file", name=LIST_LOGGER))
    session.feed(LogMessage(message="Keeping archive (rule: daily #1): foo", name=LIST_LOGGER))
    session.feed(LogMessage(message="+ not a list line", name="borg.archiver"))
    assert session.files_stats == {"+": 1, "-": 1}
    lines, _ = session.drain()
    assert [(line.kind, line.tag) for line in lines] == [
        ("status", "+"),
        ("status", "-"),
        ("log", "INFO"),
        ("log", "INFO"),
    ]
    assert lines[0].text == "+ extracted/file"


def test_session_phases():
    session = Session()
    feed_lines(session, [PROGRESS_PERCENT, PROGRESS_MESSAGE])
    assert list(session.phases) == [1, 2]
    extract = session.phases[1]
    assert (extract.msgid, extract.current, extract.total, extract.finished) == ("extract", 50012, 250012, False)
    assert extract.fraction == pytest.approx(0.2, abs=0.001)
    assert session.phases[2].fraction is None
    assert session.progress_text == "Saving files cache"
    feed_lines(session, [PROGRESS_PERCENT_FINISHED])
    assert extract.finished and extract.message.endswith("file3")  # the message of the last update stays
    assert session.progress_text == ""
    # extract first reports a total of 0 while it computes the total, that must not crash the fraction
    session.feed(ProgressPercent(operation=3, message="Calculating total archive size...", current=0, total=0))
    assert session.phases[3].fraction is None


def test_session_questions():
    session = Session()
    feed_lines(session, [QUESTION_PROMPT])
    assert session.pending_question is not None and session.pending_question.needs_answer
    lines, _ = session.drain()
    assert lines[0].kind == "log" and lines[0].tag == "PROMPT"
    feed_lines(session, [QUESTION_ENV_ANSWER])
    assert session.pending_question is None


def test_session_drain_is_bounded():
    session = Session()
    n = 2 * Session.LINES_MAX + 5
    for i in range(n):
        session.feed(RawLine(stream="stdout", line=f"line {i}"))
    lines, dropped = session.drain()
    assert len(lines) == Session.LINES_MAX
    assert dropped == n - Session.LINES_MAX
    assert lines[0].text == f"line {n - Session.LINES_MAX}" and lines[-1].text == f"line {n - 1}"
    assert lines[0].kind == "raw" and lines[0].tag == "stdout"
    assert session.drain() == ([], 0)


def test_session_sample_rates():
    session = Session()
    session.feed(ArchiveProgress(nfiles=10, original_size=1000, deduplicated_size=100))
    session.sample(now=session.started + 2.0)
    assert session.files_per_second == 5.0
    assert session.original_bytes_per_second == 500.0
    assert session.deduplicated_bytes_per_second == 50.0
    session.feed(ArchiveProgress(nfiles=10, original_size=1000, deduplicated_size=100))
    session.sample(now=session.started + 3.0)
    assert session.files_per_second == 0.0
    session.sample(now=session.started + 3.0)  # no time passed: keep the rates
    assert session.files_per_second == 0.0


def test_session_passphrase_hint():
    session = Session()
    session.feed(RawLine(stream="stderr", line=PASSPHRASE_FALLBACK_WARNING))
    session.feed(RawLine(stream="stderr", line="Enter passphrase for key /repo: ", partial=True))
    assert session.passphrase_needed
    lines, _ = session.drain()
    assert [(line.kind, line.text) for line in lines] == [
        ("raw", PASSPHRASE_FALLBACK_WARNING),
        ("hint", PASSPHRASE_HINT),
        ("raw", "Enter passphrase for key /repo: "),
    ]


def test_session_process_finished():
    session = Session()
    feed_lines(session, [QUESTION_PROMPT, PROGRESS_MESSAGE])
    session.feed(ProcessFinished(rc=2, error="boom"))
    assert not session.running and session.rc == 2 and session.error == "boom"
    assert session.pending_question is None and session.progress_text == ""
    elapsed = session.elapsed
    time.sleep(0.01)
    assert session.elapsed == elapsed  # frozen
    lines, _ = session.drain()
    assert lines[-1].kind == "log" and lines[-1].tag == "ERROR" and lines[-1].text == "boom"


def test_borg_command():
    assert borg_command(["create", "arch", "src"], executable=["borg"]) == [
        "borg",
        "--log-json",
        "--progress",
        "create",
        "arch",
        "src",
    ]
    # no duplicates when the user gave them already
    assert borg_command(["--progress", "create"], executable=["borg"]) == ["borg", "--log-json", "--progress", "create"]
    assert borg_command(["create", "--log-json"], executable=["borg"]) == ["borg", "--progress", "create", "--log-json"]
    # the default runs the interpreter that runs the cockpit
    assert borg_command(["--version"])[: -len(INJECTED_OPTIONS) - 1] == [sys.executable, "-m", "borg"]


FAKE_BORG = """
import json, sys

def err(obj):
    sys.stderr.write(json.dumps(obj) + "\\n")
    sys.stderr.flush()

err({"type": "log_message", "levelname": "INFO", "name": "borg.test", "message": "hello"})
err({"type": "file_status", "status": "A", "path": "a/b"})
sys.stderr.write("plain text\\n")
sys.stderr.flush()
print("stdout line", flush=True)
sys.stderr.write("Enter something: ")  # a prompt: no newline, waits for stdin
sys.stderr.flush()
answer = sys.stdin.readline().strip()
print("got " + answer, flush=True)
sys.exit(2)
"""


def test_runner():
    events = []
    runner = BorgRunner(["--whatever"], events.append, executable=[sys.executable, "-c", FAKE_BORG])
    runner.PARTIAL_LINE_TIMEOUT = 0.2

    async def run():
        task = asyncio.create_task(runner.start())
        deadline = time.monotonic() + 30
        while not any(isinstance(e, RawLine) and e.partial for e in events):
            assert time.monotonic() < deadline, f"no partial line seen, events: {events}"
            await asyncio.sleep(0.02)
        await runner.answer("YES")
        await asyncio.wait_for(task, 30)

    asyncio.run(run())
    assert LogMessage(message="hello", levelname="INFO", name="borg.test") in events
    assert FileStatus(status="A", path="a/b") in events
    assert RawLine(stream="stderr", line="plain text") in events
    assert RawLine(stream="stdout", line="stdout line") in events
    assert RawLine(stream="stderr", line="Enter something: ", partial=True) in events
    assert RawLine(stream="stdout", line="got YES") in events
    assert events[-1] == ProcessFinished(rc=2)
    assert runner.process is None


def test_runner_start_failure():
    events = []
    runner = BorgRunner([], events.append, executable=["/nonexistent/borg-binary"])
    asyncio.run(runner.start())
    assert len(events) == 1
    assert isinstance(events[0], ProcessFinished) and events[0].rc == -1 and events[0].error


def test_borg_command_json_stdout():
    assert borg_command(["create", "x"], executable=["borg"], json_stdout=True) == [
        "borg",
        "--log-json",
        "--progress",
        "create",
        "x",
        "--json",
    ]
    # --json goes before a "--" end-of-options marker, and is not duplicated
    assert borg_command(["create", "x", "--", "-p"], executable=["borg"], json_stdout=True)[-4:] == [
        "x",
        "--json",
        "--",
        "-p",
    ]
    assert borg_command(["create", "--json", "x"], executable=["borg"], json_stdout=True).count("--json") == 1


FINAL_JSON = """
{
    "archive": {
        "duration": 90.5,
        "id": "0123abcd0123abcd",
        "name": "test",
        "stats": {
            "chunking_time": 0.25,
            "deduplicated_size": 300,
            "files_stats": {"A": 2, "M": 1, "d": 1},
            "hashing_time": 0.5,
            "nfiles": 3,
            "original_size": 3000,
            "store_stats": {"store_calls": 7, "store_volume": 2048}
        }
    },
    "repository": {"id": "abcd", "location": "/repo"}
}
"""


def test_session_final_stats_from_stdout():
    session = Session(command="create", capture_stdout=True)
    session.feed(ArchiveProgress(nfiles=2, original_size=2000, deduplicated_size=200, files_stats={"A": 2}))
    session.feed(FileStatus(status="A", path="a"))
    for line in FINAL_JSON.splitlines():
        session.feed(RawLine(stream="stdout", line=line))
    assert session.final_json is None and session.stdout_lines  # only parsed at the end
    lines, _ = session.drain()
    assert [line.kind for line in lines] == ["status"]  # the captured stdout is not logged
    session.feed(ProcessFinished(rc=0))
    assert session.final_json["archive"]["name"] == "test"
    assert session.archive_name == "test" and session.archive_duration == 90.5
    # the final statistics win over the --list lines and archive_progress
    assert session.nfiles == 3 and session.files_stats == {"A": 2, "M": 1, "d": 1}
    assert session.original_size == 3000 and session.deduplicated_size == 300
    lines, _ = session.drain()
    assert all(line.kind == "log" and line.tag == "STATS" for line in lines)
    assert [line.text for line in lines] == [
        "Archive name: test",
        "Archive fingerprint: 0123abcd0123abcd",
        "Duration: 1 minutes 30.500 seconds",
        "Number of files: 3",
        "Original size: 3.00 kB",
        "Deduplicated size: 300 B",
        "Time spent in hashing: 0.500 seconds",
        "Time spent in chunking: 0.250 seconds",
        "Added files: 2",
        "Unchanged files: 0",
        "Modified files: 1",
        "Error files: 0",
        "Files changed while reading: 0",
        "Store store calls: 7",
        "Store store volume: 2.05 kB",
    ]


def test_session_final_stats_dry_run():
    session = Session(command="create", capture_stdout=True)
    for line in '{"dry_run": true, "stats": {"nfiles": 5, "original_size": 1234}, "repository": {}}'.splitlines():
        session.feed(RawLine(stream="stdout", line=line))
    session.feed(ProcessFinished(rc=0))
    assert session.archive_name is None
    assert session.nfiles == 5 and session.original_size == 1234 and session.deduplicated_size is None
    lines, _ = session.drain()
    assert [line.text for line in lines] == [
        "Dry run: no archive was created.",
        "Number of files: 5",
        "Original size: 1.23 kB",
    ]


def test_session_stdout_that_is_not_json():
    session = Session(command="create", capture_stdout=True)
    session.feed(RawLine(stream="stdout", line="just text"))
    session.feed(ProcessFinished(rc=2))
    assert session.final_json is None and session.final_stats is None
    lines, _ = session.drain()
    assert [(line.kind, line.text) for line in lines] == [("raw", "just text")]


def test_session_counts_warnings():
    session = Session()
    session.feed(LogMessage(message="w", levelname="WARNING"))
    session.feed(LogMessage(message="e", levelname="ERROR"))
    session.feed(LogMessage(message="c", levelname="CRITICAL"))
    session.feed(LogMessage(message="i", levelname="INFO"))
    session.feed(LogMessage(message="+ listed", name=LIST_LOGGER))
    assert (session.warnings, session.errors) == (1, 2)


def test_session_phase_lookup_and_rates():
    session = Session()
    session.feed(ProgressPercent(operation=1, msgid="extract", message="", current=0, total=1000))
    session.feed(ProgressMessage(operation=2, msgid="cache.close", message="Saving"))
    assert session.phase("extract").operation == 1 and session.phase("nope") is None
    assert session.active_phase.operation == 2
    session.sample(now=session.started + 1.0)
    session.feed(ProgressPercent(operation=1, msgid="extract", message="", current=500, total=1000))
    session.sample(now=session.started + 2.0)
    assert session.phase("extract").rate == 500.0
    assert session.active_phase.operation == 1
    session.feed(ProgressPercent(operation=1, msgid="extract", finished=True, message=""))
    assert session.active_phase is None
    session.sample(now=session.started + 3.0)
    assert session.phase("extract").rate == 0.0
    # after the run, the rates are zero
    session.feed(ArchiveProgress(nfiles=100))
    session.feed(ProcessFinished(rc=0))
    session.sample(now=session.started + 4.0)
    assert session.files_per_second == 0.0
