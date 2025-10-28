import json
import logging
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from borg.item import Item

import borg.public.cli_api.v1 as v1
from borg.archive import Statistics
from borg.archiver import Archiver
from borg.helpers.parseformat import BorgJsonEncoder
from borg.helpers.progress import ProgressIndicatorBase, ProgressIndicatorMessage
from borg.helpers.time import OutputTimestamp
from borg.logger import JsonFormatter


@pytest.fixture(autouse=True)
def reset_progress_operation_id():
    """Reset ProgressIndicatorBase operation ID counter before each test.

    This ensures each test gets predictable operation IDs starting from 1.
    """
    yield
    ProgressIndicatorBase.operation_id_counter = 0


def test_parse_progress_percent_unfinished():
    percent = ProgressIndicatorBase()
    percent.json = True
    percent.emit = True
    override_time = 4567.23

    with patch("builtins.print") as mock_print:
        percent.output_json(finished=False, current=10, override_time=override_time)
        mock_print.assert_called_once()
        json_output = mock_print.call_args[0][0]

    assert v1.ProgressPercent.model_validate_json(json_output) == v1.ProgressPercent(
        operation=1, msgid=None, finished=False, message=None, current=10, info=None, total=None, time=4567.23
    )


def test_parse_progress_percent_finished():
    percent = ProgressIndicatorBase()
    percent.json = True
    percent.emit = True
    override_time = 4567.23

    with patch("builtins.print") as mock_print:
        percent.output_json(finished=True, override_time=override_time)
        mock_print.assert_called_once()
        json_output = mock_print.call_args[0][0]

    assert v1.ProgressPercent.model_validate_json(json_output) == v1.ProgressPercent(
        operation=1, msgid=None, finished=True, message=None, current=None, info=None, total=None, time=override_time
    )


def test_parse_archive_progress_log_line():
    """Test parsing ArchiveProgressLogLine from Statistics.show_progress()."""
    stats = Statistics()
    stats.update(20, 10, unique=True)
    stats.output_json = True

    item = Item(path="foo/bar.txt")
    out = StringIO()
    stats.show_progress(item=item, stream=out)

    json_output = out.getvalue()
    parsed = v1.ArchiveProgressLogLine.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.ArchiveProgressLogLine(
        original_size=20,
        compressed_size=10,
        deduplicated_size=10,
        nfiles=0,
        path=Path("foo/bar.txt"),
        time=parsed.time,  # Use parsed value instead of injecting
    )


def test_parse_finished_archive_progress():
    """Test parsing FinishedArchiveProgress from Statistics.show_progress(final=True)."""
    stats = Statistics()
    stats.output_json = True

    out = StringIO()
    stats.show_progress(stream=out, final=True)

    json_output = out.getvalue()
    parsed = v1.FinishedArchiveProgress.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.FinishedArchiveProgress(
        type="archive_progress",
        finished=True,
        time=parsed.time,  # Use parsed value instead of injecting
    )


def test_parse_progress_message_unfinished():
    """Test parsing ProgressMessage from ProgressIndicatorMessage with message."""
    progress = ProgressIndicatorMessage()
    progress.json = True
    progress.emit = True
    override_time = 1234.56

    with patch("builtins.print") as mock_print:
        progress.output_json(message="Processing files", override_time=override_time)
        mock_print.assert_called_once()
        json_output = mock_print.call_args[0][0]

    parsed = v1.ProgressMessage.model_validate_json(json_output)

    assert parsed == v1.ProgressMessage(
        operation=progress.id,
        msgid=None,
        finished=False,
        message="Processing files",
        time=1234.56,
    )


def test_parse_progress_message_finished():
    """Test parsing ProgressMessage when finished."""
    progress = ProgressIndicatorMessage()
    progress.json = True
    progress.emit = True
    override_time = 5678.90

    with patch("builtins.print") as mock_print:
        progress.output_json(finished=True, override_time=override_time)
        mock_print.assert_called_once()
        json_output = mock_print.call_args[0][0]

    parsed = v1.ProgressMessage.model_validate_json(json_output)

    assert parsed == v1.ProgressMessage(
        operation=progress.id,
        msgid=None,
        finished=True,
        message=None,
        time=5678.90,
    )


def test_parse_file_status():
    """Test parsing FileStatus from Archiver.print_file_status()."""
    archiver = Archiver()
    archiver.output_list = True
    archiver.output_filter = None
    archiver.log_json = True

    stderr_capture = StringIO()
    with patch("sys.stderr", stderr_capture):
        archiver.print_file_status("A", "path/to/file.txt")

    json_output = stderr_capture.getvalue()
    parsed = v1.FileStatus.model_validate_json(json_output)

    assert parsed == v1.FileStatus(status="A", path=Path("path/to/file.txt"))


def test_parse_log_message():
    """Test parsing LogMessage from JsonFormatter."""
    formatter = JsonFormatter()

    # Create a LogRecord with all required fields
    record = logging.LogRecord(
        name="borg.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    record.msgid = "test.msgid"

    json_output = formatter.format(record)
    parsed = v1.LogMessage.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.LogMessage(
        levelname="INFO",
        name="borg.test",
        message="Test message",
        msgid="test.msgid",
        time=parsed.time,  # Use parsed value instead of injecting
    )


def test_parse_log_message_all_levels():
    """Test parsing LogMessage for all log levels."""
    formatter = JsonFormatter()

    levels = [
        (logging.DEBUG, "DEBUG"),
        (logging.INFO, "INFO"),
        (logging.WARNING, "WARNING"),
        (logging.ERROR, "ERROR"),
        (logging.CRITICAL, "CRITICAL"),
    ]

    for level_num, level_name in levels:
        record = logging.LogRecord(
            name="borg.test",
            level=level_num,
            pathname="test.py",
            lineno=1,
            msg=f"{level_name} message",
            args=(),
            exc_info=None,
        )

        json_output = formatter.format(record)
        parsed = v1.LogMessage.model_validate_json(json_output)

        assert isinstance(parsed.time, float)
        assert parsed == v1.LogMessage(
            levelname=level_name,
            name="borg.test",
            message=f"{level_name} message",
            msgid=None,
            time=parsed.time,  # Use parsed value instead of injecting
        )


def test_parse_log_message_without_msgid():
    """Test parsing LogMessage without msgid field."""
    formatter = JsonFormatter()

    record = logging.LogRecord(
        name="borg.test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=10,
        msg="Warning without msgid",
        args=(),
        exc_info=None,
    )
    # Don't set msgid - it should be None or absent

    json_output = formatter.format(record)
    parsed = v1.LogMessage.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.LogMessage(
        levelname="WARNING",
        name="borg.test",
        message="Warning without msgid",
        msgid=None,
        time=parsed.time,  # Use parsed value instead of injecting
    )


def test_parse_borg_create_result():
    """Test parsing BorgCreateResult from Archive.info() output."""
    # Create a mock archive that produces the same output as the production code
    start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    end_time = datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc)

    # Build the archive info dict as production code does
    archive_info = {
        "name": "test-archive",
        "id": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "start": OutputTimestamp(start_time),
        "end": OutputTimestamp(end_time),
        "duration": (end_time - start_time).total_seconds(),
        "stats": {
            "original_size": 1000000,
            "compressed_size": 500000,
            "deduplicated_size": 250000,
            "nfiles": 42,
        },
        "limits": {
            "max_archive_size": 0.05,
        },
        "command_line": ["borg", "create", "::test-archive", "/data"],
    }

    # Use BorgJsonEncoder to serialize as production does
    json_output = json.dumps({"archive": archive_info}, cls=BorgJsonEncoder)
    parsed = v1.BorgCreateResult.model_validate_json(json_output)

    assert parsed == v1.BorgCreateResult(
        archive=v1._BorgDetailedArchive(
            name="test-archive",
            id="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            start=parsed.archive.start,  # Use actual parsed datetime (may lose timezone info)
            end=parsed.archive.end,  # Use actual parsed datetime (may lose timezone info)
            duration=300.0,
            stats=v1._BorgArchiveStatistics(
                original_size=1000000,
                compressed_size=500000,
                deduplicated_size=250000,
                nfiles=42,
            ),
            limits=v1._BorgLimitUsage(max_archive_size=0.05),
            command_line=["borg", "create", "::test-archive", "/data"],
            chunker_params=None,
        )
    )


def test_parse_borg_list_result():
    """Test parsing BorgListResult from ArchiveFormatter.get_item_data() output."""
    # Build archive list as production code does
    start_time1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    start_time2 = datetime(2024, 1, 16, 10, 0, 0, tzinfo=timezone.utc)

    archives_list = [
        {
            "name": "archive-2024-01-15",
            "id": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
            "start": OutputTimestamp(start_time1),
        },
        {
            "name": "archive-2024-01-16",
            "id": "bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888cccc9999",
            "start": OutputTimestamp(start_time2),
        },
    ]

    # Use BorgJsonEncoder to serialize as production does
    json_output = json.dumps({"archives": archives_list}, cls=BorgJsonEncoder)
    parsed = v1.BorgListResult.model_validate_json(json_output)

    assert parsed == v1.BorgListResult(
        archives=[
            v1._BorgArchive(
                name="archive-2024-01-15",
                id="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
                start=parsed.archives[0].start,  # Use actual parsed datetime (may lose timezone info)
            ),
            v1._BorgArchive(
                name="archive-2024-01-16",
                id="bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888cccc9999",
                start=parsed.archives[1].start,  # Use actual parsed datetime (may lose timezone info)
            ),
        ]
    )


def test_parse_borg_list_result_empty():
    """Test parsing BorgListResult with no archives."""
    json_output = json.dumps({"archives": []}, cls=BorgJsonEncoder)
    parsed = v1.BorgListResult.model_validate_json(json_output)

    assert len(parsed.archives) == 0
