import json
import logging
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest
from borg.item import Item

import borg.public.cli_api.v1 as v1
from borg.archive import Statistics
from borg.archiver import Archiver
from borg.helpers.parseformat import BorgJsonEncoder
from borg.helpers.progress import ProgressIndicatorBase, ProgressIndicatorMessage
from borg.helpers.time import OutputTimestamp, to_localtime
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
    override_time = 1234.56

    item = Item(path="foo/bar.txt")
    out = StringIO()
    stats.show_progress(item=item, stream=out, override_time=override_time)

    json_output = out.getvalue()
    parsed = v1.ArchiveProgressLogLine.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.ArchiveProgressLogLine(
        original_size=20,
        compressed_size=10,
        deduplicated_size=10,
        nfiles=0,
        path=Path("foo/bar.txt"),
        time=override_time,
    )


def test_parse_finished_archive_progress():
    """Test parsing FinishedArchiveProgress from Statistics.show_progress(final=True)."""
    stats = Statistics()
    stats.output_json = True
    override_time = 5678.90

    out = StringIO()
    stats.show_progress(stream=out, final=True, override_time=override_time)

    json_output = out.getvalue()
    parsed = v1.FinishedArchiveProgress.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.FinishedArchiveProgress(
        type="archive_progress",
        finished=True,
        time=override_time,
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
    test_time = 1234567890.123

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
    record.created = test_time

    json_output = formatter.format(record)
    parsed = v1.LogMessage.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.LogMessage(
        levelname="INFO",
        name="borg.test",
        message="Test message",
        msgid="test.msgid",
        time=test_time,
    )


def test_parse_log_message_all_levels():
    """Test parsing LogMessage for all log levels."""
    formatter = JsonFormatter()
    test_time = 1234567890.456

    levels: list[tuple[int, Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]]] = [
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
        record.created = test_time

        json_output = formatter.format(record)
        parsed = v1.LogMessage.model_validate_json(json_output)

        assert isinstance(parsed.time, float)
        assert parsed == v1.LogMessage(
            levelname=level_name,
            name="borg.test",
            message=f"{level_name} message",
            msgid=None,
            time=test_time,
        )


def test_parse_log_message_without_msgid():
    """Test parsing LogMessage without msgid field."""
    formatter = JsonFormatter()
    test_time = 1234567890.789

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
    record.created = test_time

    json_output = formatter.format(record)
    parsed = v1.LogMessage.model_validate_json(json_output)

    assert isinstance(parsed.time, float)
    assert parsed == v1.LogMessage(
        levelname="WARNING",
        name="borg.test",
        message="Warning without msgid",
        msgid=None,
        time=test_time,
    )


def test_parse_borg_create_result():
    """Test parsing BorgCreateResult from Archive.info() output."""
    # Create timestamps in UTC
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

    # OutputTimestamp converts UTC to localtime (naive datetime)
    # When Pydantic parses the ISO string back, it creates a naive datetime
    expected_start = to_localtime(start_time)
    expected_end = to_localtime(end_time)

    assert parsed == v1.BorgCreateResult(
        archive=v1._BorgDetailedArchive(
            name="test-archive",
            id="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            start=expected_start,
            end=expected_end,
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

    # OutputTimestamp converts UTC to localtime (naive datetime)
    expected_start1 = to_localtime(start_time1)
    expected_start2 = to_localtime(start_time2)

    assert parsed == v1.BorgListResult(
        archives=[
            v1._BorgArchive(
                name="archive-2024-01-15",
                id="aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
                start=expected_start1,
            ),
            v1._BorgArchive(
                name="archive-2024-01-16",
                id="bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888cccc9999",
                start=expected_start2,
            ),
        ]
    )


def test_parse_borg_list_result_empty():
    """Test parsing BorgListResult with no archives."""
    json_output = json.dumps({"archives": []}, cls=BorgJsonEncoder)
    parsed = v1.BorgListResult.model_validate_json(json_output)

    assert len(parsed.archives) == 0


def test_parse_chunker_params_empty_string():
    """Test parsing when chunker_params is an empty string (old archives without chunker_params)."""
    start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    end_time = datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc)

    archive_info = {
        "name": "old-archive",
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
        "command_line": ["borg", "create", "::old-archive", "/data"],
        "chunker_params": "",  # Empty string as set in archive.py line 555
    }

    json_output = json.dumps({"archive": archive_info}, cls=BorgJsonEncoder)
    parsed = v1.BorgCreateResult.model_validate_json(json_output)

    # Empty string should be treated as None
    assert parsed.archive.chunker_params is None


def test_parse_chunker_params_with_values():
    """Test parsing when chunker_params has actual values."""
    start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    end_time = datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc)

    archive_info = {
        "name": "new-archive",
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
        "command_line": ["borg", "create", "::new-archive", "/data"],
        "chunker_params": ["buzhash", 19, 23, 21, 4095],  # As a list (JSON serialized tuple)
    }

    json_output = json.dumps({"archive": archive_info}, cls=BorgJsonEncoder)
    parsed = v1.BorgCreateResult.model_validate_json(json_output)

    assert parsed.archive.chunker_params is not None
    assert parsed.archive.chunker_params.algorithm == "buzhash"
    assert parsed.archive.chunker_params.min_exp == 19
    assert parsed.archive.chunker_params.max_exp == 23
    assert parsed.archive.chunker_params.mask_bits == 21
    assert parsed.archive.chunker_params.window_size == 4095


def test_parse_chunker_params_fixed_algorithm():
    """Test parsing chunker_params with 'fixed' algorithm."""
    start_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    end_time = datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc)

    archive_info = {
        "name": "fixed-archive",
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
        "command_line": ["borg", "create", "::fixed-archive", "/data"],
        "chunker_params": ["fixed", 16, 20, 18, 2048],
    }

    json_output = json.dumps({"archive": archive_info}, cls=BorgJsonEncoder)
    parsed = v1.BorgCreateResult.model_validate_json(json_output)

    assert parsed.archive.chunker_params is not None
    assert parsed.archive.chunker_params.algorithm == "fixed"
    assert parsed.archive.chunker_params.min_exp == 16
    assert parsed.archive.chunker_params.max_exp == 20
    assert parsed.archive.chunker_params.mask_bits == 18
    assert parsed.archive.chunker_params.window_size == 2048
