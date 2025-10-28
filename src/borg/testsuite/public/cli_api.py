from unittest.mock import patch

import pytest

import borg.public.cli_api.v1 as v1
from borg.helpers.progress import ProgressIndicatorBase


@pytest.fixture(autouse=True)
def reset_progress_operation_id():
    """Reset ProgressIndicatorBase operation ID counter after each test.

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
