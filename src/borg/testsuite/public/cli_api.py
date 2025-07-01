import borg.public.cli_api.v1 as v1
from borg.helpers.progress import ProgressIndicatorBase


def test_parse_progress_percent_unfinished():
    percent = ProgressIndicatorBase()
    override_time = 4567.23
    json_output = percent.make_json(finished=False, current=10, override_time=override_time)
    assert v1.ProgressPercent.model_validate_json(json_output) == v1.ProgressPercent(
        operation=1, msgid=None, finished=False, message=None, current=10, info=None, total=None, time=4567.23
    )


def test_parse_progress_percent_finished():
    percent = ProgressIndicatorBase()
    override_time = 4567.23
    json_output = percent.make_json(finished=True, override_time=override_time)
    assert v1.ProgressPercent.model_validate_json(json_output) == v1.ProgressPercent(
        operation=1, msgid=None, finished=True, message=None, current=None, info=None, total=None, time=override_time
    )
