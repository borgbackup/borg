import pytest

from ...helpers import progress
from ...helpers.progress import ProgressIndicatorPercent, get_progress_dt


@pytest.mark.parametrize(
    "fps_str,dt", [("10", 0.1), ("2", 0.5), ("0.1", 10.0), (" 5 ", 0.2)]  # surrounding whitespace is ignored
)
def test_progress_dt(monkeypatch, fps_str, dt):
    monkeypatch.setenv("BORG_PROGRESS_FPS", fps_str)
    assert get_progress_dt() == pytest.approx(dt)


def test_progress_dt_default(monkeypatch):
    monkeypatch.delenv("BORG_PROGRESS_FPS", raising=False)
    assert get_progress_dt() == pytest.approx(0.2)
    monkeypatch.setenv("BORG_PROGRESS_FPS", "")
    assert get_progress_dt() == pytest.approx(0.2)


@pytest.mark.parametrize("fps_str", ["banana", "0", "-5", "nan"])
def test_progress_dt_invalid(monkeypatch, caplog, fps_str):
    monkeypatch.setattr(progress, "_warned_fps", set())
    monkeypatch.setenv("BORG_PROGRESS_FPS", fps_str)
    assert get_progress_dt() == pytest.approx(0.2)
    assert "Invalid BORG_PROGRESS_FPS" in caplog.text
    caplog.clear()
    assert get_progress_dt() == pytest.approx(0.2)  # only warn once per value
    assert caplog.text == ""


def test_progress_percentage(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show(420)
    pi.show(680)
    out, err = capfd.readouterr()
    assert err == " 42%\n 68%\n"
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == "100%\n"
    pi.finish()
    out, err = capfd.readouterr()
    assert err == "\n"


def test_progress_percentage_step(capfd):
    pi = ProgressIndicatorPercent(100, step=2, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show()
    out, err = capfd.readouterr()
    assert err == ""  # no output at 1% as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  2%\n"


def test_progress_percentage_quiet(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("WARN")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == ""
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == ""
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ""
