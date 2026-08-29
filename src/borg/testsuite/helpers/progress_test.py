import io
import logging

import pytest

from ...helpers import progress
from ...helpers.progress import ProgressIndicatorBase, ProgressIndicatorPercent, ProgressIndicatorSpinner
from ...helpers.progress import get_progress_dt
from ...helpers.progress import ANSI_CLEAR_LINE, ANSI_HIDE_CURSOR, ANSI_SHOW_CURSOR, GREEN_16, GREEN_TRUECOLOR


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


class FakeStream(io.StringIO):
    """A stream that has an encoding, like the real stderr has."""

    encoding = "utf-8"


class FakeTTY(FakeStream):
    """A stream that claims to be a terminal, so the spinner animates into it."""

    def isatty(self):
        return True


@pytest.fixture
def progress_logger():
    """The progress logger at the level setup_logging() gives it, restored afterwards."""
    logger = logging.getLogger(ProgressIndicatorBase.LOGGER)
    level = logger.level
    logger.setLevel(logging.INFO)  # setLevel (not .level = ...): it also invalidates the isEnabledFor cache
    yield logger
    logger.setLevel(level)


@pytest.fixture
def tty(monkeypatch, progress_logger):
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "80")  # make the terminal width deterministic
    monkeypatch.setenv("NO_COLOR", "1")  # ... and the escape sequences short
    monkeypatch.delenv("COLORTERM", raising=False)  # the real terminal's value must not leak in
    monkeypatch.delenv("BORG_SPINNER", raising=False)
    return FakeTTY()


def show_force(spinner, message=None):
    # bypass the BORG_PROGRESS_FPS rate limiting, so every call produces output
    spinner.next_update = 0.0
    spinner.show(message)


def test_spinner_animates(tty):
    spinner = ProgressIndicatorSpinner("Deduplicating", stream=tty)
    assert spinner.animate
    show_force(spinner)
    assert tty.getvalue() == ANSI_HIDE_CURSOR + ANSI_CLEAR_LINE + "▫ Deduplicating"
    tty.truncate(0), tty.seek(0)
    show_force(spinner, "Compacting")
    show_force(spinner)
    show_force(spinner)
    show_force(spinner)  # frames wrap around to the first one
    assert tty.getvalue() == "".join(ANSI_CLEAR_LINE + f"{frame} Compacting" for frame in "▪◻◼▫")
    tty.truncate(0), tty.seek(0)
    spinner.finish()
    assert tty.getvalue() == ANSI_CLEAR_LINE + ANSI_SHOW_CURSOR


def test_spinner_rate_limited(tty, monkeypatch):
    monkeypatch.setenv("BORG_PROGRESS_FPS", "0.1")  # one update per 10s
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    spinner.show()  # the first update is always shown
    assert tty.getvalue() != ""
    tty.truncate(0), tty.seek(0)
    spinner.show()  # immediately after: suppressed by the rate limit
    spinner.show("even a new message has to wait")
    assert tty.getvalue() == ""


def test_spinner_context_manager(tty):
    with ProgressIndicatorSpinner("Working", stream=tty) as spinner:
        show_force(spinner)
    assert tty.getvalue().startswith(ANSI_HIDE_CURSOR)
    assert tty.getvalue().endswith(ANSI_CLEAR_LINE + ANSI_SHOW_CURSOR)


def test_spinner_nothing_painted_nothing_to_clean_up(tty):
    with ProgressIndicatorSpinner("Working", stream=tty):
        pass  # no show() call, so we never hid the cursor and must not paint anything either
    assert tty.getvalue() == ""


def test_spinner_no_message(tty):
    spinner = ProgressIndicatorSpinner(stream=tty)
    show_force(spinner)
    assert tty.getvalue() == ANSI_HIDE_CURSOR + ANSI_CLEAR_LINE + "▫"  # no trailing blank


def test_spinner_long_message_truncated(tty):
    spinner = ProgressIndicatorSpinner(stream=tty)
    show_force(spinner, "x" * 200)
    line = tty.getvalue().rsplit(ANSI_CLEAR_LINE, 1)[1]
    assert len(line) <= 80
    assert line.startswith("▫ xxx") and line.endswith("xxx")


@pytest.mark.parametrize("frames,expected", [("cube", "◰"), ("square", "▫"), ("boxed", "⊞"), ("+x", "+")])
def test_spinner_frame_sets(tty, frames, expected):
    spinner = ProgressIndicatorSpinner(frames=frames, stream=tty)
    show_force(spinner)
    assert tty.getvalue().endswith(expected)


def test_spinner_ascii_forced(tty, monkeypatch):
    monkeypatch.setenv("BORG_SPINNER", "ascii")
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    show_force(spinner)
    assert tty.getvalue().endswith("| Working")


def test_spinner_ascii_fallback_for_unencodable_frames(tty):
    tty.encoding = "ascii"  # a terminal that can not represent the fancy frames
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    show_force(spinner)
    assert tty.getvalue().endswith("| Working")


@pytest.mark.parametrize(
    "env,colour",
    [
        ({}, GREEN_16),
        ({"COLORTERM": "truecolor"}, GREEN_TRUECOLOR),
        ({"COLORTERM": "24bit"}, GREEN_TRUECOLOR),
        ({"COLORTERM": "8bit"}, GREEN_16),
        ({"NO_COLOR": "1"}, ""),
        ({"NO_COLOR": "1", "COLORTERM": "truecolor"}, ""),
    ],
)
def test_spinner_colour(tty, monkeypatch, env, colour):
    monkeypatch.delenv("NO_COLOR", raising=False)  # the tty fixture sets it
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    show_force(spinner)
    assert tty.getvalue().endswith(f"{colour}▫{progress.ANSI_RESET if colour else ''} Working")


def test_spinner_quiet(tty, progress_logger):
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    progress_logger.setLevel("WARN")  # e.g. --quiet
    show_force(spinner)
    assert tty.getvalue() == ""


def test_spinner_broken_stream(tty):
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    tty.close()  # e.g. the terminal went away
    show_force(spinner)
    assert not spinner.animate  # we gave up on it, no exception


@pytest.mark.parametrize("env", [{"BORG_SPINNER": "off"}, {"TERM": "dumb"}, {"TERM": ""}])
def test_spinner_animation_disabled(tty, monkeypatch, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    spinner = ProgressIndicatorSpinner("Working", stream=tty)
    assert not spinner.animate
    show_force(spinner)
    assert tty.getvalue() == ""  # nothing painted, it goes to the log instead


def test_spinner_no_tty(capfd, monkeypatch, progress_logger):
    monkeypatch.delenv("BORG_SPINNER", raising=False)
    spinner = ProgressIndicatorSpinner("Saving files cache")  # stderr is not a tty here
    assert not spinner.animate
    show_force(spinner)
    out, err = capfd.readouterr()
    assert err == "Saving files cache\n"
    show_force(spinner)  # the message did not change: an animation frame is all we could add
    show_force(spinner)
    out, err = capfd.readouterr()
    assert err == ""
    show_force(spinner, "Saving chunks cache")
    out, err = capfd.readouterr()
    assert err == "Saving chunks cache\n"
    spinner.finish()
    out, err = capfd.readouterr()
    assert err == "\n"  # the "finished" record, like the other progress indicators emit it


def test_spinner_no_tty_quiet(capfd, progress_logger):
    spinner = ProgressIndicatorSpinner("Saving files cache")
    progress_logger.setLevel("WARN")  # e.g. --quiet
    show_force(spinner)
    spinner.finish()
    out, err = capfd.readouterr()
    assert err == ""


def test_spinner_animate_forced(monkeypatch, progress_logger):
    stream = FakeStream()  # not a tty at all
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("NO_COLOR", "1")
    spinner = ProgressIndicatorSpinner("Working", stream=stream, animate=True)
    show_force(spinner)
    assert stream.getvalue().endswith("▫ Working")
