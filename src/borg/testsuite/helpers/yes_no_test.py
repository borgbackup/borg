import json
import logging
import signal

import pytest

from ...helpers.process import SigIntManager, signal_handler
from ...helpers.yes_no import yes, TRUISH, FALSISH, DEFAULTISH
from .. import FakeInputs


def test_yes_input():
    inputs = list(TRUISH)
    fake_input = FakeInputs(inputs)
    while fake_input.available():
        assert yes(input=fake_input)
    inputs = list(FALSISH)
    fake_input = FakeInputs(inputs)
    while fake_input.available():
        assert not yes(input=fake_input)


def test_yes_sigint_aborts():
    # borg's main() has a SIGINT handler that only sets a flag, so that a running operation can
    # be finished in an orderly way. That must not swallow a Ctrl-C given while borg waits for an
    # answer to a y/n question, see #8521.
    def input_sending_sigint():
        # raise_signal() sends the signal to *this* thread. os.kill() would send it to the
        # process and some kernels (e.g. NetBSD) then deliver it to another thread if there is
        # one - the main thread would only run the handler later, after yes() has restored the
        # previous one, and the test would flap.
        signal.raise_signal(signal.SIGINT)
        return "y"  # not reached, the signal handler raises

    with SigIntManager():  # this is what borg does while running a command
        with pytest.raises(KeyboardInterrupt):
            yes(input=input_sending_sigint)


def test_yes_restores_sigint_handler():
    # asking a question must not change the SIGINT handling of everything that comes after it.
    def handler(sig_no, stack):  # never called, we just need an identifiable handler
        pass

    with signal_handler("SIGINT", handler):
        assert yes(input=lambda: "y")
        assert signal.getsignal(signal.SIGINT) is handler


def test_yes_input_defaults():
    inputs = list(DEFAULTISH)
    fake_input = FakeInputs(inputs)
    while fake_input.available():
        assert yes(default=True, input=fake_input)
    fake_input = FakeInputs(inputs)
    while fake_input.available():
        assert not yes(default=False, input=fake_input)


def test_yes_input_custom():
    fake_input = FakeInputs(["YES", "SURE", "NOPE"])
    assert yes(truish=("YES",), input=fake_input)
    assert yes(truish=("SURE",), input=fake_input)
    assert not yes(falsish=("NOPE",), input=fake_input)


def test_yes_env(monkeypatch):
    for value in TRUISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert yes(env_var_override="OVERRIDE_THIS")
    for value in FALSISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert not yes(env_var_override="OVERRIDE_THIS")


def test_yes_env_default(monkeypatch):
    for value in DEFAULTISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert yes(env_var_override="OVERRIDE_THIS", default=True)
        assert not yes(env_var_override="OVERRIDE_THIS", default=False)


def test_yes_defaults():
    fake_input = FakeInputs(["invalid", "", " "])
    assert not yes(input=fake_input)  # default=False
    assert not yes(input=fake_input)
    assert not yes(input=fake_input)
    fake_input = FakeInputs(["invalid", "", " "])
    assert yes(default=True, input=fake_input)
    assert yes(default=True, input=fake_input)
    assert yes(default=True, input=fake_input)
    fake_input = FakeInputs([])
    assert yes(default=True, input=fake_input)
    assert not yes(default=False, input=fake_input)
    with pytest.raises(ValueError):
        yes(default=None)


def test_yes_retry():
    fake_input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert yes(retry_msg="Retry: ", input=fake_input)
    fake_input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert not yes(retry_msg="Retry: ", input=fake_input)


def test_yes_no_retry():
    input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert not yes(retry=False, default=False, input=input)
    input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert yes(retry=False, default=True, input=input)


def test_yes_output(capfd):
    fake_input = FakeInputs(["invalid", "y", "n"])
    assert yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=fake_input)
    out, err = capfd.readouterr()
    assert out == ""
    assert "intro-msg" in err
    assert "retry-msg" in err
    assert "true-msg" in err
    assert not yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=fake_input)
    out, err = capfd.readouterr()
    assert out == ""
    assert "intro-msg" in err
    assert "retry-msg" not in err
    assert "false-msg" in err


def test_yes_env_output(capfd, monkeypatch):
    env_var = "OVERRIDE_SOMETHING"
    monkeypatch.setenv(env_var, "yes")
    assert yes(env_var_override=env_var)
    out, err = capfd.readouterr()
    assert out == ""
    assert env_var in err
    assert "yes" in err


def test_yes_json_output(capfd, monkeypatch):
    # with --log-json, setup_logging() sets the "json" attribute on the "borg" logger
    # and yes() then emits question_* JSON objects on stderr instead of plain text.
    monkeypatch.setattr(logging.getLogger("borg"), "json", True, raising=False)
    fake_input = FakeInputs(["invalid", "y"])
    assert yes(
        msg="intro-msg",
        true_msg="true-msg",
        false_msg="false-msg",
        invalid_msg="invalid-msg",
        retry_msg="retry-msg",
        input=fake_input,
        msgid="TEST_MSGID",
    )
    out, err = capfd.readouterr()
    assert out == ""
    objects = [json.loads(line) for line in err.splitlines()]
    assert [o["type"] for o in objects] == [
        "question_prompt",
        "question_invalid_answer",
        "question_prompt_retry",
        "question_accepted_true",
    ]
    assert [o["message"] for o in objects] == ["intro-msg", "invalid-msg", "retry-msg", "true-msg"]
    for o in objects:
        assert o["msgid"] == "TEST_MSGID"


def test_yes_env_json_output(capfd, monkeypatch):
    monkeypatch.setattr(logging.getLogger("borg"), "json", True, raising=False)
    env_var = "OVERRIDE_SOMETHING"
    monkeypatch.setenv(env_var, "yes")
    assert yes(env_var_override=env_var)
    out, err = capfd.readouterr()
    assert out == ""
    (o,) = [json.loads(line) for line in err.splitlines()]
    assert o["type"] == "question_env_answer"
    assert o["msgid"] == env_var  # msgid defaults to env_var_override
    assert o["env_var"] == env_var
    assert o["message"] == f"yes (from {env_var})"
