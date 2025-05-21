import pytest

from ...helpers.yes_no import yes, TRUISH, FALSISH, DEFAULTISH
from .. import FakeInputs


def test_yes_input():
    inputs = list(TRUISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert yes(input=input)
    inputs = list(FALSISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert not yes(input=input)


def test_yes_input_defaults():
    inputs = list(DEFAULTISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert yes(default=True, input=input)
    input = FakeInputs(inputs)
    for i in inputs:
        assert not yes(default=False, input=input)


def test_yes_input_custom():
    input = FakeInputs(["YES", "SURE", "NOPE"])
    assert yes(truish=("YES",), input=input)
    assert yes(truish=("SURE",), input=input)
    assert not yes(falsish=("NOPE",), input=input)


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
    input = FakeInputs(["invalid", "", " "])
    assert not yes(input=input)  # default=False
    assert not yes(input=input)
    assert not yes(input=input)
    input = FakeInputs(["invalid", "", " "])
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    input = FakeInputs([])
    assert yes(default=True, input=input)
    assert not yes(default=False, input=input)
    with pytest.raises(ValueError):
        yes(default=None)


def test_yes_retry():
    input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert yes(retry_msg="Retry: ", input=input)
    input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert not yes(retry_msg="Retry: ", input=input)


def test_yes_no_retry():
    input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert not yes(retry=False, default=False, input=input)
    input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert yes(retry=False, default=True, input=input)


def test_yes_output(capfd):
    input = FakeInputs(["invalid", "y", "n"])
    assert yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=input)
    out, err = capfd.readouterr()
    assert out == ""
    assert "intro-msg" in err
    assert "retry-msg" in err
    assert "true-msg" in err
    assert not yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=input)
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
