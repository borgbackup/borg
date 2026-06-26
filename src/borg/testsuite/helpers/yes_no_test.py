import pytest

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
