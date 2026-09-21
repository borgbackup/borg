import getpass
import os
import shlex
import signal
import sys

import pytest

from ...helpers import Error
from ...helpers.parseformat import bin_to_hex
from ...helpers.passphrase import Passphrase, PasswordRetriesExceeded
from ...helpers.process import SigIntManager, signal_handler


class TestPassphrase:
    def test_passphrase_new_verification(self, capsys, monkeypatch):
        monkeypatch.setattr(getpass, "getpass", lambda prompt: "1234aöäü")
        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "no")
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "1234" not in out
        assert "1234" not in err

        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "yes")
        passphrase = Passphrase.new()
        out, err = capsys.readouterr()
        assert "3132333461c3b6c3a4c3bc" not in out
        assert "3132333461c3b6c3a4c3bc" in err
        assert passphrase == "1234aöäü"

        monkeypatch.setattr(getpass, "getpass", lambda prompt: "1234/@=")
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "1234/@=" not in out
        assert "1234/@=" in err

    def test_passphrase_new_empty(self, capsys, monkeypatch):
        monkeypatch.delenv("BORG_PASSPHRASE", False)
        monkeypatch.setattr(getpass, "getpass", lambda prompt: "")
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new(allow_empty=False)
        out, err = capsys.readouterr()
        assert "must not be blank" in err

    def test_passphrase_new_retries(self, monkeypatch):
        monkeypatch.delenv("BORG_PASSPHRASE", False)
        ascending_numbers = iter(range(20))
        monkeypatch.setattr(getpass, "getpass", lambda prompt: str(next(ascending_numbers)))
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new()

    def test_passphrase_repr(self):
        assert "secret" not in repr(Passphrase("secret"))

    def test_passphrase_wrong_debug(self, capsys, monkeypatch):
        passphrase = "wrong_passphrase"
        monkeypatch.setenv("BORG_DEBUG_PASSPHRASE", "YES")
        monkeypatch.setenv("BORG_PASSPHRASE", "env_passphrase")
        monkeypatch.setenv("BORG_PASSCOMMAND", "command")
        monkeypatch.setenv("BORG_PASSPHRASE_FD", "fd_value")

        Passphrase.display_debug_info(passphrase)

        out, err = capsys.readouterr()
        assert "Incorrect passphrase!" in err
        assert passphrase in err
        assert bin_to_hex(passphrase.encode("utf-8")) in err
        assert 'BORG_PASSPHRASE = "env_passphrase"' in err
        assert 'BORG_PASSCOMMAND = "command"' in err
        assert 'BORG_PASSPHRASE_FD = "fd_value"' in err

        monkeypatch.delenv("BORG_DEBUG_PASSPHRASE", raising=False)
        Passphrase.display_debug_info(passphrase)
        out, err = capsys.readouterr()

        assert "Incorrect passphrase!" not in err
        assert passphrase not in err

    def test_verification(self, capsys, monkeypatch):
        passphrase = "test_passphrase"
        hex_value = passphrase.encode("utf-8").hex()

        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "no")
        Passphrase.verification(passphrase)
        out, err = capsys.readouterr()
        assert passphrase not in err

        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "yes")
        Passphrase.verification(passphrase)
        out, err = capsys.readouterr()
        assert passphrase in err
        assert hex_value in err


def print_command(text):
    """Return a BORG_*_PASSCOMMAND printing *text* (shlex syntax, run without a shell)."""
    return f"{shlex.quote(sys.executable)} -c \"print('{text}')\""


class TestPassphraseEnvVarGroups:
    """The BORG_*, BORG_NEW_* and BORG_OTHER_* passphrase environment variable groups are independent."""

    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        for prefix in ("BORG_", "BORG_NEW_", "BORG_OTHER_"):
            for name in ("PASSPHRASE", "PASSCOMMAND", "PASSPHRASE_FD"):
                monkeypatch.delenv(prefix + name, raising=False)

    def test_other_and_new_are_mutually_exclusive(self):
        with pytest.raises(ValueError):
            Passphrase.env_passphrase(other=True, new=True)
        with pytest.raises(ValueError):
            Passphrase.env_passcommand(other=True, new=True)
        with pytest.raises(ValueError):
            Passphrase.fd_passphrase(other=True, new=True)

    def test_env_passphrase_selects_the_group(self, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "base-secret")
        monkeypatch.setenv("BORG_NEW_PASSPHRASE", "new-secret")
        monkeypatch.setenv("BORG_OTHER_PASSPHRASE", "other-secret")
        assert Passphrase.env_passphrase() == "base-secret"
        assert Passphrase.env_passphrase(new=True) == "new-secret"
        assert Passphrase.env_passphrase(other=True) == "other-secret"

    def test_env_passcommand_selects_the_group(self, monkeypatch):
        # regression test: an early version selected BORG_NEW_PASSCOMMAND based on the "other" flag,
        # which both broke BORG_OTHER_PASSCOMMAND and never used BORG_NEW_PASSCOMMAND.
        monkeypatch.setenv("BORG_PASSCOMMAND", print_command("base-cmd"))
        monkeypatch.setenv("BORG_NEW_PASSCOMMAND", print_command("new-cmd"))
        monkeypatch.setenv("BORG_OTHER_PASSCOMMAND", print_command("other-cmd"))
        assert Passphrase.env_passcommand() == "base-cmd"
        assert Passphrase.env_passcommand(new=True) == "new-cmd"
        assert Passphrase.env_passcommand(other=True) == "other-cmd"

    @pytest.mark.parametrize("new,other", [(False, False), (True, False), (False, True)])
    def test_fd_passphrase_selects_the_group(self, monkeypatch, new, other):
        env_var = ("BORG_NEW_" if new else "BORG_OTHER_" if other else "BORG_") + "PASSPHRASE_FD"
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"fd-secret\n")
        os.close(write_fd)
        monkeypatch.setenv(env_var, str(read_fd))
        assert Passphrase.fd_passphrase(new=new, other=other) == "fd-secret"

    def test_ambiguity_is_checked_per_group(self, monkeypatch):
        # more than one variable inside a group is ambiguous ...
        monkeypatch.setenv("BORG_NEW_PASSPHRASE", "new-secret")
        monkeypatch.setenv("BORG_NEW_PASSCOMMAND", print_command("new-cmd"))
        with pytest.raises(Error):
            Passphrase.env_passphrase(new=True)
        # ... but variables of different groups do not conflict.
        monkeypatch.delenv("BORG_NEW_PASSCOMMAND")
        monkeypatch.setenv("BORG_PASSPHRASE", "base-secret")
        monkeypatch.setenv("BORG_OTHER_PASSCOMMAND", print_command("other-cmd"))
        assert Passphrase.env_passphrase() == "base-secret"
        assert Passphrase.env_passphrase(new=True) == "new-secret"
        assert Passphrase.env_passphrase(other=True) == "other-cmd"

    def test_new_prefers_the_new_group(self, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "base-secret")
        monkeypatch.setenv("BORG_NEW_PASSPHRASE", "new-secret")
        assert Passphrase.new() == "new-secret"
        monkeypatch.delenv("BORG_NEW_PASSPHRASE")
        monkeypatch.setenv("BORG_NEW_PASSCOMMAND", print_command("new-cmd"))
        assert Passphrase.new() == "new-cmd"

    def test_new_falls_back_to_the_base_group(self, monkeypatch):
        # documented behavior: without any BORG_NEW_* variable, the new passphrase comes from
        # the regular variables, see the BORG_NEW_PASSPHRASE docs.
        monkeypatch.setenv("BORG_PASSPHRASE", "base-secret")
        assert Passphrase.new() == "base-secret"


def test_getpass_sigint_aborts(monkeypatch):
    # borg's main() has a SIGINT handler that only sets a flag, so that a running operation can be
    # finished in an orderly way. That must not swallow a Ctrl-C given while borg waits for a
    # passphrase, see #8521.
    def getpass_sending_sigint(prompt):
        # raise_signal() sends the signal to *this* thread. os.kill() would send it to the process
        # and some kernels (e.g. NetBSD) then deliver it to another thread if there is one - the
        # main thread would only run the handler later, after the prompt restored the previous one.
        signal.raise_signal(signal.SIGINT)
        return "1234"  # not reached, the signal handler raises

    monkeypatch.setattr(getpass, "getpass", getpass_sending_sigint)
    with SigIntManager():  # this is what borg does while running a command
        with pytest.raises(KeyboardInterrupt):
            Passphrase.getpass("Enter passphrase: ")


def test_getpass_restores_sigint_handler(monkeypatch):
    # asking for a passphrase must not change the SIGINT handling of everything that comes after it.
    def handler(sig_no, stack):  # never called, we just need an identifiable handler
        pass

    monkeypatch.setattr(getpass, "getpass", lambda prompt: "1234")
    with signal_handler("SIGINT", handler):
        assert Passphrase.getpass("Enter passphrase: ") == "1234"
        assert signal.getsignal(signal.SIGINT) is handler
