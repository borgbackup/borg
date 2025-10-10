import getpass
import pytest

from ...helpers.parseformat import bin_to_hex
from ...helpers.passphrase import Passphrase, PasswordRetriesExceeded


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
