import shutil
import pytest

from ... import __version__
from ...helpers.process import popen_with_error_handling, prepare_subprocess_env, SUBPROCESS_ENV_REMOVE


class TestPopenWithErrorHandling:
    @pytest.mark.skipif(not shutil.which("test"), reason='"test" binary is required')
    def test_simple(self):
        proc = popen_with_error_handling("test 1")
        assert proc.wait() == 0

    @pytest.mark.skipif(
        shutil.which("borg-foobar-test-notexist"), reason='"borg-foobar-test-notexist" binary exists (somehow?)'
    )
    def test_not_found(self):
        proc = popen_with_error_handling("borg-foobar-test-notexist 1234")
        assert proc is None

    @pytest.mark.parametrize("cmd", ('mismatched "quote', 'foo --bar="baz', ""))
    def test_bad_syntax(self, cmd):
        proc = popen_with_error_handling(cmd)
        assert proc is None

    def test_shell(self):
        with pytest.raises(AssertionError):
            popen_with_error_handling("", shell=True)


class TestPrepareSubprocessEnv:
    @pytest.mark.parametrize("name", SUBPROCESS_ENV_REMOVE)
    @pytest.mark.parametrize("system", (True, False))
    def test_removes_secrets_from_os_environ(self, monkeypatch, name, system):
        monkeypatch.setenv(name, "secret")
        assert name not in prepare_subprocess_env(system=system)

    def test_removes_secrets_from_given_env(self):
        env = {name: "secret" for name in SUBPROCESS_ENV_REMOVE}
        env["BORG_REPO"] = "/path/to/repo"
        result = prepare_subprocess_env(system=True, env=env)
        assert not set(result) & set(SUBPROCESS_ENV_REMOVE)
        assert result["BORG_REPO"] == "/path/to/repo"
        # the given env must not be modified
        assert env["BORG_PASSPHRASE"] == "secret"
        assert "BORG_VERSION" not in env

    def test_keeps_other_variables_and_sets_version(self, monkeypatch):
        monkeypatch.setenv("BORG_REPO", "/path/to/repo")
        monkeypatch.setenv("BORG_KEY_FILE", "/path/to/keyfile")
        monkeypatch.setenv("BORGSTORE_REST_USERNAME", "username")
        monkeypatch.setenv("HOME", "/home/user")
        env = prepare_subprocess_env(system=True)
        assert env["BORG_REPO"] == "/path/to/repo"
        assert env["BORG_KEY_FILE"] == "/path/to/keyfile"
        assert env["BORGSTORE_REST_USERNAME"] == "username"
        assert env["HOME"] == "/home/user"
        assert env["BORG_VERSION"] == __version__
