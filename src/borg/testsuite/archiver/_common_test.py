from unittest.mock import MagicMock, patch


def test_get_repository_ssh_v1_uses_legacy_remote():
    """get_repository picks LegacyRemoteRepository when proto=ssh and v1_or_v2=True."""
    from ...archiver._common import get_repository

    location = MagicMock()
    location.proto = "ssh"

    with patch("borg.legacy.remote.LegacyRemoteRepository") as mock_cls:
        get_repository(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None, v1_or_v2=True)

    mock_cls.assert_called_once_with(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None)


def test_get_repository_local_v1_uses_legacy_repository(tmp_path):
    """get_repository picks LegacyRepository for a local-style path when v1_or_v2=True."""
    from ...archiver._common import get_repository

    # proto="file" with v1_or_v2=True skips the borgstore elif (which requires not v1_or_v2)
    # and falls to the else branch where LegacyRepository is imported.
    location = MagicMock()
    location.proto = "file"
    location.path = str(tmp_path)

    with patch("borg.legacy.repository.LegacyRepository") as mock_cls:
        get_repository(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None, v1_or_v2=True)

    mock_cls.assert_called_once_with(str(tmp_path), create=False, exclusive=False, lock_wait=None, lock=True)
