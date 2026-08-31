from unittest.mock import MagicMock, patch


def test_get_repository_ssh_v1_uses_legacy_remote():
    """get_repository picks LegacyRemoteRepository when proto=ssh and v1_legacy=True."""
    from ...archiver._common import get_repository

    location = MagicMock()
    location.proto = "ssh"

    with patch("borg.legacy.remote.LegacyRemoteRepository") as mock_cls:
        get_repository(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None, v1_legacy=True)

    mock_cls.assert_called_once_with(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None)


def test_get_repository_local_v1_uses_legacy_repository(tmp_path):
    """get_repository picks LegacyRepository for a local-style path when v1_legacy=True."""
    from ...archiver._common import get_repository

    # proto="file" with v1_legacy=True skips the borgstore elif (which requires not v1_legacy)
    # and falls to the else branch where LegacyRepository is imported.
    location = MagicMock()
    location.proto = "file"
    location.path = str(tmp_path)

    with patch("borg.legacy.repository.LegacyRepository") as mock_cls:
        get_repository(location, create=False, exclusive=False, lock_wait=None, lock=True, args=None, v1_legacy=True)

    mock_cls.assert_called_once_with(str(tmp_path), create=False, exclusive=False, lock_wait=None, lock=True)


def test_archive_match_patterns_combines_name_and_match_archives():
    """A NAME positional is just another pattern, ANDed with the -a / --match-archives ones."""
    from ...archiver._common import archive_match_patterns

    args = MagicMock()
    args.name = "home"
    args.match_archives = ["host:myhost"]
    assert archive_match_patterns(args) == ["home", "host:myhost"]


def test_archive_match_patterns_name_keeps_selector_prefix():
    """NAME is used as-is, so a prefixed NAME like aid:1234abcd keeps working."""
    from ...archiver._common import archive_match_patterns

    args = MagicMock()
    args.name = "aid:1234abcd"
    args.match_archives = None
    assert archive_match_patterns(args) == ["aid:1234abcd"]


def test_archive_match_patterns_without_name():
    from ...archiver._common import archive_match_patterns

    args = MagicMock()
    args.name = None
    args.match_archives = ["host:myhost"]
    assert archive_match_patterns(args) == ["host:myhost"]

    args.match_archives = None
    assert archive_match_patterns(args) == []


def test_archive_match_patterns_name_only():
    from ...archiver._common import archive_match_patterns

    args = MagicMock()
    args.name = "home"
    args.match_archives = None
    assert archive_match_patterns(args) == ["home"]
