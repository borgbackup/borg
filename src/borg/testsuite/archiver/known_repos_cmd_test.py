import json
import os
import shutil
import unicodedata
from pathlib import Path

import pytest

from ...helpers import get_cache_dir, get_security_dir
from . import cmd, create_regular_file, exec_cmd, generate_archiver_tests, RK_ENCRYPTION, PURE_PYTHON_MSGPACK_WARNING

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def cmd_without_repo(archiver, *args):
    """Like cmd(), but without the injected --repo option."""
    ret, output = exec_cmd(*args, archiver=archiver.archiver, fork=archiver.FORK_DEFAULT, exe=archiver.EXE)
    assert ret == 0, output
    # same as cmd(): drop the pure-python msgpack warning (e.g. on PyPy), it would break json.loads().
    return "".join(line for line in output.splitlines(keepends=True) if PURE_PYTHON_MSGPACK_WARNING not in line)


def _write_legacy_security(repo_id, location, key_type="3"):
    """Create a borg-1.x-style $BORG_CONFIG_DIR/security/<repo_id>/ entry with the given
    location and key-type (default "3" == KeyType.REPO, legacy AES-CTR repokey).
    """
    from borg.legacy.fs import get_config_dir as get_config_dir_legacy

    security_dir = os.path.join(get_config_dir_legacy(create=False), "security", repo_id)
    os.makedirs(security_dir, exist_ok=True)
    with open(os.path.join(security_dir, "location"), "w") as fd:
        fd.write(location)
    with open(os.path.join(security_dir, "key-type"), "w") as fd:
        fd.write(key_type)


def _write_legacy_cache(repo_id, previous_location=None):
    """Create a legacy-layout ($BORG_CACHE_DIR/<repo_id>/chunks marker) cache entry, optionally
    with a [cache] previous_location in its config.
    """
    cache_path = os.path.join(get_cache_dir(create=False), repo_id)
    os.makedirs(cache_path, exist_ok=True)
    with open(os.path.join(cache_path, "chunks"), "w") as fd:
        fd.write("legacy chunks index placeholder")
    if previous_location is not None:
        with open(os.path.join(cache_path, "config"), "w") as fd:
            fd.write(f"[cache]\nprevious_location = {previous_location}\n")


def test_known_repos_empty(archivers, request):
    archiver = request.getfixturevalue(archivers)
    result = cmd(archiver, "known-repos")
    assert "No locally known repositories." in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    assert result_json == {"repositories": []}


def test_known_repos_without_repo_argument(archivers, request):
    """The actual argv operators type - no -r/--repo at all - must work, not just cmd()'s injected one."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    output = cmd_without_repo(archiver, "known-repos", "--json")
    ids = {repo["id"] for repo in json.loads(output)["repositories"]}
    assert ids == {repo_id}


def test_known_repos_lists_repo_with_cache(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    info = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]
    repo_id = info["id"]

    result = cmd(archiver, "known-repos")
    assert repo_id in result.split()
    assert "borg2" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos = result_json["repositories"]
    assert len(repos) == 1
    repo = repos[0]
    assert repo["id"] == repo_id
    assert repo["layout"] == "borg2"
    assert repo["has_cache"] is True
    assert repo["cache_size"] > 0
    assert repo["key_type"] == "aes256-ocb, sha256"
    assert repo["has_security_info"] is True
    assert repo["cache_config_mtime"] is not None
    assert repo["location"] == info["location"]
    assert repo["key_file_count"] == 0  # repokey mode (the default) has no key file on disk

    # the table's "Last written" column shows the same cache_config_mtime, at/after its header
    lines = result.splitlines()
    header, row = lines[0], lines[1]
    written_col = header.index("Last written")
    assert repo["cache_config_mtime"][:10] in row[written_col:]  # mtime's date part (YYYY-MM-DD)


def test_known_repos_cache_without_security_info(archivers, request):
    """A cache dir with no matching security dir entry is still listed, with has_security_info False."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_path = get_security_dir(repo_id, create=False)
    assert security_path.startswith(os.environ["BORG_BASE_DIR"] + os.sep)
    shutil.rmtree(security_path, ignore_errors=True)

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["layout"] == "borg2"  # discovered via the borg2 cache root even with no security info
    assert repo["has_cache"] is True
    assert repo["has_security_info"] is False
    assert repo["key_type"] is None
    assert repo["location"] is None


def test_known_repos_scans_legacy_v1_security_dir(archivers, request):
    """A v1-style security entry (legacy $BORG_CONFIG_DIR/security layout) is listed too, with
    no cache: the table's "Last written" column shows "-", not a blank or error.
    """
    archiver = request.getfixturevalue(archivers)
    legacy_repo_id = "a" * 64  # any syntactically valid 64-hex id; this test never opens a repo
    _write_legacy_security(legacy_repo_id, "/some/v1/repo/path")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    legacy_repo = repos_by_id[legacy_repo_id]
    assert legacy_repo["layout"] == "legacy"
    assert legacy_repo["location"] == "/some/v1/repo/path"
    assert legacy_repo["key_type"] == "aes256-ctr, sha256 (legacy)"
    assert legacy_repo["has_cache"] is False
    assert legacy_repo["cache_config_mtime"] is None

    table_result = cmd(archiver, "known-repos")
    header, row = table_result.splitlines()[0], table_result.splitlines()[1]
    written_col = header.index("Last written")
    location_col = header.index("Location")
    assert row[written_col:location_col].strip() == "-"


def test_known_repos_unknown_key_type_is_labeled(archivers, request):
    """A key-type byte that does not match any known key class is shown as 'unknown key type N'."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    key_type_path = os.path.join(get_security_dir(repo_id, create=False), "key-type")
    with open(key_type_path, "w") as fd:
        fd.write("144")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["key_type"] == "unknown key type 144"


def test_known_repos_ignores_storecache_and_non_repo_dirs(archivers, request):
    """A non-hex-id cache subdir (e.g. storecache), a stray security subdir, and a repo-id-
    shaped name with a trailing newline (which must not match the repo-id pattern) are all
    ignored.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_root = get_cache_dir(create=False)
    storecache_dir = f"{cache_root}/storecache"
    os.makedirs(f"{storecache_dir}/subdir", exist_ok=True)
    with open(f"{storecache_dir}/config", "w") as fd:
        fd.write("not a repo cache config")

    security_root = get_security_dir(create=False)
    stray_dir = f"{security_root}/not-a-repo-id"
    os.makedirs(stray_dir, exist_ok=True)
    with open(f"{stray_dir}/location", "w") as fd:
        fd.write("should not be listed")

    if os.name != "nt":  # Windows rejects a newline in a filename at creation time
        bad_name = "a" * 64 + "\n"
        bad_dir = os.path.join(security_root, bad_name)
        os.makedirs(bad_dir, exist_ok=True)
        with open(os.path.join(bad_dir, "location"), "w") as fd:
            fd.write("/should/not/be/listed")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    ids = {repo["id"] for repo in result_json["repositories"]}
    assert ids == {repo_id}


def test_known_repos_multiple_sorted_by_id(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id1 = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    second_repo = str(archiver.repository_path) + "-second"
    cmd_without_repo(archiver, f"--repo={second_repo}", "repo-create", RK_ENCRYPTION)
    info2 = json.loads(cmd_without_repo(archiver, f"--repo={second_repo}", "repo-info", "--json"))["repository"]
    repo_id2 = info2["id"]

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    assert set(repos_by_id) == {repo_id1, repo_id2}
    assert repos_by_id[repo_id2]["location"] == info2["location"]
    assert [repo["id"] for repo in result_json["repositories"]] == sorted([repo_id1, repo_id2])


def test_known_repos_does_not_write_cachedir_tag(archivers, request):
    """Running known-repos on an otherwise-empty cache dir must not plant CACHEDIR.TAG there."""
    archiver = request.getfixturevalue(archivers)
    cache_root = get_cache_dir(create=False)
    cachedir_tag = os.path.join(cache_root, "CACHEDIR.TAG")
    assert not os.path.exists(cachedir_tag)

    result = cmd(archiver, "known-repos")
    assert "No locally known repositories." in result
    assert not os.path.exists(cachedir_tag)


@pytest.mark.parametrize(
    "setup", ["unreadable_security_entry", "security_root_not_a_directory", "unparseable_cache_config"]
)
def test_known_repos_warns_and_exits_nonzero_on_inspection_failure(archivers, request, monkeypatch, setup):
    """Any filesystem inspection failure - an EACCES on a repo-id directory, a configured root
    that is actually a plain file, or a cache config ConfigParser cannot parse - takes the
    same path: it is skipped/treated as absent-looking, but the command still warns and exits
    nonzero, rather than crashing or silently looking fully successful.
    """
    archiver = request.getfixturevalue(archivers)

    if setup == "unreadable_security_entry":
        if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0:
            pytest.skip("chmod-based permission test, not meaningful on Windows or as root")
        security_root = get_security_dir(create=False)
        repo_id = "d" * 64
        security_path = os.path.join(security_root, repo_id)
        os.makedirs(security_path, exist_ok=True)
        with open(os.path.join(security_path, "location"), "w") as fd:
            fd.write("/should/not/be/readable")
        os.chmod(security_path, 0o000)
        try:
            result = cmd(archiver, "known-repos", exit_code=1)
            assert "could not be completed" in result
        finally:
            os.chmod(security_path, 0o755)
        return

    if setup == "security_root_not_a_directory":
        not_a_dir = str(Path(str(get_cache_dir(create=False))).parent / "not-a-directory")
        with open(not_a_dir, "w") as fd:
            fd.write("this is a file, not the security directory")
        monkeypatch.setenv("BORG_SECURITY_DIR", not_a_dir)
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be completed" in result
        return

    # setup == "unparseable_cache_config"
    repo_id = "f" * 64
    cache_path = os.path.join(get_cache_dir(create=False), repo_id)
    os.makedirs(cache_path, exist_ok=True)
    with open(os.path.join(cache_path, "chunks"), "w") as fd:
        fd.write("legacy chunks index placeholder")
    with open(os.path.join(cache_path, "config"), "w") as fd:
        fd.write("not a valid ini file [[[\n")
    result = cmd(archiver, "known-repos", exit_code=1)
    assert "could not be completed" in result


def test_known_repos_legacy_cache_previous_location_fallback(archivers, request):
    """A legacy-only cache config's [cache] previous_location is used as location when there is
    no security info for that id at all. The location contains a literal '%' (a valid path
    character) to also verify it is returned verbatim, not raised on - ConfigParser's default
    string interpolation treats '%' specially.
    """
    archiver = request.getfixturevalue(archivers)
    repo_id = "b" * 64
    _write_legacy_cache(repo_id, previous_location="/legacy/100%repo/path")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    repo = repos_by_id[repo_id]
    assert repo["layout"] == "legacy"
    assert repo["location"] == "/legacy/100%repo/path"
    assert repo["has_security_info"] is False


def test_known_repos_discovers_legacy_cache_and_keys_in_separate_roots(archiver, monkeypatch, tmp_path):
    """A legacy-only cache and key file are still discovered when their roots differ from
    the borg2 ones (the macOS default). local-only: the binary archiver subprocess can't see
    this monkeypatch.
    """
    import borg.archiver.known_repos_cmd as known_repos_cmd

    separate_cache_root = tmp_path / "legacy-cache-root"
    separate_keys_root = tmp_path / "legacy-keys-root"
    monkeypatch.setattr(known_repos_cmd, "get_cache_dir_legacy", lambda create: str(separate_cache_root))
    monkeypatch.setattr(known_repos_cmd, "get_keys_dir_legacy", lambda create: str(separate_keys_root))

    cache_repo_id = "b" * 64
    cache_path = separate_cache_root / cache_repo_id
    cache_path.mkdir(parents=True)
    (cache_path / "chunks").write_text("legacy chunks index placeholder")
    (cache_path / "config").write_text("[cache]\nprevious_location = /legacy/v1/repo/path\n")

    key_repo_id = "f" * 64
    separate_keys_root.mkdir(parents=True)
    (separate_keys_root / "keyfile.key").write_text(f"BORG_KEY {key_repo_id}\nrest of the key file\n")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}

    cache_repo = repos_by_id[cache_repo_id]
    assert cache_repo["layout"] == "legacy"
    assert cache_repo["location"] == "/legacy/v1/repo/path"
    assert cache_repo["has_security_info"] is False

    key_repo = repos_by_id[key_repo_id]
    assert key_repo["key_file_count"] == 1
    assert key_repo["has_cache"] is False


@pytest.mark.parametrize(
    "legacy_marker",
    [
        "chunks",  # legacy marker as a plain file
        "chunks.archive.d",  # legacy marker as a directory (checked first by _cache_layout())
    ],
)
def test_known_repos_layout_undetermined_when_security_roots_coincide(archivers, request, monkeypatch, legacy_marker):
    """When $BORG_SECURITY_DIR makes the current and legacy security roots the same path, a
    security entry alone cannot tell borg1 and borg2 apart (same "location"/"key-type"
    filenames either way) - the cache content (chunks/chunks.archive.d) must decide the layout,
    for either form the legacy marker can take.
    """
    archiver = request.getfixturevalue(archivers)
    security_root = get_security_dir(create=False)
    monkeypatch.setenv("BORG_SECURITY_DIR", security_root)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_root = get_cache_dir(create=False)
    cache_path = os.path.join(cache_root, repo_id)
    marker_path = os.path.join(cache_path, legacy_marker)
    if legacy_marker.endswith(".d"):
        os.makedirs(marker_path, exist_ok=True)
    else:
        with open(marker_path, "w") as fd:
            fd.write("legacy chunks index placeholder")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["layout"] == "legacy"


def test_known_repos_table_columns_align_with_long_security_label(archivers, request):
    """A Security label longer than the old fixed column width (e.g. an "authenticated-*" key
    type with the "(legacy)" suffix) must not shift the Location column - the column widths
    are computed from the actual data, not hardcoded.
    """
    archiver = request.getfixturevalue(archivers)
    security_root = get_security_dir(create=False)
    repo_id = "c" * 64
    security_path = os.path.join(security_root, repo_id)
    os.makedirs(security_path, exist_ok=True)
    with open(os.path.join(security_path, "location"), "w") as fd:
        fd.write("/some/repo")
    with open(os.path.join(security_path, "key-type"), "w") as fd:
        fd.write("7")  # KeyType.AUTHENTICATED (legacy) -> "authenticated, sha256 (legacy)", 30 chars

    result = cmd(archiver, "known-repos")
    lines = result.splitlines()
    header, row = lines[0], lines[1]
    location_col = header.index("Location")
    assert row[location_col:].strip() == "/some/repo"


def test_known_repos_counts_keyfile_in_keys_dir(archivers, request):
    """A key file in the keys directory is found by its plaintext header (not its filename,
    which is a hash of the file's own content) and counted even after security info and the
    cache for that repo are both gone - see #10453's "auditing ... keys" use case and
    repo-delete, which deletes security info and cache but not the key file.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--key-location=keyfile")
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["id"] == repo_id
    assert repo["key_file_count"] == 1

    cmd(archiver, "repo-delete", "--force")
    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    repo = repos_by_id[repo_id]
    assert repo["key_file_count"] == 1
    assert repo["has_security_info"] is False
    assert repo["has_cache"] is False


def test_known_repos_ignores_non_key_files_in_keys_dir(archivers, request):
    """A file in the keys directory without the BORG_KEY header is not mistaken for a key."""
    from borg.helpers import get_keys_dir

    archiver = request.getfixturevalue(archivers)
    keys_dir = get_keys_dir(create=True)
    create_regular_file(Path(keys_dir), "not_a_key_file", contents=b"just some unrelated file\n")

    result = cmd(archiver, "known-repos")
    assert "No locally known repositories." in result


def test_known_repos_flags_location_mismatch_between_security_and_cache(archivers, request):
    """A legacy repo whose security info has a location that differs from the cache config's
    previous_location is flagged (location_mismatch) rather than silently preferring one over
    the other - following the Bash workaround in #10453, which treated this as an error. A
    cache previous_location that agrees with the security location is not flagged.
    """
    archiver = request.getfixturevalue(archivers)
    mismatched_id = "c" * 64
    _write_legacy_security(mismatched_id, "/correct/path")
    _write_legacy_cache(mismatched_id, previous_location="/stale/different/path")

    agreeing_id = "d" * 64
    _write_legacy_security(agreeing_id, "/same/path")
    _write_legacy_cache(agreeing_id, previous_location="/same/path")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    assert repos_by_id[mismatched_id]["location"] == "/correct/path"
    assert repos_by_id[mismatched_id]["location_mismatch"] is True
    assert repos_by_id[agreeing_id]["location_mismatch"] is False

    table_result = cmd(archiver, "known-repos")
    assert "(!= cache's last location)" in table_result


def test_known_repos_location_mismatch_ignores_nfc_nfd_difference(archivers, request):
    """Same path, different unicode normalization (NFC vs. NFD, see #2913) in the security
    location and cache previous_location: not a mismatch on macOS (normalize_local_path()
    normalizes both), but is one elsewhere (it's a no-op there).
    """
    from borg.platformflags import is_darwin, is_win32

    if is_win32:
        pytest.skip("NFD path is not encodable in the Windows locale encoding")

    archiver = request.getfixturevalue(archivers)
    nfc_path = unicodedata.normalize("NFC", "/absolute/tëst")
    nfd_path = unicodedata.normalize("NFD", "/absolute/tëst")
    assert nfc_path != nfd_path  # sanity: the two forms really differ byte-wise

    repo_id = "e" * 64
    _write_legacy_security(repo_id, nfc_path)
    _write_legacy_cache(repo_id, previous_location=nfd_path)

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = next(r for r in result_json["repositories"] if r["id"] == repo_id)
    assert repo["location_mismatch"] is (not is_darwin)
