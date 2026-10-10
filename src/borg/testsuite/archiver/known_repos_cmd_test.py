import json
import os
import shutil

try:
    import resource
except ImportError:  # Windows has no resource module
    resource = None

import pytest

from ...constants import *  # NOQA
from ...helpers import get_cache_dir, get_security_dir, format_file_size
from .. import are_symlinks_supported
from . import cmd, create_regular_file, exec_cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA

requires_symlinks = pytest.mark.skipif(not are_symlinks_supported(), reason="symlinks not supported")
# evaluate geteuid only on POSIX: the name does not exist on Windows, and putting
# os.geteuid() in a skipif condition would raise at collection time there.
requires_chmod_permissions = pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="chmod-based permission test, not meaningful on Windows or as root",
)


def test_known_repos_empty(archivers, request):
    archiver = request.getfixturevalue(archivers)
    result = cmd(archiver, "known-repos")
    assert "No locally known repositories." in result


def test_known_repos_without_repo_argument(archivers, request):
    """The actual argv operators type - no -r/--repo at all - must work, not just cmd()'s injected one."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    ret, output = exec_cmd(
        "known-repos", "--json", archiver=archiver.archiver, fork=archiver.FORK_DEFAULT, exe=archiver.EXE
    )
    assert ret == 0, output
    ids = {repo["id"] for repo in json.loads(output)["repositories"]}
    assert ids == {repo_id}


def test_known_repos_empty_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    result = json.loads(cmd(archiver, "known-repos", "--json"))
    assert result == {"repositories": []}


def test_known_repos_lists_repo_with_cache(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    info = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]
    repo_id = info["id"]

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Layout: borg2" in result
    assert "Local cache: yes" in result
    assert "Cache last written:" in result
    assert "Security info: yes (aes256-ocb, sha256)" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos = result_json["repositories"]
    assert len(repos) == 1
    repo = repos[0]
    assert repo["id"] == repo_id
    assert repo["layout"] == "borg2"
    assert repo["has_cache"] is True
    assert repo["cache_size"] > 0
    assert repo["key_type"] == "aes256-ocb, sha256"
    assert repo["key_type_raw"] is not None
    assert repo["has_security_info"] is True
    assert repo["cache_config_mtime"] is not None
    assert repo["location"] == info["location"]


def test_known_repos_without_cache(archivers, request):
    """A repo whose local cache was deleted (but security info remains) is still reported, without a cache."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_path = get_cache_dir(repo_id, create=False)
    # sanity check: only remove a cache dir that is really below this test's isolated BORG_CACHE_DIR
    # (the archiver fixture points BORG_CACHE_DIR at archiver.cache_path, a per-test tmp dir), so a
    # misconfigured test environment can not delete a real, unrelated local cache.
    assert cache_path.startswith(str(archiver.cache_path) + os.sep)
    shutil.rmtree(cache_path, ignore_errors=True)

    result = cmd(archiver, "known-repos")
    assert "Local cache: no" in result
    assert "Note: a local cache exists" not in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos = result_json["repositories"]
    assert len(repos) == 1
    repo = repos[0]
    assert repo["id"] == repo_id
    assert repo["has_cache"] is False
    assert repo["cache_size"] is None
    assert repo["cache_config_mtime"] is None
    # security info (key type, location) must still be reported even without a cache
    assert repo["key_type"] == "aes256-ocb, sha256"
    assert repo["has_security_info"] is True
    assert repo["location"]


def test_known_repos_cache_without_security_info(archivers, request):
    """A cache dir with no matching security dir entry is still listed, with the "no security info" note."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_path = get_security_dir(repo_id, create=False)
    assert security_path.startswith(os.environ["BORG_BASE_DIR"] + os.sep)  # same isolation sanity check as above
    shutil.rmtree(security_path, ignore_errors=True)

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Layout: borg2" in result  # discovered via the borg2 cache root even with no security info
    assert "Local cache: yes" in result
    assert "Security info: no" in result
    assert "Note: a local cache exists, but no security info was found" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["layout"] == "borg2"
    assert repo["has_cache"] is True
    assert repo["has_security_info"] is False
    assert repo["key_type"] is None
    assert repo["location"] is None


def test_known_repos_location_only_counts_as_security_info(archivers, request):
    """A security dir with only a 'location' file (no readable key-type) still counts as having info."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_path = get_security_dir(repo_id, create=False)
    assert security_path.startswith(os.environ["BORG_BASE_DIR"] + os.sep)
    os.remove(os.path.join(security_path, "key-type"))

    result = cmd(archiver, "known-repos")
    assert "Security info: yes (key type unknown)" in result
    assert "Note: a local cache exists" not in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["has_security_info"] is True
    assert repo["key_type"] is None
    assert repo["key_type_raw"] is None
    assert repo["location"]


def test_known_repos_ignores_storecache_and_non_repo_dirs(archivers, request):
    """A non-hex-id cache subdir (e.g. storecache) and a stray security subdir are not listed."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_root = get_cache_dir(create=False)
    # BORG_STORE_CACHE's storecache dir has no "config" file of its own, but even one placed there
    # deliberately must not make it count, since it is not a 64-hex-digit directory name.
    storecache_dir = f"{cache_root}/storecache"
    os.makedirs(f"{storecache_dir}/subdir", exist_ok=True)
    with open(f"{storecache_dir}/config", "w") as fd:
        fd.write("not a repo cache config")

    security_root = get_security_dir(create=False)
    stray_dir = f"{security_root}/not-a-repo-id"
    os.makedirs(stray_dir, exist_ok=True)
    with open(f"{stray_dir}/location", "w") as fd:
        fd.write("should not be listed")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    ids = {repo["id"] for repo in result_json["repositories"]}
    assert ids == {repo_id}


def test_known_repos_multiple_sorted_by_id(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id1 = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    # a second, independent repository in a different location
    second_repo = str(archiver.repository_path) + "-second"
    ret, output = exec_cmd(
        f"--repo={second_repo}",
        "repo-create",
        RK_ENCRYPTION,
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )
    assert ret == 0, output
    ret, output = exec_cmd(
        f"--repo={second_repo}",
        "repo-info",
        "--json",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )
    assert ret == 0, output
    info2 = json.loads(output)["repository"]
    repo_id2 = info2["id"]

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    assert set(repos_by_id) == {repo_id1, repo_id2}
    assert repos_by_id[repo_id2]["location"] == info2["location"]
    # sorted by repository id
    assert [repo["id"] for repo in result_json["repositories"]] == sorted([repo_id1, repo_id2])


def test_known_repos_scans_legacy_v1_security_dir(archivers, request):
    """A v1-style security entry (legacy $BORG_CONFIG_DIR/security layout) is listed too."""
    archiver = request.getfixturevalue(archivers)
    # the archiver fixture isolates BORG_BASE_DIR to a per-test tmp dir, so BORG_CONFIG_DIR
    # (unset here) resolves below it via legacy.fs.get_config_dir() - safe to plant a fake entry in.
    from borg.legacy.fs import get_config_dir as get_config_dir_legacy

    legacy_repo_id = "a" * 64  # any syntactically valid 64-hex id; this test never opens a repo
    legacy_security_dir = os.path.join(get_config_dir_legacy(create=False), "security", legacy_repo_id)
    os.makedirs(legacy_security_dir, exist_ok=True)
    with open(os.path.join(legacy_security_dir, "location"), "w") as fd:
        fd.write("/some/v1/repo/path")
    with open(os.path.join(legacy_security_dir, "key-type"), "w") as fd:
        fd.write("3")  # KeyType.REPO (borg 1.x repokey, legacy AES-CTR)

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {legacy_repo_id}" in result
    assert "Layout: legacy" in result
    assert "Local cache: no" in result
    assert "Security info: yes (aes256-ctr, sha256 (legacy))" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repos_by_id = {repo["id"]: repo for repo in result_json["repositories"]}
    legacy_repo = repos_by_id[legacy_repo_id]
    assert legacy_repo["layout"] == "legacy"
    assert legacy_repo["location"] == "/some/v1/repo/path"
    assert legacy_repo["key_type"] == "aes256-ctr, sha256 (legacy)"
    assert legacy_repo["has_cache"] is False


def test_known_repos_does_not_write_cachedir_tag(archivers, request):
    """Running known-repos on an otherwise-empty cache dir must not plant CACHEDIR.TAG there.

    get_cache_dir(create=True) (the default) writes a CACHEDIR.TAG marker file as a side effect;
    known-repos uses create=False specifically to avoid that, since it is meant to be read-only.
    """
    archiver = request.getfixturevalue(archivers)
    cache_root = get_cache_dir(create=False)
    cachedir_tag = os.path.join(cache_root, "CACHEDIR.TAG")
    assert not os.path.exists(cachedir_tag)  # the archiver fixture's cache dir starts empty

    result = cmd(archiver, "known-repos")
    assert "No locally known repositories." in result
    assert not os.path.exists(cachedir_tag)


@requires_symlinks
def test_known_repos_does_not_follow_symlinked_cache_entry(archivers, request):
    """A cache_root/<repo_id> entry that is a symlink (not a real directory) must be skipped, not followed.

    Borg itself always creates a plain directory there; a symlink can only come from something else
    (deliberate relocation, or an attempt to redirect the read elsewhere) and must not be treated as
    a cache.
    """
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_root = get_cache_dir(create=False)
    assert cache_root.startswith(str(archiver.cache_path) + os.sep) or cache_root == str(archiver.cache_path)
    real_cache_dir = os.path.join(cache_root, repo_id)
    moved_cache_dir = real_cache_dir + "-moved"
    os.rename(real_cache_dir, moved_cache_dir)
    os.symlink(moved_cache_dir, real_cache_dir)

    result = cmd(archiver, "known-repos")
    assert "Local cache: no" in result
    assert "Security info: yes (aes256-ocb, sha256)" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["has_cache"] is False
    assert repo["cache_size"] is None


@requires_symlinks
def test_known_repos_does_not_follow_symlinked_security_entry(archivers, request):
    """A security_root/<repo_id> entry that is a symlink must be skipped too, same reasoning as the cache one."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    # repo-create also creates a local cache; remove it first so this id has *only* security info,
    # all of it reachable only through the symlink this test is about to plant.
    cache_path = get_cache_dir(repo_id, create=False)
    assert cache_path.startswith(str(archiver.cache_path) + os.sep)
    shutil.rmtree(cache_path, ignore_errors=True)

    security_root = get_security_dir(create=False)
    real_security_dir = os.path.join(security_root, repo_id)
    moved_security_dir = real_security_dir + "-moved"
    os.rename(real_security_dir, moved_security_dir)
    os.symlink(moved_security_dir, real_security_dir)

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    ids = {repo["id"] for repo in result_json["repositories"]}
    # the id only had security info (via the now-symlinked dir, which must be ignored) and no real
    # cache directory, so it must not be reported as a known repository at all.
    assert repo_id not in ids


@requires_symlinks
def test_known_repos_cache_only_discovery_does_not_leak_symlinked_security_dir(archivers, request):
    """A real cache dir plus a symlinked (attacker-controlled-content) security dir for the same id

    must not have that security content read and reported: the id is discovered via its real cache,
    but the security_root/<id> path is a symlink that scan_security_root would reject on its own -
    discovering the id through the cache must not grant an implicit pass to read it anyway.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_root = get_security_dir(create=False)
    real_security_dir = os.path.join(security_root, repo_id)
    fake_dir = os.path.join(security_root, "fake-target-for-" + repo_id)
    os.makedirs(fake_dir, exist_ok=True)
    with open(os.path.join(fake_dir, "location"), "w") as fd:
        fd.write("/not/the/real/location")
    shutil.rmtree(real_security_dir, ignore_errors=True)
    os.symlink(fake_dir, real_security_dir)

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Local cache: yes" in result
    assert "/not/the/real/location" not in result
    assert "Security info: no" in result
    assert "Note: a local cache exists, but no security info was found" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = next(r for r in result_json["repositories"] if r["id"] == repo_id)
    assert repo["location"] is None
    assert repo["has_security_info"] is False


@requires_symlinks
def test_known_repos_does_not_follow_symlinked_location_file(archivers, request):
    """A location file that is itself a symlink (inside an otherwise real, non-symlinked security dir)

    must not be followed either - rejecting a symlinked repo-id *directory* is not enough if a
    symlinked *file* inside a real directory can still redirect the read.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_dir = os.path.join(get_security_dir(create=False), repo_id)
    fake_location_file = os.path.join(security_dir, "fake-location.txt")
    with open(fake_location_file, "w") as fd:
        fd.write("/attacker/leaf/path")
    real_location_file = os.path.join(security_dir, "location")
    os.remove(real_location_file)
    os.symlink(fake_location_file, real_location_file)

    result = cmd(archiver, "known-repos")
    assert "/attacker/leaf/path" not in result
    assert "Location: (unknown)" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["location"] is None


@pytest.mark.skipif(os.name == "nt", reason="Windows rejects a newline in a filename at creation time")
def test_known_repos_rejects_repo_id_with_trailing_newline(archivers, request):
    """A directory name of 64 hex digits followed by a newline must not match the repo-id pattern.

    re.match with a plain trailing '$' anchor also matches just before a final newline; a directory
    actually named "<64 hex>\\n" (an unusual but possible local name) must not be treated as a repo.
    """
    archiver = request.getfixturevalue(archivers)
    security_root = get_security_dir(create=False)
    bad_name = "a" * 64 + "\n"
    bad_dir = os.path.join(security_root, bad_name)
    os.makedirs(bad_dir, exist_ok=True)
    with open(os.path.join(bad_dir, "location"), "w") as fd:
        fd.write("/should/not/be/listed")

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    assert result_json["repositories"] == []


def test_known_repos_scans_legacy_cache_root_when_different_from_borg2s(request, monkeypatch):
    """A v1-only cache (in legacy.fs.get_cache_dir()'s root, not borg2's) must still be listed.

    On platforms where platformdirs (borg2) and the old home-grown layout (legacy.fs) resolve to
    different default cache roots (e.g. macOS: "~/Library/Caches/borg" vs "~/.cache/borg"), a v1
    repository's cache lives only in the legacy root. The test fixture sets BORG_BASE_DIR, which
    makes both roots resolve to the same place in practice - monkeypatch legacy.fs.get_cache_dir
    directly to simulate the platforms where they differ, without depending on the real platform
    this test happens to run on.

    Local only (not parametrized over archivers/binary_archiver): the monkeypatch only takes
    effect in this pytest process, so it would silently not apply if run against a forked
    borg.exe subprocess (binary_archiver) - there is no env var that makes legacy.fs and
    helpers.fs resolve to different cache roots to simulate this instead.
    """
    archiver = request.getfixturevalue("archiver")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    # move the real cache dir into a separate "legacy" root that differs from the borg2 cache root.
    borg2_cache_root = get_cache_dir(create=False)
    real_cache_dir = os.path.join(borg2_cache_root, repo_id)
    legacy_cache_root = os.path.join(os.path.dirname(borg2_cache_root), "legacy-cache-root")
    os.makedirs(legacy_cache_root, exist_ok=True)
    os.rename(real_cache_dir, os.path.join(legacy_cache_root, repo_id))

    import borg.archiver.known_repos_cmd as known_repos_cmd

    monkeypatch.setattr(known_repos_cmd, "get_cache_dir_legacy", lambda create=False: legacy_cache_root)

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Local cache: yes" in result

    result_json = json.loads(cmd(archiver, "known-repos", "--json"))
    repo = result_json["repositories"][0]
    assert repo["id"] == repo_id
    assert repo["has_cache"] is True
    assert repo["cache_size"] > 0


def test_known_repos_warns_and_exits_nonzero_on_oversized_key_type(archivers, request):
    """A key-type file too large to interpret must log a warning AND affect the exit code.

    logger.warning() alone does not do that - this command must additionally call
    self.print_warning() (see Archiver.print_warning / EXIT_WARNING) so that a script checking the
    exit status also learns that the audit was incomplete, not just a human reading stderr.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    key_type_path = os.path.join(get_security_dir(repo_id, create=False), "key-type")
    with open(key_type_path, "w") as fd:
        fd.write("x" * 5000)  # over the 4096 byte cap in known_repos_cmd._Inspector.read_subfile

    result = cmd(archiver, "known-repos", exit_code=1)
    assert "could not be fully completed" in result
    assert f"Repository ID: {repo_id}" in result
    assert "Security info: yes (key type unknown)" in result


def test_known_repos_warns_and_exits_nonzero_on_non_utf8_location(archivers, request):
    """A location file that is not valid UTF-8 must be treated like read_subfile returned None:

    warned, counted incomplete, and (since key-type is still readable) reported as
    "Security info: yes" without a location, not silently substituted or crashed on.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    location_path = os.path.join(get_security_dir(repo_id, create=False), "location")
    with open(location_path, "wb") as fd:
        fd.write(b"\xff\xfe\x00not valid utf-8")

    result = cmd(archiver, "known-repos", exit_code=1)
    assert "could not be fully completed" in result
    assert f"Repository ID: {repo_id}" in result
    assert "Location: (unknown)" in result
    assert "Security info: yes" in result


def test_known_repos_escapes_control_characters_in_location(archivers, request):
    """A location value containing control characters (e.g. from a crafted/corrupted file) must

    be escaped before printing, not written to the terminal raw - _printable() exists precisely
    to stop a stored location/key-type value from injecting terminal control sequences.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    location_path = os.path.join(get_security_dir(repo_id, create=False), "location")
    with open(location_path, "w") as fd:
        fd.write("/tmp/evil\x1b[31mred\x1b[0m")

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    # the raw ESC byte must not appear unescaped; _printable() renders it as a Python repr
    # escape (e.g. "\x1b") instead.
    assert "\x1b" not in result
    assert "\\x1b" in result


def test_known_repos_missing_key_type_file_is_not_a_warning(archivers, request):
    """A repo with no key-type file at all (location-only) must not trigger the incomplete-scan warning.

    This is the ordinary "not found" case (see test_known_repos_location_only_counts_as_security_info)
    - distinct from "found but could not be read", which does warn.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_path = get_security_dir(repo_id, create=False)
    os.remove(os.path.join(security_path, "key-type"))

    result = cmd(archiver, "known-repos")  # default exit_code=0 in cmd(); fails if exit code is nonzero
    assert "could not be fully completed" not in result
    assert f"Repository ID: {repo_id}" in result


@requires_chmod_permissions
def test_known_repos_unlistable_cache_subdir_reports_partial_size_not_missing(archivers, request):
    """A cache dir that exists, but has a subdirectory that can't be listed, is NOT reported as missing.

    Unlike an unreadable security file (treated the same as absent, see other tests in this file),
    an unlistable part of an otherwise-present cache directory still counts as "Local cache: yes" -
    just with an incomplete (here: smaller than the real) size, plus a warning and nonzero exit code.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_dir = get_cache_dir(repo_id, create=False)
    # baseline size of whatever repo-create left (config/README/...), before the unlistable subtree.
    baseline = 0
    for dirpath, dirnames, filenames in os.walk(cache_dir):
        for name in filenames:
            baseline += os.path.getsize(os.path.join(dirpath, name))

    unlistable_subdir = os.path.join(cache_dir, "unlistable")
    os.makedirs(unlistable_subdir, exist_ok=True)
    with open(os.path.join(unlistable_subdir, "somefile"), "w") as fd:
        fd.write("x" * 1000)
    os.chmod(unlistable_subdir, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        assert "Local cache: yes" in result  # not reported as missing, unlike the security-file case
        # the unlistable subdir's 1000 bytes are not counted - this is the partial-count behavior
        # the epilog describes, not the exact size a healthy scan would report.
        assert f"Local cache: yes, {format_file_size(baseline)}" in result
        assert "1.00 kB" not in result and "1000 B" not in result

        # --json is not checked here: in the in-process (non-fork) test harness, stdout and stderr
        # are the same stream (see exec_cmd()), so the warning line above would land inside what is
        # otherwise supposed to be pure JSON output. That collision is a test-harness property that
        # also exists for every other command with a --json mode, not something specific to this
        # command, and real (forked, non-test) usage keeps the warning on stderr and --json's output
        # on stdout separately.
    finally:
        os.chmod(unlistable_subdir, 0o755)


@requires_chmod_permissions
def test_known_repos_unreadable_borg2_cache_does_not_fall_back_to_legacy(request, monkeypatch):
    """An unlistable borg2 cache must be reported as 'no cache', and must not publish the legacy
    cache's size/mtime for the same id.

    open_cache_entry returns 'unreadable' when the directory is confirmed real but its config
    could not be inspected; the command then treats that as "no cache" rather than falling back
    to the other root, since the borg2 side's actual state was never established. Mode 0o400
    (readable, not searchable) is used rather than 0o000 so the repo-id directory itself still
    opens - only the later stat of its "config" child fails with EACCES, which is the branch
    this test targets (0o000 would instead fail at the directory open itself).
    """
    archiver = request.getfixturevalue("archiver")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    borg2_cache_root = get_cache_dir(create=False)
    real_cache_dir = os.path.join(borg2_cache_root, repo_id)
    legacy_cache_root = os.path.join(os.path.dirname(borg2_cache_root), "legacy-cache-root")
    os.makedirs(os.path.join(legacy_cache_root, repo_id), exist_ok=True)
    with open(os.path.join(legacy_cache_root, repo_id, "config"), "w") as fd:
        fd.write("not-the-borg2-cache")
    with open(os.path.join(legacy_cache_root, repo_id, "decoy"), "w") as fd:
        fd.write("x" * 5000)

    import borg.archiver.known_repos_cmd as known_repos_cmd

    monkeypatch.setattr(known_repos_cmd, "get_cache_dir_legacy", lambda create=False: legacy_cache_root)

    os.chmod(real_cache_dir, 0o400)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        # the borg2 cache's own state is unknown, so this must not claim "yes" (an unverified
        # existence claim) or "no" (an unverified absence claim), and must not silently report
        # the legacy root's cache either.
        assert "Local cache: unknown" in result
        # the 5000-byte decoy lives only in the legacy root; "Local cache: unknown" above
        # already proves the legacy cache was not substituted (it would have had to report a
        # size to do that), so no separate size assertion is needed. --json is not checked
        # here: in the in-process (non-fork) test harness, stdout and stderr are the same
        # stream, so the warning line above would land inside what is otherwise supposed to
        # be pure JSON output (same test-harness property noted elsewhere in this file).
    finally:
        os.chmod(real_cache_dir, 0o755)


@requires_chmod_permissions
def test_known_repos_unsearchable_cache_root_with_nonexistent_child_reports_no_cache(request, monkeypatch):
    """An unsearchable cache ROOT (not just one repo-id subdirectory within it) must not make a

    repo-id that never had a cache there look like it has one. When the root itself can't be
    opened, cache_root_d is None and kind comes from cache_root_kind ("unreadable") - this
    path never reaches open_cache_entry(), since there is no cache_root_d to call it with.
    That "unreadable" result must not be treated as has_cache=True, and must not fall back to
    a legacy cache either - the borg2 side's existence was never confirmed absent. This is
    distinct from the repo-id-directory-level unreadable-cache test above, which makes an
    existing repo-id directory (not its parent root) unreadable.
    """
    archiver = request.getfixturevalue("archiver")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    borg2_cache_root = get_cache_dir(create=False)
    # remove the normal cache dir for this id entirely - only the unsearchable empty root remains.
    shutil.rmtree(os.path.join(borg2_cache_root, repo_id), ignore_errors=True)

    legacy_cache_root = os.path.join(os.path.dirname(borg2_cache_root), "legacy-cache-root")
    os.makedirs(os.path.join(legacy_cache_root, repo_id), exist_ok=True)
    with open(os.path.join(legacy_cache_root, repo_id, "config"), "w") as fd:
        fd.write("not-the-borg2-cache")

    import borg.archiver.known_repos_cmd as known_repos_cmd

    monkeypatch.setattr(known_repos_cmd, "get_cache_dir_legacy", lambda create=False: legacy_cache_root)

    os.chmod(borg2_cache_root, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        # this repo-id was only discovered via the (unreadable) legacy cache root here - its id
        # comes from scan_cache_root() on the legacy root reporting it present, while the borg2
        # root's state for it could never be established (root itself unsearchable). The borg2
        # side being unknown must not fabricate "yes", and must not silently claim a confirmed
        # "no" either - it surfaces as unknown. --json is not checked (see the test-harness
        # note on the previous test in this file).
        assert "Local cache: unknown" in result
    finally:
        os.chmod(borg2_cache_root, 0o755)


@requires_chmod_permissions
def test_known_repos_unopenable_security_entry_is_not_dropped(archivers, request):
    """A repo-id directory under the security root that list_names() can see, but that this

    command cannot open (EACCES), must still appear in the result - with unknown fields - not
    silently disappear from the inventory just because its own inspection failed. Before the
    fix for this, scan_security_root()'s `if entry is None: continue` treated "confirmed absent
    (missing/symlink)" and "inspection failed (EACCES)" identically, so a name list_names() had
    already returned could vanish without a trace in the output - only the summary warning and
    exit code hinted anything was wrong, with no way to tell which repository was affected.
    """
    archiver = request.getfixturevalue(archivers)
    security_root = get_security_dir(create=False)
    repo_id = "d" * 64
    security_path = os.path.join(security_root, repo_id)
    os.makedirs(security_path, exist_ok=True)
    with open(os.path.join(security_path, "location"), "w") as fd:
        fd.write("/should/not/be/readable")
    os.chmod(security_path, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        # the repository must still be LISTED - not dropped - with its security/layout fields
        # reported as unknown rather than a false "no" or a false "yes". The cache root itself
        # was searched successfully and genuinely has no entry for this id, so "Local cache:
        # no" here is a real, confirmed answer, not a false negative - this test is only about
        # the security-side unreadable entry not causing the repo-id to disappear. --json is
        # not checked here (see the in-process stdout/stderr test-harness note elsewhere in
        # this file).
        assert f"Repository ID: {repo_id}" in result
        assert "Layout: unknown" in result
        assert "Security info: unknown" in result
        assert "Local cache: no" in result
    finally:
        os.chmod(security_path, 0o755)


@requires_chmod_permissions
def test_known_repos_unopenable_cache_entry_is_not_dropped(archivers, request):
    """Same as test_known_repos_unopenable_security_entry_is_not_dropped, but for a repo-id

    directory under the cache root that this command cannot open at all (not just whose
    "config" child can't be stat'd - see test_known_repos_unreadable_borg2_cache_does_not_fall_back_to_legacy
    for that case). scan_cache_root()'s discovery pass must not drop this name either.
    """
    archiver = request.getfixturevalue(archivers)
    cache_root = get_cache_dir(create=False)
    repo_id = "e" * 64
    cache_path = os.path.join(cache_root, repo_id)
    os.makedirs(cache_path, exist_ok=True)
    with open(os.path.join(cache_path, "config"), "w") as fd:
        fd.write("irrelevant")
    os.chmod(cache_path, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        assert f"Repository ID: {repo_id}" in result
        assert "Local cache: unknown" in result
        # --json is not checked here (see the in-process stdout/stderr test-harness note
        # elsewhere in this file).
    finally:
        os.chmod(cache_path, 0o755)


@requires_chmod_permissions
def test_known_repos_unopenable_cache_entry_with_security_confirmed_absent(archivers, request):
    """Same setup as test_known_repos_unopenable_cache_entry_is_not_dropped, but with both

    security roots present and empty (confirmed searched, not just absent by default):
    security info must be reported as confirmed absent ("no"), not "unknown". Before the
    fix for this, this id fell into do_known_repos()'s catch-all else branch (reached only
    via the unreadable-cache discovery path, not borg2_ids/legacy_ids/*_cache_ids), which
    unconditionally set has_security_info to None even though the security side had
    already been fully and successfully searched.
    """
    archiver = request.getfixturevalue(archivers)
    # touch both security roots so they exist and are searchable (still empty for this id).
    get_security_dir(create=True)
    from borg.legacy.fs import get_security_dir as get_security_dir_legacy

    get_security_dir_legacy(create=True)

    cache_root = get_cache_dir(create=False)
    repo_id = "f" * 64
    cache_path = os.path.join(cache_root, repo_id)
    os.makedirs(cache_path, exist_ok=True)
    with open(os.path.join(cache_path, "config"), "w") as fd:
        fd.write("irrelevant")
    os.chmod(cache_path, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert f"Repository ID: {repo_id}" in result
        assert "Security info: no" in result
        assert "Local cache: unknown" in result
    finally:
        os.chmod(cache_path, 0o755)


@requires_chmod_permissions
def test_known_repos_unsearchable_security_parent_warns(archivers, request):
    """A security root whose parent cannot be searched must warn, not look empty.

    Path.is_dir() on Python 3.14 returns False for this case without raising. A naive
    "if not is_dir(): treat as absent" check would therefore exit 0 on an unreadable parent.
    The actual code opens the root via os_open() (not Path.is_dir()), which raises EACCES here
    and is counted as incomplete via _warn().
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]
    security_root = get_security_dir(create=False)
    parent = os.path.dirname(security_root)
    # only chmod a parent that is inside this test's isolated BORG_BASE_DIR
    assert parent.startswith(os.environ["BORG_BASE_DIR"] + os.sep)
    os.chmod(parent, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        # the repo-create above also left a local cache, so this id is still discovered (via
        # the cache root, which is unaffected by chmod'ing the security root's parent) - but
        # with the ENTIRE security root unsearchable, "no security entry for this id" can
        # never be confirmed; it must surface as unknown, not a false "no".
        assert f"Repository ID: {repo_id}" in result
        assert "Security info: unknown" in result
    finally:
        os.chmod(parent, 0o755)


@requires_chmod_permissions
def test_known_repos_unreadable_legacy_cache_root_with_confirmed_absent_borg2_cache(request, monkeypatch):
    """When the current (borg2) cache is confirmed absent for an id, but the legacy cache

    ROOT ITSELF cannot even be opened (not just a specific entry within it - see
    test_known_repos_unreadable_borg2_cache_does_not_fall_back_to_legacy for that case), this
    command must not claim "no cache": the legacy side was never actually searched, so the
    true answer is unknown. Before the fix for this, the "absent" fallback condition only
    checked `legacy_cache_root_d is not None`, which is also true/false independent of whether
    the legacy root could be *opened* - if it couldn't be opened, kind simply stayed "absent"
    from the already-confirmed-absent borg2 side, silently skipping the (failed) legacy check
    instead of surfacing that failure.
    """
    archiver = request.getfixturevalue("archiver")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    # this id has security info (from repo-create) but no borg2 cache entry - delete it so the
    # borg2 cache side is confirmed absent, forcing the legacy-cache fallback path.
    borg2_cache_root = get_cache_dir(create=False)
    shutil.rmtree(os.path.join(borg2_cache_root, repo_id), ignore_errors=True)

    legacy_cache_root = os.path.join(os.path.dirname(borg2_cache_root), "legacy-cache-root")
    os.makedirs(legacy_cache_root, exist_ok=True)

    import borg.archiver.known_repos_cmd as known_repos_cmd

    monkeypatch.setattr(known_repos_cmd, "get_cache_dir_legacy", lambda create=False: legacy_cache_root)

    os.chmod(legacy_cache_root, 0o000)
    try:
        result = cmd(archiver, "known-repos", exit_code=1)
        assert "could not be fully completed" in result
        assert f"Repository ID: {repo_id}" in result
        # borg2 cache: confirmed absent. legacy cache ROOT: could not even be opened - the
        # legacy side was never searched, so the combined answer must be unknown, not "no".
        assert "Local cache: unknown" in result
    finally:
        os.chmod(legacy_cache_root, 0o755)


def test_known_repos_security_root_listing_failure_does_not_confirm_cache_only_id_absent(request, monkeypatch):
    """A security root that opens fine but fails to LIST (e.g. EIO) must not let a

    cache-only id be reported as having confirmed-absent security info - scan_security_root()
    cannot have seen every entry under a root it failed to list, so "this id has no security
    entry" is not something it can actually assert, even though no individual repo-id
    directory's open failed. Before the fix for this, only root-OPEN failure and per-id EACCES
    were tracked (security_root_kind / security_unreadable_ids) - a root that opened
    successfully and then failed during list_names() itself fell through neither check, so
    security_fully_searched stayed True and a cache-only id got a false "no".
    """
    archiver = request.getfixturevalue("archiver")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    # this id has a cache (from repo-create) but no security entry for it specifically is
    # required - delete the security entry so this id is discovered ONLY via the cache root,
    # exercising the borg2_cache_ids branch in do_known_repos().
    security_path = get_security_dir(repo_id, create=False)
    shutil.rmtree(security_path, ignore_errors=True)

    import borg.archiver.known_repos_cmd as known_repos_cmd

    orig_list_names = known_repos_cmd._Inspector.list_names
    security_root = get_security_dir(create=False)

    def failing_list_names(self, d, display):
        # simulate a successful open followed by a listing failure (e.g. EIO) specifically for
        # the (already-opened) security root, leaving every other list_names() call (cache
        # root, individual repo-id directories) unaffected.
        if display == security_root:
            raise OSError(5, "Input/output error")  # EIO, caught the same way a real one is
        return orig_list_names(self, d, display)

    def patched_list_names(self, d, display):
        try:
            return failing_list_names(self, d, display)
        except OSError as exc:
            self._warn("known-repos: could not list %s, results may be incomplete: %s", display, exc)
            return []

    monkeypatch.setattr(known_repos_cmd._Inspector, "list_names", patched_list_names)

    result = cmd(archiver, "known-repos", exit_code=1)
    assert "could not be fully completed" in result
    assert f"Repository ID: {repo_id}" in result
    # the security root's own listing failed - "no security entry for this id" was never
    # actually confirmed, so this must be unknown, not a false "no".
    assert "Security info: unknown" in result
    # the cache side was unaffected by this failure and should still be confirmed present.
    assert "Local cache: yes" in result


@pytest.mark.skipif(os.name == "nt", reason="FIFOs via os.mkfifo are not available on Windows")
def test_known_repos_rejects_fifo_location_without_hanging(archivers, request):
    """A stationary FIFO named 'location' (no writer) must be rejected quickly, not hang.

    Opening a FIFO read-only blocks until a writer connects; read_subfile must use O_NONBLOCK
    on the dir_fd-relative open so this command never stalls on one.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    security_path = get_security_dir(repo_id, create=False)
    location_path = os.path.join(security_path, "location")
    os.remove(location_path)
    os.mkfifo(location_path)

    # cmd() runs in-process (no fork) for the "archiver" param, so a regression of O_NONBLOCK
    # here would hang this test rather than fail it cleanly.
    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Location: (unknown)" in result


def test_known_repos_security_only_repo_with_oversized_location_is_still_listed(archivers, request):
    """A repo whose ONLY local state is an oversized (unreadable) location file must still be

    listed with has_security_info True (the file's presence IS confirmed via stat, independent
    of whether its content could be decoded) - not disappear, and not be downgraded to "no"
    just because the content itself could not be read.
    """
    archiver = request.getfixturevalue(archivers)
    security_root = get_security_dir(create=False)
    repo_id = "c" * 64
    security_path = os.path.join(security_root, repo_id)
    os.makedirs(security_path, exist_ok=True)
    with open(os.path.join(security_path, "location"), "w") as fd:
        fd.write("x" * 5000)  # over the 4096 byte cap

    result = cmd(archiver, "known-repos", exit_code=1)
    assert "could not be fully completed" in result
    assert f"Repository ID: {repo_id}" in result
    assert "Location: (unknown)" in result
    # the oversized location file is this repo's ONLY security state; it was confirmed PRESENT
    # via stat (independent of the content read that then failed), so this is "Security info:
    # yes" with an unknown key type, not "no" - "no" would be a false claim of absence for a
    # file this command already knows exists.
    assert "Security info: yes (key type unknown)" in result

    # --json is not checked here: in the in-process (non-fork) test harness, stdout and stderr
    # are the same stream, so the warning line above would land inside what is otherwise
    # supposed to be pure JSON output (same test-harness property noted elsewhere in this file).


def test_known_repos_deep_cache_tree_does_not_hit_recursion_limit(archivers, request):
    """dir_size must use an explicit stack, not Python recursion, so a cache directory deeper

    than sys.getrecursionlimit() does not abort the whole command with RecursionError.

    dir_size() holds one fd open per currently-descended level (not per sibling), so a tree
    this deep needs that many simultaneously open fds - more than the default soft limit on
    macOS (256) or many Linux distros (1024). Raise the soft limit for this test only (never
    above the hard limit) rather than reducing the depth, since the depth itself is what
    exercises sys.getrecursionlimit(); skip on platforms without an fd-based soft/hard limit
    (e.g. Windows, which uses the Path fallback and does not hold one fd per level).
    """
    if resource is None or not hasattr(resource, "RLIMIT_NOFILE"):
        pytest.skip("fd-based open-files limit (resource.RLIMIT_NOFILE) not available on this platform")
    depth = 1500  # beyond sys.getrecursionlimit()'s default (~1000)
    needed_fds = depth + 64  # +margin for fds pytest/borg itself already holds open
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < needed_fds:
        pytest.skip(f"hard open-files limit ({hard}) is below what this depth needs ({needed_fds})")
    if soft < needed_fds:
        resource.setrlimit(resource.RLIMIT_NOFILE, (needed_fds, hard))
        request.addfinalizer(lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard)))

    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = json.loads(cmd(archiver, "repo-info", "--json"))["repository"]["id"]

    cache_dir = get_cache_dir(repo_id, create=False)
    # build via relative single-component mkdir+chdir steps, not one long os.path.join'd
    # absolute path, to avoid hitting the OS's own path-length limit (ENAMETOOLONG) long
    # before reaching a depth that would actually exercise Python's recursion limit.
    previous_cwd = os.getcwd()
    try:
        os.chdir(cache_dir)
        for d in range(depth):
            os.mkdir(f"d{d}")
            os.chdir(f"d{d}")
        with open("leaf", "w") as fd:
            fd.write("x" * 7)
    finally:
        os.chdir(previous_cwd)

    result = cmd(archiver, "known-repos")
    assert f"Repository ID: {repo_id}" in result
    assert "Local cache: yes" in result


@pytest.mark.skipif(os.name == "nt", reason="test assumes a real fd; Windows always uses the Path fallback")
def test_dir_size_closes_every_handle_when_list_names_raises_base_exception(tmpdir):
    """dir_size() must close root (and any already-opened subdirectory) even when list_names()

    raises something that is not an OSError (e.g. KeyboardInterrupt) - including on the very
    first call for root, and on the first call for a freshly opened subdirectory, before either
    one has been appended to/left on the stack by a completed iteration. A fd leaked here is a
    real resource leak, not just a style concern: this is a focused unit test against
    _Inspector directly (not the CLI), since the leak is only observable via the raw fd.
    """
    from borg.archiver.known_repos_cmd import _Inspector
    from pathlib import Path

    root = Path(tmpdir)  # open_root() is always called with a Path in production code
    sub = root / "sub"
    sub.mkdir()
    (sub / "f.txt").write_bytes(b"x" * 10)

    inspector = _Inspector()
    root_fd = inspector.open_root(root, str(root))
    assert isinstance(root_fd, int), "test assumes a real fd, not the Windows Path fallback"

    captured = {}
    orig_open_subdir = inspector.open_subdir

    def capturing_open_subdir(parent, name, display):
        fd = orig_open_subdir(parent, name, display)
        captured["sub_fd"] = fd
        return fd

    inspector.open_subdir = capturing_open_subdir

    orig_list_names = inspector.list_names
    calls = {"n": 0}

    def flaky_list_names(d, display):
        calls["n"] += 1
        if calls["n"] == 2:  # the second call is for "sub", opened by the loop below
            raise KeyboardInterrupt("simulated interrupt")
        return orig_list_names(d, display)

    inspector.list_names = flaky_list_names

    with pytest.raises(KeyboardInterrupt):
        inspector.dir_size(root_fd, root)

    with pytest.raises(OSError):
        os.fstat(root_fd)
    sub_fd = captured.get("sub_fd")
    assert isinstance(sub_fd, int)
    with pytest.raises(OSError):
        os.fstat(sub_fd)


@pytest.mark.skipif(os.name == "nt", reason="test assumes a real fd; Windows always uses the Path fallback")
def test_dir_size_closes_root_when_its_own_list_names_raises_base_exception(tmpdir):
    """Same leak class as above, but for root's own first list_names() call specifically -

    the one at the very start of dir_size(), before the while loop has run at all.
    """
    from borg.archiver.known_repos_cmd import _Inspector
    from pathlib import Path

    root = Path(tmpdir)  # open_root() is always called with a Path in production code
    inspector = _Inspector()
    root_fd = inspector.open_root(root, str(root))
    assert isinstance(root_fd, int), "test assumes a real fd, not the Windows Path fallback"

    def raising_list_names(d, display):
        raise KeyboardInterrupt("simulated interrupt")

    inspector.list_names = raising_list_names

    with pytest.raises(KeyboardInterrupt):
        inspector.dir_size(root_fd, root)

    with pytest.raises(OSError):
        os.fstat(root_fd)
