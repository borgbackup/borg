import json
import os
import shutil

from ...constants import *  # NOQA
from ...monitoring import BODY_PLAIN, FORMAT_VERSION
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def _monitoring_key(archiver):
    """Derive BORG_MONITORING_KEY via `borg monitor --key` (needs the borg key)."""
    output = cmd(archiver, "monitor", "--key")
    keys = [line.strip() for line in output.splitlines() if line.strip().startswith("v1:")]
    assert len(keys) == 1, output
    return keys[0]


def _entries(archiver, *extra):
    """Run `borg monitor --json` and return {archive-or-command: entry}."""
    data = json.loads(cmd(archiver, "monitor", "--json", *extra))
    return {(e["archive"] or e["command"]): e for e in data["entries"]}


def _monitoring_dir(archiver):
    return os.path.join(archiver.repository_path, "monitoring")


def _monitoring_object_count(archiver):
    return len(os.listdir(_monitoring_dir(archiver)))


def _replay_oldest_under_newest_name(archiver):
    """Copy the oldest report object to a name that sorts last, return the original names.

    This is what an untrusted repository server can do: object names are plaintext, so it
    can re-serve an old (validly signed) report as if it were the most recent one.
    """
    names = sorted(os.listdir(_monitoring_dir(archiver)))
    replay = f"{'9' * 20}.baadf00d"
    shutil.copyfile(os.path.join(_monitoring_dir(archiver), names[0]), os.path.join(_monitoring_dir(archiver), replay))
    return names


def _plain_report(archiver, name):
    """Read an unsigned report object: 2 header bytes, then the JSON payload."""
    with open(os.path.join(_monitoring_dir(archiver), name), "rb") as f:
        return json.loads(f.read()[2:].decode("utf-8"))


def _write_plain_report(archiver, name, report):
    """Write an unsigned report object, as a repository server could fabricate one."""
    data = bytes([FORMAT_VERSION, BODY_PLAIN]) + json.dumps(report).encode("utf-8")
    with open(os.path.join(_monitoring_dir(archiver), name), "wb") as f:
        f.write(data)


def test_create_publishes_report_and_monitor_reads_it(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    output = cmd(archiver, "monitor")
    assert "status:     success" in output
    assert "trusted:    True" in output
    assert "archive1" in output

    entries = _entries(archiver)
    assert set(entries) == {"archive1"}
    e = entries["archive1"]
    assert e["trusted"] is True and e["stale"] is False
    assert e["report"]["command"] == "create"
    assert e["report"]["status"] == "success"
    assert "archive_id" in e["report"]
    # host/user metadata is recorded and surfaced on the entry
    assert e["hostname"] and e["hostname"] == e["report"]["hostname"]
    assert e["username"] and e["username"] == e["report"]["username"]


def test_multiple_series_are_not_masked(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # two independent archive series backed up by the same command
    cmd(archiver, "create", "backup-home", "input")
    cmd(archiver, "create", "backup-system", "input")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    # both series are reported independently - the later one does not overwrite the earlier
    entries = _entries(archiver)
    assert set(entries) == {"backup-home", "backup-system"}

    # --name restricts to a single series
    data = json.loads(cmd(archiver, "monitor", "--name", "backup-home", "--json"))
    assert [e["archive"] for e in data["entries"]] == ["backup-home"]


def test_same_series_from_different_hosts_kept_separate(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # same archive series name, but backed up from two different hosts to the same repo
    monkeypatch.setenv("BORG_HOSTNAME", "host-a")
    cmd(archiver, "create", "shared", "input")
    monkeypatch.setenv("BORG_HOSTNAME", "host-b")
    cmd(archiver, "create", "shared", "input")
    monkeypatch.delenv("BORG_HOSTNAME")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    data = json.loads(cmd(archiver, "monitor", "--json"))
    assert sorted(e["hostname"] for e in data["entries"]) == ["host-a", "host-b"]
    assert all(e["archive"] == "shared" for e in data["entries"])

    # --host narrows to a single host
    data = json.loads(cmd(archiver, "monitor", "--host", "host-a", "--json"))
    assert [e["hostname"] for e in data["entries"]] == ["host-a"]

    # an unknown host matches nothing -> dead man's switch fires
    out = cmd(archiver, "monitor", "--host", "nope", exit_code=EXIT_ERROR)
    assert "No monitoring report" in out


def test_prune_publishes_its_own_report(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # one series with two archives, then prune down to one
    cmd(archiver, "create", "series", "input")
    cmd(archiver, "create", "series", "input")
    cmd(archiver, "prune", "--keep", "1", "series")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    entries = _entries(archiver)
    assert set(entries) == {"series", "prune"}
    assert entries["series"]["report"]["command"] == "create"
    prune = entries["prune"]["report"]
    assert prune["command"] == "prune"
    assert prune["stats"]["archives_pruned"] == 1
    assert prune["stats"]["archives_kept"] == 1


def test_delete_and_undelete_publish_reports(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "a1", "input")
    cmd(archiver, "create", "a2", "input")
    cmd(archiver, "delete", "a2")
    cmd(archiver, "undelete", "a2")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    entries = _entries(archiver)
    assert {"delete", "undelete"} <= set(entries)
    assert entries["delete"]["report"]["stats"]["archives_deleted"] == 1
    assert entries["undelete"]["report"]["stats"]["archives_undeleted"] == 1


def test_transfer_publishes_report(archivers, request, monkeypatch):
    from .transfer_cmd_test import setup_repos

    archiver = request.getfixturevalue(archivers)
    with setup_repos(archiver, monkeypatch) as other_repo1:
        create_regular_file(archiver.input_path, "file1", contents=b"some data")
        cmd(archiver, "create", "arch1", "input")
        cmd(archiver, "create", "arch2", "input")
    cmd(archiver, "transfer", other_repo1)
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))

    entries = _entries(archiver)
    assert "transfer" in entries
    stats = entries["transfer"]["report"]["stats"]
    assert stats["archives_transferred"] == 2
    assert stats["archives_considered"] == 2


def test_keep_evicts_old_objects(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for _ in range(4):
        cmd(archiver, "create", "series", "input")
    assert _monitoring_object_count(archiver) == 4
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))
    # reading with --keep deletes all but the N newest objects
    cmd(archiver, "monitor", "--keep", "2")
    assert _monitoring_object_count(archiver) == 2
    # --keep 0 disables cleanup
    cmd(archiver, "monitor", "--keep", "0")
    assert _monitoring_object_count(archiver) == 2


def test_monitor_stale_report_alerts(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))
    # a zero freshness window makes any report stale -> error exit code (dead man's switch)
    output = cmd(archiver, "monitor", "--max-age", "0", exit_code=EXIT_ERROR)
    assert "STALE" in output


def test_monitor_no_report(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))
    output = cmd(archiver, "monitor", exit_code=EXIT_ERROR)
    assert "No monitoring report" in output


def test_monitor_without_key_errors(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    # sealed report but no BORG_MONITORING_KEY -> clean Error (use fork so it maps to a rc)
    output = cmd(archiver, "monitor", fork=True, exit_code=EXIT_ERROR)
    assert "BORG_MONITORING_KEY" in output


def test_monitor_unencrypted_repo_is_untrusted(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "archive1", "input")
    # no key needed; report is plaintext and flagged untrusted -> warning exit code
    output = cmd(archiver, "monitor", exit_code=EXIT_WARNING)
    assert "trusted:    False" in output
    # there is no monitoring key to export for a keyless (none-*) repo
    out = cmd(archiver, "monitor", "--key", fork=True, exit_code=EXIT_ERROR)
    assert "keyless" in out


def test_replayed_report_is_refused(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "series", "input")
    cmd(archiver, "create", "series", "input")
    _replay_oldest_under_newest_name(archiver)
    monkeypatch.setenv("BORG_MONITORING_KEY", _monitoring_key(archiver))
    # the object name is bound into the seal, so a report re-served under another name
    # does not even open - the attempt surfaces instead of silently shadowing the newer one
    output = cmd(archiver, "monitor", fork=True, exit_code=EXIT_ERROR)
    assert "verification/decryption failed" in output


def test_unsigned_replay_does_not_shadow_newer_report(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "series", "input")
    cmd(archiver, "create", "series", "input")
    names = _replay_oldest_under_newest_name(archiver)
    newest_time = _plain_report(archiver, names[-1])["time"]
    # unsigned reports can not be bound to their name, so the time inside the report - not
    # the (server-controlled) object name - has to decide which one is the latest
    data = json.loads(cmd(archiver, "monitor", "--json", exit_code=EXIT_WARNING))
    assert [e["report"]["time"] for e in data["entries"]] == [newest_time]


def test_injected_unsigned_report_is_refused(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"some data")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "series", "input")
    key = _monitoring_key(archiver)
    # the server drops the sealed report (which it can not forge) and puts an unsigned
    # "success" of its own in its place - this must not be downgraded to a warning
    for name in os.listdir(_monitoring_dir(archiver)):
        os.remove(os.path.join(_monitoring_dir(archiver), name))
    _write_plain_report(
        archiver,
        f"{'1' * 20}.0badc0de",
        {"command": "create", "archive": "series", "status": "success", "rc": 0, "time": "2286-11-20T17:46:39+00:00"},
    )
    monkeypatch.setenv("BORG_MONITORING_KEY", key)
    output = cmd(archiver, "monitor", fork=True, exit_code=EXIT_ERROR)
    assert "unsigned" in output


def test_monitor_key_export_is_deterministic(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    assert _monitoring_key(archiver) == _monitoring_key(archiver)
