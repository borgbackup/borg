from datetime import datetime, timezone, timedelta
import errno
from pathlib import Path
import re
import shutil
from unittest.mock import patch

import pytest

from ...archive import ArchiveChecker, ChunkBuffer
from ...constants import *  # NOQA
from ...helpers import bin_to_hex, hex_to_bin, msgpack, CommandError, Error, IntegrityError, sig_int
from ...manifest import Archives, Manifest
from ...repository import PackTracker, Repository
from ..repository_test import fchunk, corrupt_chunk_on_disk
from . import (
    cmd,
    src_file,
    create_src_archive,
    create_regular_file,
    open_archive,
    generate_archiver_tests,
    read_chunk,
    write_wrong_content_chunk,
    RK_ENCRYPTION,
)

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def corrupt(data, position):
    """Return data with the byte at position flipped, so the result is guaranteed to differ.

    Overwriting a byte with a fixed value is not reliable: if the original byte already happens
    to have that value, nothing changes and the "corruption" is a no-op. For encrypted/MACed
    objects the bytes are ~random, so a fixed overwrite is a no-op ~1/256 of the time, which made
    tests relying on it intermittently fail. Flipping all bits always changes the byte.
    """
    if position < 0:
        position += len(data)
    return data[:position] + bytes([data[position] ^ 0xFF]) + data[position + 1 :]


def check_cmd_setup(archiver):
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        cmd(archiver, "repo-create", RK_ENCRYPTION)
        create_src_archive(archiver, "archive1")
        create_src_archive(archiver, "archive2")


def test_check_usage(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    output = cmd(archiver, "check", "-v", "--progress", exit_code=0)
    assert "Starting full repository check" in output
    assert "Starting archive consistency check" in output

    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=0)
    assert "Starting full repository check" in output
    assert "Starting archive consistency check" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", exit_code=0)
    assert "Starting full repository check" not in output
    assert "Starting archive consistency check" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--match-archives=archive2", exit_code=0)
    assert "archive1" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--first=1", exit_code=0)
    assert "archive1" in output
    assert "archive2" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--last=1", exit_code=0)
    assert "archive1" not in output
    assert "archive2" in output


def test_check_soft_interrupt(archivers, request, monkeypatch):
    """A mid-run Ctrl-C stops both check phases at a safe boundary (#7893): the repository check persists
    its checked packs for a later partial check to resume, and the archive check runs finish() and then
    raises. The check is read-only, so a normal check still passes afterwards."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)  # produces many packs

    # repository check: interrupt after the first pack.
    with Repository(archiver.repository_path, exclusive=True) as repository:
        orig_hash = repository.store.hash
        pack_checks = []

        def hash_then_interrupt(key):
            result = orig_hash(key)
            if key.startswith("packs/"):  # count pack checks, not the index files hashed first
                pack_checks.append(key)
                if len(pack_checks) == 1:  # one Ctrl-C after the first pack is checked
                    sig_int._sig_int_triggered = True
            return result

        monkeypatch.setattr(repository.store, "hash", hash_then_interrupt)
        try:
            repository.check()
        finally:
            sig_int._sig_int_triggered = False
        assert len(PackTracker.load(repository.store)) == 1  # the pack checked before the break persisted

    # a partial check resumes from the saved record (the one pack checked before the interrupt).
    output = cmd(archiver, "check", "-v", "--repository-only", "--max-duration=600", exit_code=0)
    assert "1 pack check results on record" in output

    # archive check: interrupt verify_data after 3 chunks.
    with Repository(archiver.repository_path, exclusive=True) as repository:
        orig_get = repository.get
        get_calls = 0

        def get_then_interrupt(*args, **kwargs):
            nonlocal get_calls
            get_calls += 1
            if get_calls == 3:  # trip mid-loop, after 3 chunks
                sig_int._sig_int_triggered = True
            return orig_get(*args, **kwargs)

        monkeypatch.setattr(repository, "get", get_then_interrupt)
        try:
            with pytest.raises(Error, match="Got Ctrl-C"):
                ArchiveChecker().check(repository, verify_data=True, sort_by="ts", format="{archive} {time} {id}")
        finally:
            sig_int._sig_int_triggered = False
        # verify_data breaks at the chunk it interrupted on, and the skipped scans issue no more get()s.
        assert get_calls == 3

    # nothing changed, so a normal check passes.
    cmd(archiver, "check", exit_code=0)


def test_check_repair_soft_interrupt(archivers, request, monkeypatch):
    """A Ctrl-C after the first archive of a --repair archive check stops at the archive boundary, runs
    finish() (dropping the chunk index, writing the manifest), then raises. No archive is lost, and a
    second --repair finishes the job so a following check reports the repository consistent."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)  # two archives

    orig_create = Archives.create

    def create_then_interrupt(self, *args, **kwargs):
        orig_create(self, *args, **kwargs)
        sig_int._sig_int_triggered = True  # one Ctrl-C after the first archive was rebuilt

    monkeypatch.setattr(Archives, "create", create_then_interrupt)
    try:
        with Repository(archiver.repository_path, exclusive=True) as repository:
            with pytest.raises(Error, match="Got Ctrl-C"):
                ArchiveChecker().check(repository, repair=True, sort_by="ts", format="{archive} {time} {id}")
    finally:
        sig_int._sig_int_triggered = False  # reset the global flag for the following tests
    # restore the real method; monkeypatch.undo() would also drop the autouse env (BORG_TESTONLY_WEAKEN_KDF).
    monkeypatch.setattr(Archives, "create", orig_create)

    # both archives survive the interrupt between archives.
    output = cmd(archiver, "repo-list", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output

    # a second --repair finishes the job; a plain check then finds no problems.
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_check_interrupt_skips_archive_check(archivers, request, monkeypatch):
    """A Ctrl-C during the repository check makes a full `borg check` skip the archive check. do_check
    raises at the sig_int guard, which sits before the archive_checker.check() call, so the raise itself
    is the skip. Exercises the do_check path (the other soft-interrupt tests call check() directly)."""
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:  # a class-level monkeypatch cannot reach the borg.exe subprocess
        pytest.skip("in-process store patch does not apply to the binary")
    check_cmd_setup(archiver)  # produces many packs

    from borgstore.store import Store

    orig_hash = Store.hash
    pack_checks = []

    def hash_then_interrupt(self, key):
        result = orig_hash(self, key)
        if key.startswith("packs/"):  # count pack checks, not the index files hashed first
            pack_checks.append(key)
            if len(pack_checks) == 1:  # one Ctrl-C after the first pack is checked
                sig_int._sig_int_triggered = True
        return result

    # spy on the archive check: "Got Ctrl-C" is also raised inside ArchiveChecker.check(), so matching the
    # message alone would not prove the skip. Recording that check() never runs is the load-bearing assertion.
    orig_check = ArchiveChecker.check
    archive_check_ran = False

    def spy_check(self, *args, **kwargs):
        nonlocal archive_check_ran
        archive_check_ran = True
        return orig_check(self, *args, **kwargs)

    monkeypatch.setattr(Store, "hash", hash_then_interrupt)
    monkeypatch.setattr(ArchiveChecker, "check", spy_check)
    try:
        # exec_cmd calls Archiver.run() directly; only main() maps Error to an exit code, so it propagates.
        with pytest.raises(Error, match="Got Ctrl-C"):
            cmd(archiver, "check", "-v")
    finally:
        sig_int._sig_int_triggered = False
    assert archive_check_ran is False  # do_check raised at the sig_int guard, before archive_checker.check()


def test_check_max_age(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    # --repair and --archives-only do not allow --max-age; 0d is a valid value (resolves to no reuse).
    # --max-duration needs --repository-only, but not --max-age: a partial check advances on its own.
    if archiver.FORK_DEFAULT:
        cmd(archiver, "check", "--repair", "--max-age=1d", exit_code=CommandError().exit_code)
        cmd(archiver, "check", "--repair", "--max-age=0d", exit_code=CommandError().exit_code)
        cmd(archiver, "check", "--archives-only", "--max-age=1d", exit_code=CommandError().exit_code)
        cmd(archiver, "check", "--max-duration=3600", exit_code=CommandError().exit_code)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "check", "--repair", "--max-age=1d")
        with pytest.raises(CommandError):
            cmd(archiver, "check", "--repair", "--max-age=0d")
        with pytest.raises(CommandError):
            cmd(archiver, "check", "--archives-only", "--max-age=1d")
        with pytest.raises(CommandError):
            cmd(archiver, "check", "--max-duration=3600")

    # a partial check runs without --max-age.
    cmd(archiver, "check", "--repository-only", "--max-duration=3600", exit_code=0)

    # a check records its results, a later one with --max-age reuses them.
    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=0)
    assert "Starting full repository check" in output
    output = cmd(archiver, "check", "-v", "--repository-only", "--max-age=4w", exit_code=0)
    assert "reusing those younger than --max-age" in output
    assert "no problems found" in output


def test_date_matching(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-2022-11-20", ts="2022-11-20T23:59:59")
    create_src_archive(archiver, "archive-2022-12-18", ts="2022-12-18T23:59:59")
    create_src_archive(archiver, "archive-now")
    cmd(archiver, "check", "-v", "--archives-only", "--oldest=23e", exit_code=2)

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=1y", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=1y", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=1m", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=1m", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=4w", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=4w", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=1d", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=1d", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=24H", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=24H", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=1440M", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=1440M", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=86400S", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=86400S", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    # Check for output when a time span older than the earliest archive is given. Issue #1711
    output = cmd(archiver, "check", "-v", "--archives-only", "--older=9999m", exit_code=0)
    for archive in ("archive1", "archive2", "archive3"):
        assert archive not in output


def test_missing_file_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    archive, repository = open_archive(archiver.repository_path, "archive1")

    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                valid_chunks = item.chunks
                killed_chunk = valid_chunks[-1]
                repository.delete(killed_chunk.id)
                break
        else:
            pytest.fail("should not happen")  # convert 'fail'

    output = cmd(archiver, "check", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    # archive1 and archive2 share src_file, so the missing chunk is grouped once, with both archives
    # listed on its single reference line (the id also appears once in the streamed "Missing chunk
    # detected" line emitted while the archives are analyzed).
    killed_hex = bin_to_hex(killed_chunk.id)
    chunk_header_lines = [ln for ln in output.splitlines() if ln.startswith("- Chunk ") and killed_hex in ln]
    assert len(chunk_header_lines) == 1
    ref_lines = [line for line in output.splitlines() if src_file in line]
    assert len(ref_lines) == 1
    assert "archive1" in ref_lines[0] and "archive2" in ref_lines[0]
    output = cmd(archiver, "check", "--repair", exit_code=0)
    # repair is not changing anything, just reporting.
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(killed_chunk.id) in output

    # check does not modify the chunks list.
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(archiver.repository_path, archive_name)
        with repository:
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    assert len(valid_chunks) == len(item.chunks)
                    assert valid_chunks == item.chunks
                    break
            else:
                pytest.fail("should not happen")  # convert 'fail'

    # do a fresh backup (that will include the killed chunk)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        create_src_archive(archiver, "archive3")

    # check should not complain anymore about missing chunks:
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "The following chunks are missing in the repository:" not in output


def test_missing_file_chunk_report_truncated(archiver):
    # local-only: this patches ArchiveChecker.MAX_MISSING_CHUNKS in-process, which has no effect
    # when borg runs as a separate process (binary_archiver), so it must not be parametrized.
    check_cmd_setup(archiver)

    # remove several distinct file chunks, so more missing chunks exist than the (patched) report limit.
    archive, repository = open_archive(archiver.repository_path, "archive1")
    killed_ids = []
    with repository:
        for item in archive.iter_items():
            if "chunks" not in item or not item.chunks:
                continue
            chunk_id = item.chunks[-1].id
            if chunk_id not in killed_ids:
                repository.delete(chunk_id)
                killed_ids.append(chunk_id)
            if len(killed_ids) >= 3:
                break
    assert len(killed_ids) >= 2  # need several distinct missing chunks to exercise truncation

    # cap the report to a single chunk, so the remaining missing chunks are truncated.
    with patch.object(ArchiveChecker, "MAX_MISSING_CHUNKS", 1):
        output = cmd(archiver, "check", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    assert output.count("- Chunk ") == 1  # only one chunk is detailed
    assert "only the first 1 missing chunks are listed" in output  # the rest are noted as truncated


def test_missing_file_chunk_refs_truncated(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # many distinct files with identical content dedup to the same chunk, so a single missing chunk
    # ends up referenced by more files than MAX_REFS_PER_CHUNK, which exercises the per-chunk cap
    # without patching (so it works in binary mode too, where borg runs as a separate process).
    cap = ArchiveChecker.MAX_REFS_PER_CHUNK
    for i in range(cap + 1):
        create_regular_file(archiver.input_path, f"samefile{i}", contents=b"same content for dedup")
    cmd(archiver, "create", "archive1", "input")

    archive, repository = open_archive(archiver.repository_path, "archive1")
    killed_id = None
    with repository:
        for item in archive.iter_items():
            if item.path.endswith("samefile0"):
                killed_id = item.chunks[0].id
                repository.delete(killed_id)
                break
    assert killed_id is not None

    output = cmd(archiver, "check", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(killed_id) in output
    assert f"only the first {cap} files are listed" in output  # the remaining referencing files are truncated


def test_missing_archive_item_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.metadata.items[0])
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_archive_metadata(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.id)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_check_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    output = cmd(archiver, "check", "-v", "--archives-only", "--format", "{archive}|{hostname}", exit_code=0)
    assert "Analyzing archive archive1|" in output


def test_check_format_env_var(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    monkeypatch.setenv("BORG_CHECK_FORMAT", "{archive}|env")
    output = cmd(archiver, "check", "-v", "--archives-only", exit_code=0)
    assert "Analyzing archive archive1|env" in output
    output = cmd(archiver, "check", "-v", "--archives-only", "--format", "{archive}|arg", exit_code=0)
    assert "Analyzing archive archive1|arg" in output  # --format overrides the env var


def test_check_format_invalid_key(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        output = cmd(archiver, "check", "--archives-only", "--format", "{nosuchkey}", exit_code=expected_ec)
        assert "Invalid format keys: nosuchkey" in output
    else:
        with pytest.raises(CommandError, match="Invalid format keys: nosuchkey"):
            cmd(archiver, "check", "--archives-only", "--format", "{nosuchkey}")


def test_check_format_repository_only(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        output = cmd(archiver, "check", "--repository-only", "--format", "{archive}", exit_code=expected_ec)
        assert "--repository-only contradicts" in output
    else:
        with pytest.raises(CommandError, match="--repository-only contradicts"):
            cmd(archiver, "check", "--repository-only", "--format", "{archive}")
    # only the option contradicts, a set env var must not make the repository check fail:
    monkeypatch.setenv("BORG_CHECK_FORMAT", "{archive}|env")
    cmd(archiver, "check", "--repository-only", exit_code=0)


def test_check_format_invalid_format_string(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        output = cmd(archiver, "check", "--archives-only", "--format", "{archive", exit_code=expected_ec)
        assert "Invalid format string" in output
    else:
        with pytest.raises(CommandError, match="Invalid format string"):
            cmd(archiver, "check", "--archives-only", "--format", "{archive")


def test_check_format_missing_archive_metadata(archivers, request):
    # {comment} needs the archive metadata, which is deleted below.
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.id)
    archive_id_hex = bin_to_hex(archive.id)
    output = cmd(archiver, "check", "-v", "--archives-only", "--format", "{archive} {comment}", exit_code=1)
    # the archive directory entry has no name for it, only the id, which {archive} {comment} would not show.
    # the timestamp uses the same style as the formatter would produce, e.g. "Thu, 1970-01-01 00:00:00 +0000":
    assert re.search(r"Analyzing archive archive-does-not-exist \w{3}, \d{4}-\d{2}-\d{2} ", output)
    assert f"{archive_id_hex} (1/2)" in output
    assert f"Archive metadata block {archive_id_hex} is missing!" in output
    assert "Analyzing archive archive2" in output  # the intact archive still uses the given format


def test_missing_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        if isinstance(repository, Repository):
            repository.store_delete("config/manifest")
        else:
            repository.delete(Manifest.MANIFEST_ID)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_corrupted_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = repository.get_manifest()
        corrupted_manifest = corrupt(manifest, 250)
        repository.put_manifest(corrupted_manifest)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_spoofed_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        cdata = manifest.repo_objs.format(
            Manifest.MANIFEST_ID,
            {},
            msgpack.packb(
                {
                    "version": 1,
                    "archives": {},
                    "config": {},
                    "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(timespec="microseconds"),
                }
            ),
            # we assume that an attacker can put a file into backup src files that contains a fake manifest.
            # but, the attacker can not influence the ro_type borg will use to store user file data:
            ro_type=ROBJ_FILE_STREAM,  # a real manifest is stored with ROBJ_MANIFEST
        )
        # maybe a repo-side attacker could manage to move the fake manifest file chunk over to the manifest ID.
        # we simulate this here by directly writing the fake manifest data to the manifest ID.
        repository.put_manifest(cdata)
    # borg should notice that the manifest has the wrong ro_type.
    cmd(archiver, "check", exit_code=1)
    # borg check --repair should remove the corrupted manifest and rebuild a new one.
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_check_repair_rebuilds_corrupt_index(archivers, request):
    # A corrupt index with all packs intact: the default (full) --repair rebuilds the index from the
    # packs and persists it (via the archives check, see ArchiveChecker.finish), leaving the repository
    # usable again without a slow rebuild on the next access.
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        assert isinstance(repository, Repository)
        for info in repository.store_list("index"):  # rot every index fragment
            name = f"index/{info.name}"
            data = bytearray(repository.store_load(name))
            data[0] ^= 0xFF
            repository.store_store(name, bytes(data))
    cmd(archiver, "check", exit_code=1)  # read-only check reports the corrupt index
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "rebuilt" in output.lower()
    # item 6: repair persisted a fresh index instead of leaving it for a slow rebuild on the next
    # access. confirm the on-disk index exists and every fragment is intact.
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        index_infos = list(repository.store_list("index"))
        assert index_infos  # a fresh index was persisted
        for info in index_infos:  # each fragment's content still matches its sha256 name
            assert repository.store.hash(f"index/{info.name}") == info.name
    cmd(archiver, "check", exit_code=0)  # the repository is consistent again
    assert "archive1" in cmd(archiver, "repo-list")  # and remains usable


@pytest.mark.skip(reason="TODO: repair does not yet rewrite store-corrupted packs, refs #8572")
def test_manifest_rebuild_corrupted_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = repository.get_manifest()
        # flip a byte inside the encrypted manifest data so its integrity check fails and
        # check --repair rebuilds the manifest.
        corrupted_manifest = corrupt(manifest, len(manifest) // 3)
        repository.put_manifest(corrupted_manifest)
        corrupt_chunk_on_disk(repository, archive.id)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" not in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_check_undelete_archives(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)  # creates archive1 and archive2
    existing_archive_ids = set(cmd(archiver, "repo-list", "--short").splitlines())
    create_src_archive(archiver, "archive3")
    archive_ids = set(cmd(archiver, "repo-list", "--short").splitlines())
    new_archive_id_hex = (archive_ids - existing_archive_ids).pop()
    (Path(archiver.repository_path) / "archives" / new_archive_id_hex).unlink()  # lose the entry for archive3
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output
    # borg check will re-discover archive3 and create a new archives directory entry.
    cmd(archiver, "check", "--repair", "--find-lost-archives", exit_code=0)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" in output


def test_spoofed_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    repo_objs = archive.repo_objs
    with repository:
        # attacker would corrupt or delete the manifest to trigger a rebuild of it:
        manifest = repository.get_manifest()
        corrupted_manifest = corrupt(manifest, 250)
        repository.put_manifest(corrupted_manifest)
        archive_dict = {
            "command_line": "",
            "item_ptrs": [],
            "hostname": "foo",
            "username": "bar",
            "name": "archive_spoofed",
            "time": "2016-12-15T18:49:51.849711",
            "version": 2,
        }
        archive = repo_objs.key.pack_metadata(archive_dict)
        archive_id = repo_objs.id_hash(archive)
        repository.put(
            archive_id,
            repo_objs.format(
                archive_id,
                {},
                archive,
                # we assume that an attacker can put a file into backup src files that contains a fake archive.
                # but, the attacker can not influence the ro_type borg will use to store user file data:
                ro_type=ROBJ_FILE_STREAM,  # a real archive is stored with ROBJ_ARCHIVE_META
            ),
        )
        repository.flush()  # make the put durable before close()/the check below
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", "--debug", exit_code=0)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive_spoofed" not in output


def test_extra_chunks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        key = b"01234567890123456789012345678901"
        chunk = fchunk(b"xxxx", chunk_id=key)
        repository.put(key, chunk)
        repository.flush()  # make the put durable before close()/the check below
    cmd(archiver, "check", "-v", exit_code=0)  # check does not deal with orphans anymore


def test_repair_finish_flushes_pack_writer(archivers, request):
    """finish() stores chunks re-added during --repair before it (re)builds the index (#10055).

    close() asserts an empty pack writer buffer, so a chunk left buffered by finish() would
    trip it.
    """
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects in-process repository internals")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)

    with Repository(archiver.repository_location, exclusive=True) as repository:
        checker = ArchiveChecker()
        checker.repair = True
        checker.repository = repository
        checker.key = checker.make_key(repository)
        checker.manifest = Manifest.load(repository, (Manifest.Operation.CHECK,), key=checker.key)
        # re-adding a chunk makes the chunks index no longer match the packs, so finish() rebuilds it.
        checker.chunks_modified = True

        # a chunk re-added during repair, buffered in the pack writer:
        key = b"01234567890123456789012345678901"
        repository.put(key, fchunk(b"repaired", chunk_id=key))
        assert repository._pack_writer._pieces

        checker.finish()
        assert not repository._pack_writer._pieces  # finish() stored it


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "none-sha256"]])
def test_verify_data(archivers, request, init_args):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")

    check_cmd_setup(archiver)
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                corrupt_chunk_on_disk(repository, chunk.id)
                break

    # the normal archives check does not read file content data.
    cmd(archiver, "check", "--archives-only", exit_code=0)
    # but with --verify-data, it does and notices the issue.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output

    # repair will find the defect chunk and remove it
    output = cmd(archiver, "check", "--repair", "--verify-data", exit_code=0)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(chunk.id) in output
    assert src_file in output

    # run with --verify-data again, it will notice the missing chunk.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(chunk.id) in output


def test_verify_data_wrong_chunk_content(archivers, request, monkeypatch):
    # a chunk whose content does not match its id (only an evil borg client that had the repo key could
    # have written it): the AEAD layer authenticates it just fine, only the id check notices, see #9994.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")

    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                break
        write_wrong_content_chunk(archive, repository, chunk.id)

    # by default, reads do not check the id/content invariant, so this is not noticed:
    monkeypatch.delenv("BORG_ASSERT_ID", raising=False)
    cmd(archiver, "extract", "archive1", exit_code=0)
    # ... but check --verify-data always checks it:
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert "id verification failed" in output

    # with "read" in BORG_ASSERT_ID, reads check it too:
    monkeypatch.setenv("BORG_ASSERT_ID", "read")
    with pytest.raises(IntegrityError):  # local (not forked): the Error propagates instead of setting the rc
        cmd(archiver, "extract", "archive1")


def test_repair_wrong_item_metadata_chunk_content(archivers, request, monkeypatch):
    # check --repair re-packs the item metadata stream it reads into new chunks with freshly computed ids,
    # so it re-certifies the id/content invariant, even though reads do not check it by default, see #9994.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")

    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        chunk_id = archive.metadata.items[0]  # first chunk of the item metadata stream
        data = read_chunk(archive, repository, chunk_id, ro_type=ROBJ_ARCHIVE_STREAM)
        # append a msgpack nil: the item stream still unpacks (so a read that does not check the id gets
        # away with it), but the content does not hash to the chunk id any more.
        write_wrong_content_chunk(archive, repository, chunk_id, ro_type=ROBJ_ARCHIVE_STREAM, wrong_data=data + b"\xc0")

    monkeypatch.delenv("BORG_ASSERT_ID", raising=False)
    # a normal archives check reads the item metadata stream, but does not check the id:
    output = cmd(archiver, "check", "--archives-only", exit_code=1)
    assert "id verification failed" not in output
    # --repair rebuilds the archive from what it reads, so there it is checked:
    output = cmd(archiver, "check", "--repair", "--archives-only", exit_code=0)
    assert f"{bin_to_hex(chunk_id)}" in output
    assert "id verification failed" in output


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "none-sha256"]])
def test_corrupted_file_chunk(archivers, request, init_args):
    ## like test_verify_data, but also checks a repository-only check passes after repair and a plain
    ## archives check reports the missing chunk.

    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                corrupt_chunk_on_disk(repository, chunk.id)
                break

    # --verify-data decrypts and catches the corruption.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output

    # repair: the defect chunk will be removed.
    output = cmd(archiver, "check", "--repair", "--verify-data", exit_code=0)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(chunk.id) in output
    assert src_file in output

    # run normal check again
    cmd(archiver, "check", "--repository-only", exit_code=0)
    output = cmd(archiver, "check", "--archives-only", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    assert src_file in output


@pytest.mark.skip(
    reason="TODO: a non-repair check verifies index and packs by sha256 and uses that verified index (it does "
    "not rebuild it); after dropping all packs the index still lists their chunks, so reading them raises "
    "ObjectNotFound instead of being reported as missing. Needs the index/repair redesign, refs #8572."
)
def test_empty_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        # empty the repo by dropping every pack file directly via the store. We iterate the actual
        # packs/ listing (the file names are the pack_ids), so this does not depend on what list()
        # yields.
        for info in repository.store_list("packs"):
            repository.store_delete("packs/" + info.name)
    cmd(archiver, "check", exit_code=1)


def make_store_reads_fail(monkeypatch, should_fail, *, after=0):
    """Make matching posixfs reads fail with an OSError, like failing storage does.

    should_fail(name, offset, size) decides per read; offset/size are None for the operations that
    do not take a range (hash, info, list). The first <after> matching reads still succeed, which
    models storage that starts failing (or fails only sometimes) rather than being dead from the
    start.

    Patches the backend rather than using file permissions, so this also works when the tests run
    as root and does not depend on the platform's permission semantics. Returns a dict whose
    "failing" entry switches the failures off again (monkeypatch.undo() must not be used here, it
    would also revert the autouse clean_env fixture).
    """
    from borgstore.backends.posixfs import PosixFS

    state = {"failing": True, "hits": 0}
    orig = {name: getattr(PosixFS, name) for name in ("hash", "load", "info", "list")}

    def check(name, offset=None, size=None):
        if not (state["failing"] and should_fail(name, offset, size)):
            return
        state["hits"] += 1
        if state["hits"] > after:
            raise OSError(errno.EIO, "Input/output error", name)

    def failing_hash(self, name, algorithm="sha256"):
        check(name)
        return orig["hash"](self, name, algorithm=algorithm)

    def failing_load(self, name, *, size=None, offset=0):
        check(name, offset, size)
        return orig["load"](self, name, size=size, offset=offset)

    def failing_info(self, name):
        check(name)
        return orig["info"](self, name)

    def failing_list(self, name):
        check(name)
        return orig["list"](self, name)

    monkeypatch.setattr(PosixFS, "hash", failing_hash)
    monkeypatch.setattr(PosixFS, "load", failing_load)
    monkeypatch.setattr(PosixFS, "info", failing_info)
    monkeypatch.setattr(PosixFS, "list", failing_list)
    return state


def object_name(name):
    """Return the object's own name, without the nesting levels borgstore puts in front of it."""
    # the backend gets the name including those levels, e.g. packs/d0/d0a6... for packs/d0a6...
    return name.rsplit("/", 1)[-1]


def make_pack_unreadable(monkeypatch, pack_name):
    """Make every read of the pack packs/<pack_name> fail."""
    return make_store_reads_fail(monkeypatch, lambda name, offset, size: object_name(name) == pack_name)


def make_namespace_listing_fail(monkeypatch, namespace):
    """Make listing the given store namespace fail."""
    return make_store_reads_fail(monkeypatch, lambda name, offset, size: name.split("/")[0] == namespace)


def some_pack_name(archiver):
    """Return the name of one of the repository's pack files."""
    with Repository(archiver.repository_location, exclusive=True) as repository:
        return sorted(info.name for info in repository.store_list("packs"))[0]


def pack_name_of(archiver, chunk_id):
    """Return the name of the pack file holding chunk_id."""
    with Repository(archiver.repository_location, exclusive=True) as repository:
        return bin_to_hex(repository.chunks[chunk_id].pack_id)


def file_content_chunk_id(archiver, archive_name="archive1"):
    """Return the id of a file content chunk of the given archive."""
    archive, repository = open_archive(archiver.repository_path, archive_name)
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                return item.chunks[-1].id
    raise AssertionError(f"{src_file} not found in {archive_name}")


def test_check_unreadable_pack(archivers, request, monkeypatch):
    # an I/O error while reading a pack must not crash the check with a traceback: it is reported,
    # the check goes on and fails at the end, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)
    pack_name = some_pack_name(archiver)
    make_pack_unreadable(monkeypatch, pack_name)

    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=1)
    assert f"Store object packs/{pack_name} could not be read" in output
    assert "Input/output error" in output
    # the check did not stop at the unreadable pack ...
    assert "Finished checking packs." in output
    assert "store object(s) could not be read" in output
    # ... and it did not claim the pack is corrupt (we never saw its content).
    assert "is corrupted" not in output
    assert "Corrupt pack" not in output


def test_check_unreadable_pack_not_recorded(archivers, request, monkeypatch):
    # a pack we could not read gets no result recorded, so a later check verifies it again instead
    # of remembering it as corrupt, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    pack_name = some_pack_name(archiver)
    state = make_pack_unreadable(monkeypatch, pack_name)
    cmd(archiver, "check", "--repository-only", exit_code=1)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        tracker = PackTracker.load(repository.store)
        assert tracker.get(hex_to_bin(pack_name)) is None
        assert tracker.corrupt_ids() == []
    # once the pack reads fine again, the check passes without any manual cleanup.
    state["failing"] = False
    cmd(archiver, "check", exit_code=0)


def test_check_repair_refuses_unreadable_pack(archivers, request, monkeypatch):
    # --repair must not repair around an unreadable pack: its chunks may well be readable again
    # once the underlying problem is fixed, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    pack_name = some_pack_name(archiver)
    make_pack_unreadable(monkeypatch, pack_name)
    with pytest.raises(Repository.RepairUnsafe):  # local (not forked): the Error propagates
        cmd(archiver, "check", "--repair")


def test_check_verify_data_unreadable_pack_keeps_chunks(archivers, request, monkeypatch):
    # --verify-data deletes chunks whose content is defect, but must keep chunks it could not read
    # at all, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    # target the pack holding file content, so --verify-data is what reads it.
    pack_name = pack_name_of(archiver, file_content_chunk_id(archiver))
    with Repository(archiver.repository_location, exclusive=True) as repository:
        chunks_before = sorted(chunk_id for chunk_id, _ in repository.chunks.iteritems())
    state = make_pack_unreadable(monkeypatch, pack_name)

    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert "could not be read and were left untouched" in output

    state["failing"] = False
    with Repository(archiver.repository_location, exclusive=True) as repository:
        chunks_after = sorted(chunk_id for chunk_id, _ in repository.chunks.iteritems())
    assert chunks_after == chunks_before  # nothing was thrown away


def test_check_unreadable_archive_metadata_pack(archivers, request, monkeypatch):
    # the pack holding an archive's metadata is unreadable: listing the archives must not die, the
    # affected archive is reported and the other archives still get checked, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        archive_id = archive.id
    pack_name = pack_name_of(archiver, archive_id)
    make_pack_unreadable(monkeypatch, pack_name)

    output = cmd(archiver, "check", "--archives-only", exit_code=1)
    assert f"Archive metadata block {bin_to_hex(archive_id)} could not be read" in output
    assert "Input/output error" in output
    assert "Archive consistency check complete, problems found." in output


def test_unreadable_archive_metadata_pack_does_not_fake_an_archive(archivers, request, monkeypatch):
    # outside of borg check, an unreadable archive metadata object must not turn into a placeholder
    # entry: acting on a repository we can not fully read (e.g. prune, which would see the
    # placeholder's 1970 timestamp) is how transient I/O errors become data loss, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        archive_id = archive.id
    make_pack_unreadable(monkeypatch, pack_name_of(archiver, archive_id))
    with pytest.raises(Repository.StoreReadError):  # local (not forked): the Error propagates
        cmd(archiver, "repo-list")


def test_check_unreadable_packs_listing(archivers, request, monkeypatch):
    # without a listing we do not know what to check, so this one is fatal - but it must end the
    # check with a clear message instead of a traceback, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    make_namespace_listing_fail(monkeypatch, "packs")
    with pytest.raises(Repository.StoreReadError):  # local (not forked): the Error propagates
        cmd(archiver, "check", "--repository-only")


def test_check_unreadable_index_object(archivers, request, monkeypatch):
    # an unreadable index object is reported and the check goes on to the packs. the missing-pack
    # cross-check needs the index too, so it is skipped rather than reporting bogus results, #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        index_name = sorted(info.name for info in repository.store_list("index"))[0]
    make_store_reads_fail(monkeypatch, lambda name, offset, size: object_name(name) == index_name)

    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=1)
    assert f"Store object index/{index_name} could not be read" in output
    assert "skipping missing-pack detection" in output
    assert "Finished checking packs." in output  # the packs were checked anyway
    assert "store object(s) could not be read" in output


def test_check_repair_unreadable_pack_aborts_index_rebuild(archivers, request, monkeypatch):
    # --repair rebuilds the chunk index from the packs' object headers. an unreadable pack stops
    # that with a clear error: an index rebuilt without its objects would drop them, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    make_pack_unreadable(monkeypatch, some_pack_name(archiver))
    with pytest.raises(Repository.StoreReadError):  # local (not forked): the Error propagates
        cmd(archiver, "check", "--archives-only", "--repair")


def test_verify_data_repair_keeps_a_chunk_that_fails_to_re_read(archivers, request, monkeypatch):
    # --verify-data --repair deletes a chunk only after its content failed to verify twice. if the
    # second read fails outright, we did not see the content again, so the chunk must stay: this is
    # exactly how a flaky disk would otherwise talk borg into throwing data away, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    chunk_id = file_content_chunk_id(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        entry = repository.chunks[chunk_id]
        corrupt_chunk_on_disk(repository, chunk_id)
    pack_name = bin_to_hex(entry.pack_id)
    # fail reads of exactly this object, and only from the second one on (a bad spot in the pack
    # that the first read still got through): the first read returns the corrupted content, so the
    # chunk lands in the defect list, and the re-read that would confirm it fails. matching on the
    # object's full range leaves the pack's header scan (a short read at the same offset) working,
    # so rebuilding the chunk index from the packs still succeeds.
    make_store_reads_fail(
        monkeypatch,
        lambda name, offset, size: (
            object_name(name) == pack_name and offset == entry.obj_offset and size == entry.obj_size
        ),
        after=1,
    )

    output = cmd(archiver, "check", "--repair", "--verify-data", "--archives-only", exit_code=0)
    assert "not deleted, could not be re-read" in output
    with Repository(archiver.repository_location, exclusive=True) as repository:
        assert chunk_id in repository.chunks  # the chunk is still there


def test_find_lost_archives_skips_unreadable_chunk(archivers, request, monkeypatch):
    # the --find-lost-archives scan only looks for archive metadata, so skipping an unreadable
    # chunk can at worst miss a lost archive - it never drops data, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    make_pack_unreadable(monkeypatch, pack_name_of(archiver, file_content_chunk_id(archiver)))

    output = cmd(archiver, "check", "--archives-only", "--find-lost-archives", exit_code=1)
    assert "Skipping unreadable chunk" in output


def test_unreadable_archives_listing_is_not_an_empty_repository(archivers, request, monkeypatch):
    # a namespace listing that fails must not look like "the namespace is empty" - that would make
    # e.g. repo-list report a repository with no archives at all, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    make_namespace_listing_fail(monkeypatch, "archives")
    with pytest.raises(Repository.StoreReadError):  # local (not forked): the Error propagates
        cmd(archiver, "repo-list")


def test_check_repair_stops_at_unreadable_archive_metadata(archivers, request, monkeypatch):
    # a bad spot inside an otherwise readable pack: the chunk index still rebuilds from the pack's
    # headers, so --repair gets as far as the archive itself - and must stop there rather than
    # rewrite the archive around metadata it never read, refs #3509.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        archive_id = archive.id
        entry = repository.chunks[archive_id]
    pack_name = bin_to_hex(entry.pack_id)
    # fail reads of the archive metadata object only; the short header reads at the same offset
    # (and every other object in the pack) keep working.
    state = make_store_reads_fail(
        monkeypatch,
        lambda name, offset, size: (
            object_name(name) == pack_name and offset == entry.obj_offset and size == entry.obj_size
        ),
    )
    with pytest.raises(Repository.StoreReadError):  # local (not forked): the Error propagates
        cmd(archiver, "check", "--archives-only", "--repair")

    # the archive is untouched: once it reads again, it is still there and still checks out.
    state["failing"] = False
    assert "archive1" in cmd(archiver, "repo-list")
    cmd(archiver, "check", exit_code=0)
