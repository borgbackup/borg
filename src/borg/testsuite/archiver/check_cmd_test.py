import errno
import gc
from pathlib import Path
import re
import shutil
import struct
import weakref
from unittest.mock import patch

import pytest

from ...crypto.key import store_hash, STORE_HASH_NAME
from ... import archive as archive_module
from ...archive import Archive, ArchiveChecker, ChunkBuffer
from ...cache import (
    Cache,
    CorruptChunkIndexFragment,
    chunkindex_is_invalid,
    delete_chunkindex_from_repo,
    list_chunkindex_hashes,
    read_chunkindex_from_repo,
    write_chunkindex_invalid,
)
from ...crypto.key import RepositoryKeyInfoMissing
from ...constants import *  # NOQA
from ...helpers import bin_to_hex, hex_to_bin, CommandError, CorruptPack, Error, sig_int
from ...helpers import BackupDamagedChunksError
from ...helpers.passphrase import PassphraseWrong
from ...hashindex import ChunkIndex
from ...item import Item
from ...manifest import Archives, Manifest
from ...repoobj import RepoObj
from ...repository import PackReader, PackTracker, Repository
from .. import changedir
from ..repoobj_test import DATA_SIZE_OFFSET
from ..repository_test import fchunk, corrupt_chunk_on_disk
from . import (
    cmd,
    src_file,
    create_src_archive,
    create_regular_file,
    open_archive,
    open_repository,
    generate_archiver_tests,
    KeyedRepository,
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
    with KeyedRepository(archiver.repository_path, exclusive=True) as repository:
        orig_hash = repository.store.hash
        pack_checks = []

        def hash_then_interrupt(key, **kwargs):
            result = orig_hash(key, **kwargs)
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
        assert len(PackTracker.load(repository)) == 1  # the pack checked before the break persisted

    # a partial check resumes from the saved record (the one pack checked before the interrupt).
    output = cmd(archiver, "check", "-v", "--repository-only", "--max-duration=600", exit_code=0)
    assert "1 pack check results on record" in output

    # archive check: interrupt verify_data after 3 chunks.
    with Repository(archiver.repository_path, exclusive=True) as repository:
        orig_get_many = repository.get_many
        chunks_read = 0

        def get_many_then_interrupt(ids, **kwargs):
            nonlocal chunks_read
            for data in orig_get_many(ids, **kwargs):
                chunks_read += 1
                if chunks_read == 3:  # trip mid-loop, after 3 chunks
                    sig_int._sig_int_triggered = True
                yield data

        monkeypatch.setattr(repository, "get_many", get_many_then_interrupt)
        try:
            with pytest.raises(Error, match="Got Ctrl-C"):
                ArchiveChecker().check(repository, verify_data=True, sort_by="ts", format="{archive} {time} {id}")
        finally:
            sig_int._sig_int_triggered = False
        # verify_data breaks at the chunk it interrupted on, and the skipped scans read nothing more.
        assert chunks_read == 3

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


def test_check_repair_interrupt_during_index_rebuild(archivers, request, monkeypatch):
    """A --repair archive check rebuilds the chunk index before it reads any archive. A Ctrl-C stops that
    rebuild and raises, the stored index keeps the fragments it had, and a second --repair completes the
    check, #10042."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)  # produces several packs

    orig_iter_headers = PackReader.iter_headers
    packs_read = []

    def iter_headers_then_interrupt(self, **kwargs):
        packs_read.append(self.pack_id)
        yield from orig_iter_headers(self, **kwargs)
        sig_int._sig_int_triggered = True  # one Ctrl-C after the first pack was walked

    with Repository(archiver.repository_path, exclusive=True) as repository:
        assert len(repository.store_list("packs")) > 1  # there is a pack boundary to stop at
        index_before = set(list_chunkindex_hashes(repository))
        monkeypatch.setattr(PackReader, "iter_headers", iter_headers_then_interrupt)
        try:
            with pytest.raises(Error, match="Got Ctrl-C"):
                ArchiveChecker().check(repository, repair=True, sort_by="ts", format="{archive} {time} {id}")
        finally:
            sig_int._sig_int_triggered = False  # reset the global flag for the following tests
        # restore the real method; monkeypatch.undo() would also drop the autouse env (BORG_TESTONLY_WEAKEN_KDF).
        monkeypatch.setattr(PackReader, "iter_headers", orig_iter_headers)
        assert len(packs_read) == 1  # the rebuild stopped at the pack boundary
        assert set(list_chunkindex_hashes(repository)) == index_before  # no partial index was stored

    # the repo is as it was before the interrupt, so a second --repair completes the check.
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_check_repair_finish_completes_after_interrupt(archiver, monkeypatch):
    """finish() runs with sig_int already set, #9850: it re-reads the packs the repair wrote and stores an
    index that matches them, so the invalid marker is cleared and a plain check passes afterwards."""
    # local-only: this patches in-process internals, including check_cmd_setup's small ChunkBuffer.BUFFER_SIZE.
    # With the default buffer size an archive's item metadata is a single chunk, which the repair rewrites to
    # the same id, so it stores nothing and finish() has no written pack to re-read.
    check_cmd_setup(archiver)  # two archives

    orig_create = Archives.create
    orig_finish = ArchiveChecker.finish
    orig_iter_headers = PackReader.iter_headers
    in_finish = False
    packs_read_in_finish = []
    checker = ArchiveChecker()

    def create_then_interrupt(self, *args, **kwargs):
        orig_create(self, *args, **kwargs)
        sig_int._sig_int_triggered = True  # one Ctrl-C after the first archive was rebuilt

    def finish_spy(self):
        nonlocal in_finish
        in_finish = True
        try:
            return orig_finish(self)
        finally:
            in_finish = False

    def count_packs_read(self, **kwargs):
        if in_finish:
            packs_read_in_finish.append(self.pack_id)
        return orig_iter_headers(self, **kwargs)

    monkeypatch.setattr(Archives, "create", create_then_interrupt)
    monkeypatch.setattr(ArchiveChecker, "finish", finish_spy)
    monkeypatch.setattr(PackReader, "iter_headers", count_packs_read)
    try:
        with Repository(archiver.repository_path, exclusive=True) as repository:
            with pytest.raises(Error, match="Got Ctrl-C"):
                checker.check(repository, repair=True, sort_by="ts", format="{archive} {time} {id}")
            pack_count = len(repository.store_list("packs"))
    finally:
        sig_int._sig_int_triggered = False  # reset the global flag for the following tests
    # restore the real methods; monkeypatch.undo() would also drop the autouse env (BORG_TESTONLY_WEAKEN_KDF).
    monkeypatch.setattr(Archives, "create", orig_create)
    monkeypatch.setattr(ArchiveChecker, "finish", orig_finish)
    monkeypatch.setattr(PackReader, "iter_headers", orig_iter_headers)

    # the repair stored re-packed item metadata chunks, so finish() re-reads the packs it wrote.
    assert checker.chunks_modified is True
    assert set(packs_read_in_finish) == checker.written_packs
    assert 0 < len(packs_read_in_finish) < pack_count  # not every pack of the repository
    with Repository(archiver.repository_path, exclusive=True) as repository:
        assert not chunkindex_is_invalid(repository)  # finish() reached delete_chunkindex_invalid()
    cmd(archiver, "check", exit_code=0)  # the stored index matches the packs


def test_check_interrupt_within_archive(archivers, request, monkeypatch):
    """A check without --repair only reads the archives, so a Ctrl-C stops it after the current archive
    item, #10042."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    item_count = len(cmd(archiver, "list", "archive1", exit_code=0).splitlines())
    assert item_count > 1  # there is an item to stop before

    orig_add = ChunkBuffer.add
    items_read = 0

    def add_then_interrupt(self, item):
        nonlocal items_read
        items_read += 1
        sig_int._sig_int_triggered = True  # one Ctrl-C after the first item
        return orig_add(self, item)

    monkeypatch.setattr(ChunkBuffer, "add", add_then_interrupt)
    try:
        with Repository(archiver.repository_path, exclusive=True) as repository:
            with pytest.raises(Error, match="Got Ctrl-C"):
                ArchiveChecker().check(repository, sort_by="ts", format="{archive} {time} {id}")
    finally:
        sig_int._sig_int_triggered = False  # reset the global flag for the following tests
    # restore the real method; monkeypatch.undo() would also drop the autouse env (BORG_TESTONLY_WEAKEN_KDF).
    monkeypatch.setattr(ChunkBuffer, "add", orig_add)
    assert items_read == 1  # the check stopped within the first archive

    cmd(archiver, "check", exit_code=0)  # the interrupted check changed nothing


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

    def hash_then_interrupt(self, key, **kwargs):
        result = orig_hash(self, key, **kwargs)
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
                repository.delete(killed_chunk.id, validate=None)
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
                repository.delete(chunk_id, validate=None)
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
                repository.delete(killed_id, validate=None)
                break
    assert killed_id is not None

    output = cmd(archiver, "check", exit_code=1)
    assert "The following chunks are missing in the repository:" in output
    assert bin_to_hex(killed_id) in output
    assert f"only the first {cap} files are listed" in output  # the remaining referencing files are truncated


def delete_first_item_chunk(archiver):
    """Set up two archives and delete the first item metadata chunk of archive1."""
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.item_ids[0], validate=None)


def test_missing_archive_item_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    delete_first_item_chunk(archiver)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_archive_metadata(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.id, validate=None)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


# checker_builds: per index build in ArchiveChecker, whether repository.chunks was loaded at that time.
# A full check without --repair uses the index the repository check loaded. --repair builds once: finish()
# re-reads only the packs the repair wrote, see test_repair_finish_reads_only_the_packs_put_wrote.
@pytest.mark.parametrize(
    "args, exit_code, checker_builds",
    [(["--archives-only"], 1, [False]), ([], 1, []), (["--repair"], 0, [False])],
    ids=["archives-only", "full", "repair"],
)
def test_check_holds_a_single_chunk_index(archiver, monkeypatch, args, exit_code, checker_builds):
    """check has at most one chunk index in memory: the repository and the checker use the same index."""
    # local-only: this patches in-process archive and repository internals.
    # with an item metadata chunk missing, --repair stores a new item metadata stream.
    delete_first_item_chunk(archiver)

    loaded_at_build = []
    built = []  # weak references to the indexes the checker built
    alive_at_build = []  # per index build in ArchiveChecker: whether an index it built before is still alive
    real_build = archive_module.build_chunkindex_from_repo

    def build_chunkindex_from_repo(repository, **kwargs):
        loaded_at_build.append(repository.is_chunk_index_loaded)
        gc.collect()  # PyPy frees objects only on collection
        alive_at_build.append(any(ref() is not None for ref in built))
        chunks = real_build(repository, **kwargs)
        built.append(weakref.ref(chunks))
        return chunks

    repository_builds = 0  # index builds by the Repository.chunks property
    real_chunks = Repository.chunks

    def chunks(self):
        nonlocal repository_builds
        if not self.is_chunk_index_loaded:
            repository_builds += 1
        return real_chunks.fget(self)

    same_index = []  # per rebuild_archives call: whether repository.chunks is the checker's index
    real_rebuild_archives = ArchiveChecker.rebuild_archives

    def rebuild_archives(self, **kwargs):
        same_index.append(self.repository.chunks is self.chunks)
        return real_rebuild_archives(self, **kwargs)

    monkeypatch.setattr(archive_module, "build_chunkindex_from_repo", build_chunkindex_from_repo)
    monkeypatch.setattr(Repository, "chunks", property(chunks, real_chunks.fset))
    monkeypatch.setattr(ArchiveChecker, "rebuild_archives", rebuild_archives)
    cmd(archiver, "check", *args, exit_code=exit_code)

    assert loaded_at_build == checker_builds
    assert alive_at_build == [False] * len(checker_builds)
    assert same_index == [True]
    assert repository_builds == 0
    if "--repair" in args:
        cmd(archiver, "check", exit_code=0)


@pytest.mark.parametrize("index", ["index", "no-index", "marker"])
def test_check_without_repair_stores_no_chunk_index(archivers, request, index):
    """check without --repair does not store a chunk index.

    The archive has an item metadata chunk missing: the checker re-chunks its item metadata stream into
    chunks the repository does not have. With index/ fragments, the check leaves them as they are. Without
    them, the checker builds the index from the packs and does not store it. With the invalid marker set,
    that build deletes the fragments and the marker, and the check does not store its index either.
    """
    archiver = request.getfixturevalue(archivers)
    delete_first_item_chunk(archiver)
    with open_repository(archiver) as repository:
        chunk_ids_before = {chunk_id for chunk_id, _ in repository.chunks.iteritems()}
        if index == "no-index":
            delete_chunkindex_from_repo(repository)
        index_before = list_chunkindex_hashes(repository)
        assert bool(index_before) is (index != "no-index")
        if index == "marker":
            write_chunkindex_invalid(repository)

    cmd(archiver, "check", "--archives-only", exit_code=1)
    cmd(archiver, "check", exit_code=1)

    with open_repository(archiver) as repository:
        # check the stored state before .chunks rebuilds the index and close() stores it.
        assert list_chunkindex_hashes(repository) == (index_before if index == "index" else [])
        assert not chunkindex_is_invalid(repository)
        assert {chunk_id for chunk_id, _ in repository.chunks.iteritems()} == chunk_ids_before


@pytest.mark.parametrize("repair", [False, True], ids=["check", "repair"])
def test_check_with_buffered_chunks(archiver, repair):
    """ArchiveChecker.check() stores the chunks the pack writer still buffers before it uses the index."""
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        data = b"buffered chunk"
        chunk_id = archive.key.id_hash(data)
        repository.put(chunk_id, archive.repo_objs.format(chunk_id, {}, data, ro_type=ROBJ_FILE_STREAM))
        assert repository.chunks[chunk_id].flags & ChunkIndex.F_PENDING
        ArchiveChecker().check(repository, verify_data=True, repair=repair, sort_by="ts", format="{archive}")
    with open_repository(archiver) as repository:
        assert repository.get(chunk_id)


def test_check_repair_verify_data_aborted_marks_the_index_invalid(archiver, monkeypatch):
    """A --repair --verify-data check that stops after a delete leaves the chunk index marked invalid.

    delete() rewrites the pack of the defect chunk, so the index/ fragments point its other chunks at a
    pack that is gone. The marker makes the next use rebuild the index from the packs.
    """
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                defect_id = item.chunks[-1].id
                break
        corrupt_chunk_on_disk(repository, defect_id)
        chunk_ids = {chunk_id for chunk_id, _ in repository.chunks.iteritems()} - {defect_id}

    def rebuild_archives(self, **kwargs):
        raise Error("stopped before finish()")

    with monkeypatch.context() as m:
        m.setattr(ArchiveChecker, "rebuild_archives", rebuild_archives)
        with open_repository(archiver) as repository:
            with pytest.raises(Error, match="stopped before finish"):
                ArchiveChecker().check(repository, verify_data=True, repair=True, sort_by="ts", format="{archive}")

    with open_repository(archiver) as repository:
        # no .chunks access or get() here: rebuilding the index would clear the marker.
        assert chunkindex_is_invalid(repository)
        # the index/ fragments are still there and point chunks at the pack delete() removed.
        packs = {info.name for info in repository.store_list("packs")}
        stale = set()
        for hash in list_chunkindex_hashes(repository):
            fragment = read_chunkindex_from_repo(repository, hash)
            stale |= {chunk_id for chunk_id, entry in fragment.items() if bin_to_hex(entry.pack_id) not in packs}
        assert stale & chunk_ids
    cmd(archiver, "check", "--repair", exit_code=0)
    with open_repository(archiver) as repository:
        assert not chunkindex_is_invalid(repository)
        # the stored index finds every other chunk.
        for chunk_id in chunk_ids:
            repository.get(chunk_id)


def test_check_repair_stopped_in_the_index_store_marks_the_index_invalid(archiver, monkeypatch):
    """A --repair check that stops while finish() stores the chunk index leaves it marked invalid.

    The repair stored a new item metadata stream and new archive metadata, which the index/ fragments do not
    have. The marker makes the next use rebuild the index from the packs, which have them.
    """
    delete_first_item_chunk(archiver)

    def write_chunkindex_to_repo(repository, chunks, **kwargs):
        raise Error("stopped in the index store")

    with monkeypatch.context() as m:
        m.setattr(archive_module, "write_chunkindex_to_repo", write_chunkindex_to_repo)
        with open_repository(archiver) as repository:
            with pytest.raises(Error, match="stopped in the index store"):
                ArchiveChecker().check(repository, repair=True, sort_by="ts", format="{archive}")

    with open_repository(archiver) as repository:
        assert chunkindex_is_invalid(repository)
        assert list_chunkindex_hashes(repository)
    cmd(archiver, "check", exit_code=0)
    with open_repository(archiver) as repository:
        assert not chunkindex_is_invalid(repository)


def test_check_repair_clears_the_invalid_marker(archivers, request):
    """check --repair clears the invalid marker when it stores the index, also without index/ fragments before."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    with open_repository(archiver) as repository:
        delete_chunkindex_from_repo(repository)
        write_chunkindex_invalid(repository)
    cmd(archiver, "check", "--repair", exit_code=0)
    with open_repository(archiver) as repository:
        assert not chunkindex_is_invalid(repository)
        assert list_chunkindex_hashes(repository)
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
        repository.delete(archive.id, validate=None)
    archive_id_hex = bin_to_hex(archive.id)
    output = cmd(archiver, "check", "-v", "--archives-only", "--format", "{archive} {comment}", exit_code=1)
    # the archive directory entry has no name for it, only the id, which {archive} {comment} would not show.
    # the timestamp uses the same style as the formatter would produce, e.g. "Thu, 1970-01-01 00:00:00 +0000":
    assert re.search(r"Analyzing archive archive-does-not-exist \w{3}, \d{4}-\d{2}-\d{2} ", output)
    assert f"{archive_id_hex} (1/2)" in output
    assert f"Archive metadata block {archive_id_hex} is missing!" in output
    assert "Analyzing archive archive2" in output  # the intact archive still uses the given format


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
    # a read-only check reports the corrupt index, then the archives check aborts: it needs the index.
    if archiver.FORK_DEFAULT:
        cmd(archiver, "check", exit_code=CorruptChunkIndexFragment.exit_mcode)
    else:
        with pytest.raises(CorruptChunkIndexFragment):
            cmd(archiver, "check")
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "rebuilt" in output.lower()
    # item 6: repair persisted a fresh index instead of leaving it for a slow rebuild on the next
    # access. confirm the on-disk index exists and every fragment is intact.
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        index_infos = list(repository.store_list("index"))
        assert index_infos  # a fresh index was persisted
        for info in index_infos:  # each fragment's content still matches its store hash name
            assert repository.store.hash(f"index/{info.name}", algorithm=STORE_HASH_NAME) == info.name
    cmd(archiver, "check", exit_code=0)  # the repository is consistent again
    assert "archive1" in cmd(archiver, "repo-list")  # and remains usable


def tamper_object_keeping_pack_name(repository):
    """Flip a byte in the metadata slot of the 2nd object of a pack holding more than 2 objects, and store
    the pack under the store hash of its new content, so its content still matches its name. Corrupt
    every index fragment. Return the ids of the changed object and of the object after it.
    """
    by_pack = {}
    for chunk_id, entry in repository.chunks.iteritems():
        by_pack.setdefault(entry.pack_id, []).append((entry.obj_offset, chunk_id))
    pack_id, objects = next((p, sorted(o)) for p, o in by_pack.items() if len(o) > 2)
    (offset, tampered_id), (_, neighbour_id) = objects[1], objects[2]
    old_name = "packs/" + bin_to_hex(pack_id)
    data = corrupt(repository.store_load(old_name), offset + RepoObj.obj_header.size)
    repository.store_store("packs/" + store_hash(data).hexdigest(), data)
    repository.store_delete(old_name)
    for info in repository.store_list("index"):
        name = f"index/{info.name}"
        repository.store_store(name, corrupt(repository.store_load(name), 0))
    return tampered_id, neighbour_id


def test_check_repository_only_repair_validates_index_rebuild(archivers, request):
    """--repository-only --repair leaves an object that fails validation out of the index (#9901)."""
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects the store directly")
    check_cmd_setup(archiver)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        tampered_id, neighbour_id = tamper_object_keeping_pack_name(repository)
    output = cmd(archiver, "check", "-v", "--repository-only", "--repair", exit_code=1)
    assert "does not authenticate" in output
    assert "continuing at the object at offset" in output
    assert "index rebuilt without pack byte range(s) it could not authenticate" in output
    with KeyedRepository(archiver.repository_location) as repository:
        assert tampered_id not in repository.chunks
        assert neighbour_id in repository.chunks


def test_check_repository_only_repair_aborts_on_wrong_passphrase(archivers, request, monkeypatch):
    """--repair aborts on a wrong passphrase (#9901)."""
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects the store directly")
    check_cmd_setup(archiver)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        tamper_object_keeping_pack_name(repository)
    monkeypatch.setenv("BORG_PASSPHRASE", "definitely-not-the-passphrase")
    with pytest.raises(PassphraseWrong):
        cmd(archiver, "check", "-v", "--repository-only", "--repair")


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
    # the attacker would hope that the search for lost archives picks the fake archive up, but
    # borg notices that the object has the wrong ro_type.
    cmd(archiver, "check", "--repair", "--find-lost-archives", "--debug", exit_code=0)
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
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        key = b"01234567890123456789012345678901"
        chunk = fchunk(b"xxxx", chunk_id=key)
        repository.put(key, chunk)
        repository.flush()  # make the put durable before close()/the check below
    cmd(archiver, "check", "-v", exit_code=0)  # check does not deal with orphans anymore


@pytest.mark.parametrize("damaged_field", ["magic", "data_size"])
def test_repair_resyncs_pack_with_corrupt_object_header(archivers, request, damaged_field):
    """--repair rebuilds the chunks index from a pack whose object header is damaged.

    A damaged header loses the object boundaries, so the rebuild scans for the next object that
    authenticates and continues there. Authenticating needs the key, which --repair reads first.
    A damaged data_size leaves the header parseable, so the rebuild catches it against the csize
    in the authenticated metadata.
    """
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects the store directly")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)

    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        # damage the header of the second object of a pack that holds more than two.
        by_pack = {}
        for chunk_id, entry in repository.chunks.items():
            by_pack.setdefault(entry.pack_id, []).append((entry.obj_offset, chunk_id))
        pack_id, objs = next((p, sorted(o)) for p, o in by_pack.items() if len(o) > 2)
        damaged_offset, damaged_id = objs[1]
        next_offset, next_id = objs[2]
        key = "packs/" + bin_to_hex(pack_id)
        pack = repository.store_load(key)
        if damaged_field == "magic":
            pack = corrupt(pack, damaged_offset)
        else:
            hdr_size = RepoObj.obj_header.size
            hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(pack[damaged_offset : damaged_offset + hdr_size]))
            # a data_size that keeps the object inside the pack, so the header still parses.
            pos = damaged_offset + DATA_SIZE_OFFSET
            pack = pack[:pos] + struct.pack("<I", hdr.data_size + 16) + pack[pos + 4 :]
        repository.store_store(key, pack)

    output = cmd(archiver, "check", "--repair", "--debug", exit_code=0)
    problem = {"magic": "no object header", "data_size": "object does not authenticate"}[damaged_field]
    assert f"{problem} at offset {damaged_offset}" in output
    assert f"continuing at the object at offset {next_offset}" in output  # the rebuild resumed at the next object
    # the resync dropped an object, so the summary reports a problem.
    assert "Archive consistency check complete, problems found." in output
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert damaged_id not in repository.chunks  # the damaged object can not be read back, so it is not indexed
        assert repository.chunks[next_id].obj_offset == next_offset  # the one after it is
        # the damaged object is the only one of its pack the rebuild lost.
        for _, chunk_id in objs:
            assert (chunk_id in repository.chunks) == (chunk_id != damaged_id)
    cmd(archiver, "list", "archive1", exit_code=0)  # the archives are readable
    # the pack still holds the damaged bytes, so it keeps failing the store-level check: a pack is
    # named by the store hash of its content. Repairing that is repository-level repair (#10026).
    output = cmd(archiver, "check", "--repository-only", exit_code=1)
    assert f"Store object packs/{bin_to_hex(pack_id)} is corrupted" in output


def test_check_repair_validates_index_rebuild(archivers, request):
    """--repair leaves an object that fails validation out of the index and keeps the object after it (#9901)."""
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects the store directly")
    check_cmd_setup(archiver)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        tampered_id, neighbour_id = tamper_object_keeping_pack_name(repository)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "does not authenticate" in output
    assert "continuing at the object at offset" in output
    assert "index rebuilt without pack byte range(s) it could not authenticate" in output
    assert "Archive consistency check complete, problems found." in output
    with KeyedRepository(archiver.repository_location) as repository:
        assert tampered_id not in repository.chunks
        assert neighbour_id in repository.chunks


@pytest.mark.parametrize("mode", [[], ["--repository-only"], ["--archives-only"]])
def test_check_aborts_on_wrong_passphrase(archivers, request, monkeypatch, mode):
    """check always needs the key: it aborts on a wrong passphrase, before it checks anything."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    monkeypatch.setenv("BORG_PASSPHRASE", "definitely-not-the-passphrase")
    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "check", "-v", *mode, exit_code=PassphraseWrong().exit_code)
        assert "Passphrase supplied in BORG_PASSPHRASE" in output
        assert "repository check" not in output  # the repository check did not start
        assert "archive consistency check" not in output  # nor the archives check
    else:
        with pytest.raises(PassphraseWrong):
            cmd(archiver, "check", "-v", *mode)


@pytest.mark.parametrize("mode", [[], ["--repository-only"], ["--archives-only"]])
def test_check_aborts_without_key_info(archivers, request, mode):
    """check always needs the key: it refuses a repository whose config has no key info."""
    archiver = request.getfixturevalue(archivers)
    # a repository created via the Python API has no key, so its config has no key info.
    with Repository(archiver.repository_location, exclusive=True, create=True):
        pass
    if archiver.FORK_DEFAULT:
        expected_ec = RepositoryKeyInfoMissing("repo").exit_code
        output = cmd(archiver, "check", "-v", *mode, exit_code=expected_ec)
        assert "has no key information in its config" in output
        assert "repository check" not in output  # the repository check did not start
        assert "archive consistency check" not in output  # nor the archives check
    else:
        with pytest.raises(RepositoryKeyInfoMissing):
            cmd(archiver, "check", "-v", *mode)


def test_repo_list_aborts_cleanly_on_corrupt_pack(archivers, request):
    """A command rebuilding the chunks index over a corrupt object header aborts with a hint (#10122)."""
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("inspects the store directly")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)

    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        # damage the header of the 2nd object of a pack holding more than 2, so the walk aborts mid-pack.
        by_pack = {}
        for entry in repository.chunks.values():
            by_pack.setdefault(entry.pack_id, []).append(entry.obj_offset)
        pack_id, offsets = next((p, sorted(o)) for p, o in by_pack.items() if len(o) > 2)
        damaged_offset = offsets[1]
        key = "packs/" + bin_to_hex(pack_id)
        repository.store_store(key, corrupt(repository.store_load(key), damaged_offset))
        # drop the index fragments, so the next command has to read the pack headers.
        delete_chunkindex_from_repo(repository)

    # fork: only a subprocess runs borg's top-level error handler, which turns the Error into a rc.
    output = cmd(archiver, "repo-list", fork=True, exit_code=CorruptPack.exit_mcode)
    assert "Traceback" not in output
    assert f"no object header at offset {damaged_offset} (pack corruption)" in output
    assert "borg check --repair" in output

    # a check without --repair passes a validator too, so it resyncs past the damaged header and
    # runs to the end of its diagnosis, reporting the object the resync skipped as missing. Which
    # object that is depends on how the pack was filled, so only the last line is asserted here.
    output = cmd(archiver, "check", fork=True, exit_code=1)
    assert "Traceback" not in output
    assert f"no object header at offset {damaged_offset}" in output
    assert "Archive consistency check complete, problems found." in output

    # --repair passes a validator, so it resyncs past the damaged header instead of aborting.
    # TODO: it does not rewrite the pack yet, so a later rebuild hits the same header again.
    cmd(archiver, "check", "--repair", exit_code=0)


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
        checker.repo_objs = RepoObj(checker.key)
        checker.manifest = Manifest.load(repository, key=checker.key)
        checker.chunks = repository.chunks
        checker.chunks_modified = True

        # a chunk re-added during repair, buffered in the pack writer:
        key = b"01234567890123456789012345678901"
        repository.put(key, fchunk(b"repaired", chunk_id=key))
        assert repository._pack_writer._pieces

        checker.finish()
        assert not repository._pack_writer._pieces  # finish() stored it


def record_finish_walks(monkeypatch):
    """Return a list that collects the id of every pack whose object headers finish() walks.

    ArchiveChecker.verify_written_packs walks a pack with PackReader.iter_headers.
    """
    walked = []
    in_finish = False
    real_finish = ArchiveChecker.finish
    real_iter_headers = PackReader.iter_headers

    def finish(self):
        nonlocal in_finish
        in_finish = True
        try:
            return real_finish(self)
        finally:
            in_finish = False

    def iter_headers(self, *args, **kwargs):
        if in_finish:
            walked.append(self.pack_id)
        return real_iter_headers(self, *args, **kwargs)

    monkeypatch.setattr(ArchiveChecker, "finish", finish)
    monkeypatch.setattr(PackReader, "iter_headers", iter_headers)
    return walked


def list_packs(archiver):
    with Repository(archiver.repository_location, exclusive=True) as repository:
        return {info.name for info in repository.store_list("packs")}


def put_objects_in_one_pack(archiver, contents):
    """Store an encrypted repo object per contents entry, all in one new pack no archive references.

    Returns the object ids, in pack order, and the pack id.
    """
    with Repository(archiver.repository_location, exclusive=True) as repository:
        manifest = Manifest.load(repository)
        ids = []
        for data in contents:
            chunk_id = manifest.key.id_hash(data)
            repository.put(chunk_id, manifest.repo_objs.format(chunk_id, {}, data, ro_type=ROBJ_FILE_STREAM))
            ids.append(chunk_id)
        repository.flush()
        entries = [repository.chunks[chunk_id] for chunk_id in ids]
    assert {entry.pack_id for entry in entries} == {entries[0].pack_id}
    assert [entry.obj_offset for entry in entries] == sorted(entry.obj_offset for entry in entries)
    return ids, entries[0].pack_id


def test_repair_finish_reads_only_the_rewritten_pack(archiver, monkeypatch):
    """--verify-data --repair removes a defect chunk; finish() re-reads only the pack delete() wrote."""
    # local-only: this patches in-process archive and repository internals.
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "2")  # many packs, so a full walk would be noticed
    check_cmd_setup(archiver)
    # a defect chunk that no archive references, so the check after the repair finds nothing missing.
    # delete() rewrites its pack, keeping the other object in it (the bystander).
    (bystander_id, defect_id), pack_id = put_objects_in_one_pack(archiver, [b"bystander", b"defect"])
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        corrupt_chunk_on_disk(repository, defect_id)
    packs_before = list_packs(archiver)
    assert len(packs_before) > 10

    walked = record_finish_walks(monkeypatch)
    # the BUFFER_SIZE check_cmd_setup used: rebuild_archives re-chunks the item metadata into the same
    # chunks, so it stores nothing and the rewritten pack is the only pack the repair writes.
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        output = cmd(archiver, "check", "--repair", "--verify-data", "--info", exit_code=0)
    assert f"{bin_to_hex(defect_id)}, integrity error" in output
    assert "Re-reading 1 pack(s) written by the repair." in output

    new_packs = list_packs(archiver) - packs_before
    assert packs_before - list_packs(archiver) == {bin_to_hex(pack_id)}
    assert len(new_packs) == 1
    assert [bin_to_hex(pack_id) for pack_id in walked] == list(new_packs)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert defect_id not in repository.chunks
        assert bin_to_hex(repository.chunks[bystander_id].pack_id) in new_packs
    cmd(archiver, "check", exit_code=0)


def test_repair_finish_reads_no_pack_after_deleting_a_whole_pack(archiver, monkeypatch):
    """--verify-data --repair removes a defect chunk that is alone in its pack; finish() re-reads no pack.

    delete() drops the whole pack and writes no new one, so the repair wrote no pack.
    """
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    (defect_id,), pack_id = put_objects_in_one_pack(archiver, [b"defect"])
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        corrupt_chunk_on_disk(repository, defect_id)
    packs_before = list_packs(archiver)

    walked = record_finish_walks(monkeypatch)
    findings = record_verify_findings(monkeypatch)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):  # see test_repair_finish_reads_only_the_rewritten_pack
        output = cmd(archiver, "check", "--repair", "--verify-data", "--info", exit_code=0)
    assert f"{bin_to_hex(defect_id)}, integrity error" in output
    assert findings == [False]
    assert "pack(s) written by the repair." not in output
    assert walked == []
    assert list_packs(archiver) == packs_before - {bin_to_hex(pack_id)}
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert defect_id not in repository.chunks
    cmd(archiver, "check", exit_code=0)


def test_repair_finish_reads_only_the_packs_put_wrote(archiver, monkeypatch):
    """--repair re-stores a missing item metadata chunk; finish() re-reads only the packs put() wrote."""
    # local-only: this patches in-process archive and repository internals.
    # a pack per object, so every put() after the first returns the pack the background store-thread
    # stored before it.
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "1")
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.item_ids[0], validate=None)
    packs_before = list_packs(archiver)

    walked = record_finish_walks(monkeypatch)
    findings = record_verify_findings(monkeypatch)
    cmd(archiver, "check", "--repair", exit_code=0)
    assert findings == [False]

    new_packs = list_packs(archiver) - packs_before
    assert new_packs
    assert sorted(bin_to_hex(pack_id) for pack_id in walked) == sorted(new_packs)  # each one once
    cmd(archiver, "check", exit_code=0)


def test_repair_finish_reads_the_pack_its_flush_stores(archiver, monkeypatch):
    """finish() re-reads the pack its own flush stores, e.g. for chunks buffered when a Ctrl-C stopped the repair."""
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    walked = record_finish_walks(monkeypatch)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        checker = ArchiveChecker()
        checker.repair = True
        checker.repository = repository
        checker.key = checker.make_key(repository)
        checker.repo_objs = RepoObj(checker.key)
        checker.manifest = Manifest.load(repository, key=checker.key)
        checker.chunks = repository.chunks
        checker.chunks_modified = True
        data = b"repaired"
        chunk_id = checker.key.id_hash(data)
        assert repository.put(chunk_id, checker.repo_objs.format(chunk_id, {}, data, ro_type=ROBJ_FILE_STREAM)) is None
        checker.finish()
        assert not checker.error_found
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert walked == [repository.chunks[chunk_id].pack_id]


def test_repair_finish_reads_a_rewritten_pack_no_index_entry_names(archiver, monkeypatch):
    """finish() re-reads a pack delete() wrote, also when no index entry names that pack.

    The pack holds an object with a corrupt header, which the rebuild in check() drops, and a defect
    chunk, which --verify-data --repair deletes. compact_pack copies the dropped object's bytes (no
    index entry covers them) into the new pack, so the new pack exists, but no index entry points at it.
    """
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    (dropped_id, defect_id), pack_id = put_objects_in_one_pack(archiver, [b"dropped", b"defect"])
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        corrupt_chunk_on_disk(repository, defect_id)  # corrupts the payload, the header still validates
        key = "packs/" + bin_to_hex(pack_id)
        dropped = repository.chunks[dropped_id]
        repository.store_store(key, corrupt(repository.store_load(key), dropped.obj_offset))  # corrupts the magic
    packs_before = list_packs(archiver)

    walked = record_finish_walks(monkeypatch)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):  # see test_repair_finish_reads_only_the_rewritten_pack
        output = cmd(archiver, "check", "--archives-only", "--repair", "--verify-data", "--debug", exit_code=0)
    assert "no object header at offset 0" in output
    assert f"{bin_to_hex(defect_id)}, integrity error" in output

    assert packs_before - list_packs(archiver) == {bin_to_hex(pack_id)}
    new_packs = list_packs(archiver) - packs_before
    assert len(new_packs) == 1
    assert [bin_to_hex(pack_id) for pack_id in walked] == list(new_packs)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert not any(bin_to_hex(entry.pack_id) in new_packs for _, entry in repository.chunks.iteritems())


def test_repair_finish_accepts_a_superseded_duplicate_in_a_rewritten_pack(archiver, monkeypatch):
    """A superseded duplicate that delete() copies into the new pack is not a finding of finish().

    The pack holds an object with a corrupt header, two copies of one chunk and a defect chunk. The
    rebuild in check() drops the first object and indexes the second copy. compact_pack copies the bytes
    before the second copy, which no index entry covers, into the new pack: its search for superseded
    duplicates there stops at the corrupt header. So the new pack holds both copies, the index names
    only the second.
    """
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "4")  # the four objects below go into one pack
    (dropped_id, dup_id, _, defect_id), pack_id = put_objects_in_one_pack(
        archiver, [b"dropped", b"duplicate", b"duplicate", b"defect"]
    )
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        corrupt_chunk_on_disk(repository, defect_id)  # corrupts the payload, the header still validates
        key = "packs/" + bin_to_hex(pack_id)
        dropped = repository.chunks[dropped_id]
        repository.store_store(key, corrupt(repository.store_load(key), dropped.obj_offset))  # corrupts the magic

    walked = record_finish_walks(monkeypatch)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):  # see test_repair_finish_reads_only_the_rewritten_pack
        output = cmd(archiver, "check", "--archives-only", "--repair", "--verify-data", "--debug", exit_code=0)
    assert f"{bin_to_hex(defect_id)}, integrity error" in output
    assert "in a gap, keeping the remaining" in output
    assert len(walked) == 1
    assert "the chunks index does not match the pack" not in output
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        entry = repository.chunks[dup_id]
        assert entry.pack_id == walked[0]
        # the second copy: the first one starts where the dropped object ends.
        assert entry.obj_offset > dropped.obj_size
    cmd(archiver, "check", exit_code=0)


def record_verify_findings(monkeypatch, tamper=None):
    """Return a list that collects, per verify_written_packs call, whether that call found a problem.

    tamper(checker) runs right before the call. The problems found before it (e.g. the damage the
    repair fixed) stay recorded in checker.error_found, but do not count for the call.
    """
    findings = []
    real_verify = ArchiveChecker.verify_written_packs

    def verify_written_packs(self):
        if tamper is not None:
            tamper(self)
        error_found, self.error_found = self.error_found, False
        try:
            return real_verify(self)
        finally:
            findings.append(self.error_found)
            self.error_found = self.error_found or error_found

    monkeypatch.setattr(ArchiveChecker, "verify_written_packs", verify_written_packs)
    return findings


def test_repair_finish_fixes_a_wrong_index_entry_for_a_written_pack(archiver, monkeypatch):
    """finish() compares the written packs with their index entries, reports a difference and fixes it."""
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.item_ids[0], validate=None)

    tampered = {}

    def tamper(checker):
        # an index entry with a wrong offset, as a bug in the offset arithmetic would make one.
        pack_id = min(checker.written_packs)
        chunk_id, entry = next((cid, e) for cid, e in checker.chunks.iteritems() if e.pack_id == pack_id)
        checker.chunks[chunk_id] = entry._replace(obj_offset=entry.obj_offset + 1)
        tampered[chunk_id] = entry

    findings = record_verify_findings(monkeypatch, tamper)
    output = cmd(archiver, "check", "--repair", exit_code=0)
    assert findings == [True]
    ((chunk_id, entry),) = tampered.items()
    assert f"pack {bin_to_hex(entry.pack_id)}: the chunks index does not match the pack" in output
    assert "Indexed objects not in the pack: 1, objects in the pack with an unindexed chunk id: 1." in output
    assert "Archive consistency check complete, problems found." in output

    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        stored = repository.chunks[chunk_id]
        assert (stored.pack_id, stored.obj_offset, stored.obj_size) == (entry.pack_id, entry.obj_offset, entry.obj_size)
    cmd(archiver, "check", exit_code=0)


def test_repair_finish_reports_a_missing_written_pack(archiver, monkeypatch):
    """finish() reports a written pack that is gone and removes the index entries that name it."""
    # local-only: this patches in-process archive and repository internals.
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.item_ids[0], validate=None)

    removed = []

    def tamper(checker):
        # a written pack that vanished, as a store losing it would make it.
        pack_id = min(checker.written_packs)
        checker.repository.store_delete("packs/" + bin_to_hex(pack_id))
        removed.append(pack_id)

    findings = record_verify_findings(monkeypatch, tamper)
    output = cmd(archiver, "check", "--repair", exit_code=0)
    assert findings == [True]
    (pack_id,) = removed
    assert f"pack {bin_to_hex(pack_id)}: written by the repair, but it is missing." in output
    assert "the chunks index does not match the pack" not in output
    assert "Archive consistency check complete, problems found." in output
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        assert not any(entry.pack_id == pack_id for _, entry in repository.chunks.iteritems())


@pytest.mark.parametrize("holder", ["first", "second"])
def test_verify_written_packs_does_not_depend_on_the_pack_order(archiver, monkeypatch, holder):
    """A chunk in one written pack, indexed at a bogus location in the other one, is indexed where it is.

    holder: which of the two written packs, in the order verify_written_packs reads them, holds the chunk.
    """
    # local-only: this patches in-process archive and repository internals.
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "1")  # a pack per object
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        manifest = Manifest.load(repository)
        ids = []
        for data in [b"aaa", b"bbb"]:
            chunk_id = manifest.key.id_hash(data)
            repository.put(chunk_id, manifest.repo_objs.format(chunk_id, {}, data, ro_type=ROBJ_FILE_STREAM))
            ids.append(chunk_id)
        repository.flush()
        entries = {chunk_id: repository.chunks[chunk_id] for chunk_id in ids}
        first_id, second_id = sorted(ids, key=lambda chunk_id: entries[chunk_id].pack_id)
        chunk_id, other_id = (first_id, second_id) if holder == "first" else (second_id, first_id)

        checker = ArchiveChecker()
        checker.repair = True
        checker.repository = repository
        checker.key = manifest.key
        checker.repo_objs = manifest.repo_objs
        checker.chunks = repository.chunks
        checker.written_packs = {entry.pack_id for entry in entries.values()}
        checker.chunks[chunk_id] = entries[chunk_id]._replace(pack_id=entries[other_id].pack_id, obj_offset=1)

        checker.verify_written_packs()

        assert checker.error_found
        fixed = checker.chunks[chunk_id]
        expected = entries[chunk_id]
        assert (fixed.pack_id, fixed.obj_offset, fixed.obj_size) == (
            expected.pack_id,
            expected.obj_offset,
            expected.obj_size,
        )


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "authenticated-sha256"]])
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


def _archive_checker(repository):
    """An ArchiveChecker wired to repository, for calling a single check step directly."""
    checker = ArchiveChecker()
    checker.repair = False
    checker.repository = repository
    checker.key = checker.make_key(repository)
    checker.repo_objs = RepoObj(checker.key)
    checker.chunks = repository.chunks
    return checker


def _watch_pack_loads(monkeypatch, repository):
    """Record which packs get loaded as a whole (size=None: no range read, the full object)."""
    loaded = []
    orig_load = repository.store.load

    def load(key, **kwargs):
        if key.startswith("packs/") and kwargs.get("size") is None:
            loaded.append(key)
        return orig_load(key, **kwargs)

    monkeypatch.setattr(repository.store, "load", load)
    return loaded


def test_verify_data_reads_each_pack_once(archivers, request, monkeypatch):
    """verify_data() walks the chunk index pack by pack, so it fetches every pack exactly once."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    with open_repository(archiver) as repository:
        checker = _archive_checker(repository)
        packs = {entry.pack_id for _, entry in repository.chunks.iteritems()}
        assert len(packs) > Repository.PACK_READER_CACHE_SIZE  # more packs than the pack cache holds
        loaded = _watch_pack_loads(monkeypatch, repository)

        checker.verify_data()

        assert not checker.error_found
        assert sorted(loaded) == sorted("packs/" + bin_to_hex(pack_id) for pack_id in packs)


def test_verify_data_reports_a_missing_pack(archivers, request, monkeypatch):
    """A pack that is gone is reported once, with the chunks it holds counted as lost, and the check goes on."""
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    with open_repository(archiver) as repository:
        checker = _archive_checker(repository)
        # the fullest pack, so it holds more chunks than just the one that is read first
        gone, gone_chunks = max(repository.chunks.iter_packs(), key=lambda pack: len(pack[1]))
        assert len(gone_chunks) > 1
        repository.store_delete("packs/" + bin_to_hex(gone))
        repository.clear_pack_cache()
        loaded = _watch_pack_loads(monkeypatch, repository)

        logged = []
        monkeypatch.setattr(archive_module.logger, "error", lambda msg, *args: logged.append(msg % args))

        checker.verify_data()

        assert checker.error_found
        # one line for the pack, not one per chunk, then the summary: the other packs verify fine.
        assert len(logged) == 2
        assert logged[0] == f"pack {bin_to_hex(gone)} is missing, {len(gone_chunks)} chunks are lost."
        # the lost chunks count as verified and as errors, as if each had been read and failed.
        assert logged[-1].endswith(f"verified {len(repository.chunks)} chunks with {len(gone_chunks)} error(s).")
        # each pack was loaded once, the missing one included, and the scan continued past it.
        packs = {entry.pack_id for _, entry in repository.chunks.iteritems()}
        assert sorted(loaded) == sorted("packs/" + bin_to_hex(pack_id) for pack_id in packs)


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
    with changedir("output"):
        cmd(archiver, "extract", "archive1", exit_code=0)
    # ... but check --verify-data always checks it:
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert "id verification failed" in output

    # with "read" in BORG_ASSERT_ID, reads check it too: extract treats the chunk as corrupted, i.e.
    # it extracts all-zero data instead and reports the file with a warning.
    monkeypatch.setenv("BORG_ASSERT_ID", "read")
    Path("output2").mkdir()
    with changedir("output2"):
        output = cmd(archiver, "extract", "archive1", exit_code=BackupDamagedChunksError.exit_mcode)
    assert "id verification failed" in output
    assert "1 chunk(s) missing or corrupted in the repository, replaced by all-zero data" in output


def test_repair_wrong_item_metadata_chunk_content(archivers, request, monkeypatch):
    # check --repair re-packs the item metadata stream it reads into new chunks with freshly computed ids,
    # so it re-certifies the id/content invariant, even though reads do not check it by default, see #9994.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")

    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        chunk_id = archive.item_ids[0]  # first chunk of the item metadata stream
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


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "authenticated-sha256"]])
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
    # the archive metadata was stored in the deleted packs.
    output = cmd(archiver, "check", exit_code=1)
    assert "pack(s) referenced by the index are missing" in output
    assert "Archive metadata block" in output and "is missing!" in output


def test_repair_repository_only_removes_missing_pack_entries(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        for info in repository.store_list("packs"):
            repository.store_delete("packs/" + info.name)
    output = cmd(archiver, "check", "--repair", "--repository-only", exit_code=1)
    assert "Removed the index entries of their" in output
    assert "without --repository-only" in output
    # the stored index lacks the entries of the missing packs now.
    output = cmd(archiver, "check", "--repository-only", exit_code=0)
    assert "Missing pack" not in output
    # the archives still reference the lost chunks: a full repair removes them.
    output = cmd(archiver, "check", exit_code=1)
    assert "Archive metadata block" in output and "is missing!" in output
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_items_with_unknown_keys_are_kept(archivers, request):
    # items with keys this borg version does not know (e.g. written by a newer borg) are not an error:
    # check warns about them once per archive (rc stays 0) and --repair writes them back unchanged.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("archive is crafted via direct (local) repository access")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    item = Item(
        internal_dict=dict(
            path="dir/file", mode=0o100644, mtime=0, uid=0, gid=0, user="root", group="root", size=0, newkey="future"
        )
    )
    with Repository(archiver.repository_path, exclusive=True) as repository:
        manifest = Manifest.load(repository)
        with Cache(repository, manifest, archive_name="future") as cache:
            archive = Archive(manifest, "future", cache=cache, create=True)
            archive.items_buffer.add(item)
            archive.save(name="future")

    output = cmd(archiver, "check", "--archives-only", exit_code=0)
    assert "Archive future: items have keys unknown to this borg version" in output
    assert "newkey" in output
    assert "Did not get expected metadata dict" not in output
    cmd(archiver, "check", "--repair", "--archives-only", exit_code=0)
    archive, repository = open_archive(archiver.repository_path, "future")
    with repository:
        items = list(archive.iter_items())
    assert len(items) == 1
    assert items[0].as_dict()["newkey"] == "future"
    output = cmd(archiver, "check", "--archives-only", exit_code=0)
    assert "keys unknown to this borg version" in output  # still just the warning


def make_pack_unreadable(monkeypatch, pack_name):
    """Make reading the pack packs/<pack_name> fail with an OSError, like failing storage does.

    Patches the posixfs backend rather than using file permissions, so it also works when the tests
    run as root and does not depend on the platform's permission semantics. Returns a dict whose
    "failing" entry switches the failures off again (monkeypatch.undo() must not be used here, it
    would also revert the autouse clean_env fixture).
    """
    from borgstore.backends.posixfs import PosixFS

    state = {"failing": True}
    orig_hash, orig_load = PosixFS.hash, PosixFS.load

    def hits_pack(name):
        # the backend gets the name including borgstore's nesting levels, e.g. packs/d0/d0a6...
        return state["failing"] and name.rsplit("/", 1)[-1] == pack_name

    def failing_hash(self, name, algorithm="sha256"):
        if hits_pack(name):
            raise OSError(errno.EIO, "Input/output error", name)
        return orig_hash(self, name, algorithm=algorithm)

    def failing_load(self, name, *, size=None, offset=0):
        if hits_pack(name):
            raise OSError(errno.EIO, "Input/output error", name)
        return orig_load(self, name, size=size, offset=offset)

    monkeypatch.setattr(PosixFS, "hash", failing_hash)
    monkeypatch.setattr(PosixFS, "load", failing_load)
    return state


def some_pack_name(archiver):
    """Return the name of one of the repository's pack files."""
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        return sorted(info.name for info in repository.store_list("packs"))[0]


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
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        tracker = PackTracker.load(repository)
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
    pack_name = some_pack_name(archiver)
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        chunks_before = sorted(chunk_id for chunk_id, _ in repository.chunks.iteritems())
    state = make_pack_unreadable(monkeypatch, pack_name)

    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert "could not be read and were left untouched" in output

    state["failing"] = False
    with KeyedRepository(archiver.repository_location, exclusive=True) as repository:
        chunks_after = sorted(chunk_id for chunk_id, _ in repository.chunks.iteritems())
    assert chunks_after == chunks_before  # nothing was thrown away
