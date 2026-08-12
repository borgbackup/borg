import os
import re

import pytest

from ...constants import *  # NOQA
from ...helpers import bin_to_hex, sig_int, Error, CompressionSpec
from ...repository import Repository, PackReader, repo_lister
from ...cache import list_chunkindex_hashes
from ...manifest import Manifest
from ...compress import ZSTD, ZLIB, LZ4, CNONE
from ...archiver.repo_compress_cmd import PackRecompressor

from . import create_regular_file, cmd, RK_ENCRYPTION
from ..repository_test import H, fchunk, pdchunk


def test_repo_compress(archiver):
    def check_compression(ctype, clevel, olevel):
        """Check that all chunks in the repo are compressed/obfuscated as expected."""
        repository = Repository(archiver.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            for id, _ in repo_lister(repository, limit=LIST_SCAN_LIMIT):
                chunk = repository.get(id, read_data=True)
                meta, data = manifest.repo_objs.parse(
                    id, chunk, ro_type=ROBJ_DONTCARE
                )  # will also decompress according to metadata
                m_olevel = meta.get("olevel", -1)
                m_psize = meta.get("psize", -1)
                print(bin_to_hex(id), meta["ctype"], meta["clevel"], meta["csize"], meta["size"], m_olevel, m_psize)
                # this is not as easy as one thinks due to the DecidingCompressor choosing the smallest of
                # (desired compressed, lz4 compressed, not compressed).
                assert meta["ctype"] in (ctype, LZ4.ID, CNONE.ID)
                assert meta["clevel"] in (clevel, 255)  # LZ4 and CNONE have level 255
                if olevel != -1:  # we expect obfuscation
                    assert "psize" in meta
                    assert m_olevel == olevel
                else:
                    assert "psize" not in meta
                    assert "olevel" not in meta

    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 3, -1
    cmd(archiver, "create", "test", "input", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 1, -1  # change compressor (and level)
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # only change level
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 110  # only change to obfuscated
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 112  # only change obfuscation level
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # change to not obfuscated
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 1, -1
    cmd(archiver, "repo-compress", "-C", f"auto,{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 2, 111
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},auto,{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    # data must survive all those recompressions unharmed
    cmd(archiver, "check")


def test_repo_compress_zstd_negative_level(archiver):
    """zstd's negative ("fast") levels survive a repo-compress round trip.

    The second run is the interesting part: it only reports everything as already-ok if the
    level the compressor is configured with and the clevel byte stored in the repo are the
    same representation. If they diverge, borg parses and recompresses every object again on
    every run (see get_csettings).
    """
    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "-C", "lz4")

    for level in (-1, -4):  # -1 is the level whose byte (255) is also the "no level" sentinel
        cmd(archiver, "repo-compress", "-C", f"zstd,{level}")
        repository = Repository(archiver.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            for id, _ in repo_lister(repository, limit=LIST_SCAN_LIMIT):
                chunk = repository.get(id, read_data=True)
                meta, data = manifest.repo_objs.parse(id, chunk, ro_type=ROBJ_DONTCARE)
                assert meta["ctype"] in (ZSTD.ID, LZ4.ID, CNONE.ID)
                if meta["ctype"] == ZSTD.ID:
                    assert meta["clevel"] == ZSTD.encode_level(level)

        # Running it again must recognise the objects as already having the desired
        # compression. Checking for "0 recompressed" alone would not catch anything: objects
        # whose settings are misread get recompressed to the identical result and are then
        # counted as "kept as-is", so the telling number is how many were recognised as ok.
        output = cmd(archiver, "repo-compress", "-C", f"zstd,{level}", "--stats")
        stats = re.search(
            r"Objects: (\d+) total, (\d+) recompressed, (\d+) already had the desired compression", output
        )
        assert stats, output
        total, recompressed, already_ok = (int(g) for g in stats.groups())
        assert recompressed == 0
        assert already_ok > 0, f"no object was recognised as already compressed with zstd,{level}"

    cmd(archiver, "check")


def test_repo_compress_stats(archiver):
    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    cname, clevel = ZLIB.name, 3
    cmd(archiver, "create", "test", "input", "-C", f"{cname},{clevel}")

    cname, clevel = ZSTD.name, 1  # change compressor (and level)
    output = cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}", "--stats")
    assert "Recompression stats:" in output


def test_repo_compress_multiple_packs(archiver, monkeypatch):
    # process a repository whose data spans several packs, pack after pack.
    monkeypatch.setenv("BORG_PACK_MAX_SIZE", "65536")  # tiny packs, so the repo has quite a few
    for i in range(8):
        # per file: 128 kiB of distinct data that compresses to roughly a quarter of its size,
        # so the compressed objects fill several packs and every pack needs recompression.
        create_regular_file(archiver.input_path, f"file{i}", contents=os.urandom(16 * 1024) * 8)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "-C", "zlib,3")

    with Repository(archiver.repository_path, exclusive=True) as repository:
        packs_before = {info.name for info in repository.store_list("packs")}
    assert len(packs_before) > 2

    cmd(archiver, "repo-compress", "-C", "zstd,3", "--stats")

    # several packs were rewritten. not necessarily all of them: a pack holding only incompressible
    # objects (e.g. an archive chunkids list, stored uncompressed even under -C zlib) is kept as-is.
    with Repository(archiver.repository_path, exclusive=True) as repository:
        packs_after = {info.name for info in repository.store_list("packs")}
        assert len(packs_before - packs_after) >= 2
        # no object is left with the old zlib compression
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        for id, _ in repo_lister(repository, limit=LIST_SCAN_LIMIT):
            meta = manifest.repo_objs.parse_meta(id, repository.get(id, read_data=False), ro_type=ROBJ_DONTCARE)
            assert meta["ctype"] != ZLIB.ID

    # everything still there and consistent?
    cmd(archiver, "check")
    output = cmd(archiver, "list", "test")
    for i in range(8):
        assert f"file{i}" in output


def test_repo_compress_second_run_changes_nothing(archiver):
    # a second run with the same settings must not rewrite any pack and must leave the stored
    # chunk index alone (no invalidation, no rewrite - other clients' cached indexes stay valid).
    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "-C", "zlib,3")

    cmd(archiver, "repo-compress", "-C", "zstd,3")

    with Repository(archiver.repository_path, exclusive=True) as repository:
        packs_before = {info.name for info in repository.store_list("packs")}
        hashes_before = list_chunkindex_hashes(repository)

    output = cmd(archiver, "repo-compress", "-C", "zstd,3", "--stats")
    assert ", 0 recompressed" in output  # everything already zstd,3 (or "kept as-is"): nothing to rewrite

    with Repository(archiver.repository_path, exclusive=True) as repository:
        assert {info.name for info in repository.store_list("packs")} == packs_before
        assert list_chunkindex_hashes(repository) == hashes_before


def test_repo_compress_soft_interrupt_persists_valid_index(archiver, monkeypatch):
    """One Ctrl-C stops repo-compress at the next pack boundary, saves a chunk index that still
    matches the repository, and exits with an error. A later run recompresses the remaining packs."""
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "1")  # one object per pack -> several packs to stop between
    for i in range(3):
        # compressible, distinct data, so every object really gets recompressed (lz4 -> zstd)
        create_regular_file(archiver.input_path, f"file{i}", contents=os.urandom(512) * 4)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", "input")

    with Repository(archiver.repository_path, exclusive=True) as repository:
        pack_names_before = {info.name for info in repository.store_list("packs")}
        assert len(pack_names_before) >= 2  # need several packs to observe an early stop

        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        manifest.repo_objs.compressor = CompressionSpec("zstd,3").compressor
        recompressor = PackRecompressor(repository, manifest, print_stats=False)

        original_store_delete = repository.store_delete
        calls = []

        def store_delete_then_interrupt(name, **kwargs):
            original_store_delete(name, **kwargs)
            if name.startswith("packs/"):  # only pack deletes, not the index invalidation deletes
                calls.append(name)
                if len(calls) == 1:
                    sig_int._sig_int_triggered = True  # one Ctrl-C after the first pack was rewritten

        monkeypatch.setattr(repository, "store_delete", store_delete_then_interrupt)
        try:
            with pytest.raises(Error, match="Got Ctrl-C"):
                recompressor.recompress()
        finally:
            sig_int._sig_int_triggered = False  # reset the global flag for the following tests

    # a valid chunk index was persisted and every entry points at a pack that still exists
    with Repository(archiver.repository_path, exclusive=True) as repository:
        assert list_chunkindex_hashes(repository) != []
        pack_names_after = {info.name for info in repository.store_list("packs")}
        # one pack was rewritten before the stop, the remaining old packs are still there
        assert 0 < len(pack_names_before - pack_names_after) < len(pack_names_before)
        for id, entry in repository.chunks.iteritems():
            assert bin_to_hex(entry.pack_id) in pack_names_after

    # a later run finishes the recompression of the remaining packs
    cmd(archiver, "repo-compress", "-C", "zstd,3")
    cmd(archiver, "check")


def transform_via(replacements):
    """Make a transform_pack callback replacing the given objects, keeping all others unchanged."""

    def transform(chunk_id, obj_bytes):
        return replacements.get(chunk_id, obj_bytes)

    return transform


def test_transform_pack_keeps_unindexed_gap(tmp_path):
    # bytes no index entry covers (e.g. objects of a backup that crashed before writing its index)
    # must be carried into the transformed pack unchanged - recovering them is "borg check --repair"'s
    # job. also, the objects around them must be repointed correctly although their sizes changed.
    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 3  # one flush() -> one pack
        for cid, data in [(H(0), b"WWWW"), (H(1), b"XXXX"), (H(2), b"YYYY")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        pack_id = repository.chunks[H(0)].pack_id
        del repository.chunks[H(1)]  # X's bytes become an unindexed gap between W and Y

        replacements = {H(0): fchunk(b"W" * 100, chunk_id=H(0)), H(2): fchunk(b"y", chunk_id=H(2))}
        calls = []
        new_pack_id, new_size = repository.transform_pack(
            pack_id, [H(0), H(2)], transform_via(replacements), before_change=lambda: calls.append(1)
        )
        assert new_pack_id != pack_id
        assert calls == [1]  # before_change called (once), the store was modified

        # the transformed objects are indexed and readable, with their new sizes
        assert pdchunk(repository.get(H(0))) == b"W" * 100
        assert pdchunk(repository.get(H(2))) == b"y"
        # the old pack is gone, the new one exists with the reported size
        pack_names = {info.name: info.size for info in repository.store_list("packs")}
        assert bin_to_hex(pack_id) not in pack_names
        assert pack_names[bin_to_hex(new_pack_id)] == new_size
        # X's object is still in the new pack, as unindexed gap bytes at the right position
        gap_objects = [
            (chunk_id, offset, size)
            for chunk_id, offset, size in PackReader(repository.store, new_pack_id).iter_headers()
            if chunk_id == H(1)
        ]
        assert len(gap_objects) == 1


def test_transform_pack_drops_superseded_gap(tmp_path):
    # a gap object whose chunk id the index maps to another location is a redundant, superseded
    # duplicate (equal ids mean equal content) - a transformed pack must not carry it forward.
    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 2  # one flush() -> one pack
        # pack A: W and X; pack B: a second copy of X, which repoints the index to pack B,
        # leaving X's bytes in pack A as a superseded gap.
        for cid, data in [(H(0), b"WWWW"), (H(1), b"XXXX")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        pack_a = repository.chunks[H(0)].pack_id
        repository.put(H(1), fchunk(b"XXXX", chunk_id=H(1)))
        repository.flush()
        pack_b = repository.chunks[H(1)].pack_id
        assert pack_b != pack_a

        w_new = fchunk(b"W" * 100, chunk_id=H(0))
        new_pack_id, new_size = repository.transform_pack(pack_a, [H(0)], transform_via({H(0): w_new}))
        assert new_pack_id != pack_a
        assert new_size == len(w_new)  # only W remains, X's superseded bytes were dropped
        assert pdchunk(repository.get(H(0))) == b"W" * 100
        assert pdchunk(repository.get(H(1))) == b"XXXX"  # the authoritative copy in pack B


def test_transform_pack_unchanged_pack_untouched(tmp_path):
    # if every transform keeps its object, the store must not be touched at all:
    # no pack write, no pack delete, no before_change call.
    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 2  # one flush() -> one pack
        for cid, data in [(H(0), b"WWWW"), (H(1), b"XXXX")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        pack_id = repository.chunks[H(0)].pack_id
        pack_names_before = {info.name for info in repository.store_list("packs")}

        calls = []
        new_pack_id, new_size = repository.transform_pack(
            pack_id, [H(0), H(1)], transform_via({}), before_change=lambda: calls.append(1)
        )
        assert new_pack_id == pack_id
        assert calls == []  # nothing changed, so before_change was never called
        assert {info.name for info in repository.store_list("packs")} == pack_names_before
        assert pdchunk(repository.get(H(0))) == b"WWWW"
        assert pdchunk(repository.get(H(1))) == b"XXXX"
