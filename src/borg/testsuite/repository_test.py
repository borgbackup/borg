import io
import os
import sys
from collections import namedtuple
from hashlib import sha256

import pytest
from borghash import HashTableNT

from ..helpers import IntegrityError, Location, bin_to_hex
from ..hashindex import ChunkIndex
from ..repository import Repository, MAX_DATA_SIZE, rest_serve_command, PackWriter, PackReader
from ..repository import PackTracker
from ..repoobj import RepoObj, OBJ_MAGIC, OBJ_VERSION
from .hashindex_test import H


def test_rest_serve_command_local():
    # rest:// without a host runs "borg serve --rest" locally, talking over stdio.
    cmd = rest_serve_command(Location("rest:////tmp/repo"))
    assert "ssh" not in cmd
    assert cmd[0] == sys.executable
    assert cmd[-4:] == ["serve", "--rest", "--backend", "FILE:/tmp/repo"]


def test_rest_serve_command_ssh(monkeypatch):
    # rest:// with a host is reached via ssh, running "borg serve --rest" remotely.
    # we override BORGSTORE_RSH to a simple "ssh" here to simplify testing.
    # without that, borgstore 0.5.5+ would also set some ssh options via cmdline.
    monkeypatch.setenv("BORGSTORE_RSH", "ssh")
    monkeypatch.delenv("BORG_REMOTE_PATH", raising=False)
    cmd = rest_serve_command(Location("rest://user@host/repo/path"))
    assert cmd[:2] == ["ssh", "user@host"]
    assert cmd[-5:] == ["borg", "serve", "--rest", "--backend", "FILE:repo/path"]


@pytest.fixture()
def repository(tmp_path):
    repository_location = os.fspath(tmp_path / "repository")
    yield Repository(repository_location, exclusive=True, create=True)


def pytest_generate_tests(metafunc):
    # Generate tests that run on repositories.
    if "repo_fixtures" in metafunc.fixturenames:
        metafunc.parametrize("repo_fixtures", ["repository"])


def get_repository_from_fixture(repo_fixtures, request):
    # Return the repository object from the fixture.
    return request.getfixturevalue(repo_fixtures)


def reopen(repository, exclusive: bool | None = True, create=False):
    if isinstance(repository, Repository):
        if repository.opened:
            raise RuntimeError("Repo must be closed before a reopen. Cannot support nested repository contexts.")
        return Repository(repository._location, exclusive=exclusive, create=create)

    raise TypeError(f"Invalid argument type. Expected 'Repository', received '{type(repository).__name__}'.")


def fchunk(data, meta=b"", chunk_id=b"\x00" * 32):
    # Build a raw chunk with a valid RepoObj layout but no encryption or compression. Pass a unique
    # chunk_id when objects must not share a pack: identical bytes hash to the same sha256 pack id
    # and would otherwise collapse into one pack.
    hdr = RepoObj.obj_header.pack(OBJ_MAGIC, OBJ_VERSION, chunk_id, len(meta), len(data))
    assert isinstance(data, bytes)
    chunk = hdr + meta + data
    return chunk


def corrupt_chunk_on_disk(repository, chunk_id):
    # Flip a byte of the chunk's data in its pack file on disk, chunk index untouched.
    entry = repository.chunks[chunk_id]
    key = "packs/" + bin_to_hex(entry.pack_id)
    pack = repository.store_load(key)
    pos = entry.obj_offset + entry.obj_size - 1  # last byte of the chunk
    pack = pack[:pos] + bytes([pack[pos] ^ 0xFF]) + pack[pos + 1 :]
    repository.store_store(key, pack)


def pchunk(chunk):
    # Parse chunk: extract data and metadata from a raw chunk made by fchunk.
    hdr_size = RepoObj.obj_header.size
    hdr = chunk[:hdr_size]
    meta_size, data_size = RepoObj.obj_header.unpack(hdr)[3:5]
    meta = chunk[hdr_size : hdr_size + meta_size]
    data = chunk[hdr_size + meta_size : hdr_size + meta_size + data_size]
    return data, meta


def pdchunk(chunk):
    # Parse only the data from a raw chunk made by fchunk.
    return pchunk(chunk)[0]


def test_basic_operations(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA", chunk_id=H(x)))  # put() updates _chunks via PackWriter
        repository.flush()  # don't rely on the put count filling whole packs; flush before get()/close()
        key50 = H(50)
        assert pdchunk(repository.get(key50)) == b"SOMEDATA"
    # no manual hand-off of the index across reopen: close() persisted it to the repo cache,
    # and the freshly opened repo rebuilds .chunks from there (or by listing the repo) on its own.
    with reopen(repository) as repository:
        for x in range(100):
            assert pdchunk(repository.get(H(x))) == b"SOMEDATA"


def test_chunk_index_persisted_on_close(tmp_path):
    # close() must serialize the live chunk index into the repo cache, so a freshly opened
    # repo can resolve pack locations without any manual hand-off. This proves the round-trip
    # by reading the persisted index back directly (not via a repo rescan, which would reconstruct
    # the same entries from the pack headers and so could mask a broken persist step).
    from ..cache import list_chunkindex_hashes, read_chunkindex_from_repo

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        for x in range(10):
            repository.put(H(x), fchunk(b"DATA"))
        repository.flush()  # don't rely on the put count filling whole packs; flush before close()
    # reopen and read the cached fragments straight from disk
    with Repository(location, exclusive=True) as repository:
        persisted = ChunkIndex()
        for hash in list_chunkindex_hashes(repository):
            fragment = read_chunkindex_from_repo(repository, hash)
            if fragment is not None:
                for k, v in fragment.items():
                    persisted[k] = v
        for x in range(10):
            assert H(x) in persisted  # close() actually wrote this session's chunks
        # and the reopened repo resolves them end to end
        for x in range(10):
            assert pdchunk(repository.get(H(x))) == b"DATA"


def test_read_data(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        meta, data = b"meta", b"data"
        hdr = RepoObj.obj_header.pack(OBJ_MAGIC, OBJ_VERSION, H(0), len(meta), len(data))
        chunk_complete = hdr + meta + data
        chunk_short = hdr + meta
        repository.put(H(0), chunk_complete)
        repository.flush()  # make the buffered pack durable before get()
        assert repository.get(H(0)) == chunk_complete
        assert repository.get(H(0), read_data=True) == chunk_complete
        assert repository.get(H(0), read_data=False) == chunk_short


def test_consistency(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.flush()  # flush before reading the just-put chunk back
        assert pdchunk(repository.get(H(0))) == b"foo"
        repository.put(H(0), fchunk(b"foo2"))
        repository.flush()
        assert pdchunk(repository.get(H(0))) == b"foo2"
        repository.put(H(0), fchunk(b"bar"))
        repository.flush()
        assert pdchunk(repository.get(H(0))) == b"bar"
        # delete removes the object the index points at; the stale earlier copies are not resurrected.
        repository.delete(H(0))
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(H(0))


def test_delete_with_stale_earlier_object_in_pack(repo_fixtures, request):
    # Re-putting H(0) leaves its old bytes ahead of H(1) in the first pack while its index entry moves
    # to a new pack. delete(H(1)) then sees a partial pack view (H(1) at a non-zero offset) and must not
    # trip compact_pack's contiguity assert.
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # H(0) and H(1) share the first pack
        repository.put(H(0), fchunk(b"aaa"))
        repository.put(H(1), fchunk(b"bbb"))  # fills the pack, flushing both objects
        repository.put(H(0), fchunk(b"ccc"))  # re-put: H(0)'s index entry moves to a new pack
        repository.flush()
        repository.delete(H(1))
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(H(1))
        assert pdchunk(repository.get(H(0))) == b"ccc"  # H(0) still served from its new pack


def test_multi_object_pack_roundtrip(repo_fixtures, request):
    # Two objects fill one pack and must both read back: the second from a non-zero offset, and
    # read_data=False returning only its header+meta. The test pins max_count=2 so it does not depend
    # on the Repository.open() default; the compact tests override max_count via build_one_pack() too.
    meta0, data0 = b"meta0", b"the-first-object"
    meta1, data1 = b"m1", b"second"
    chunk0 = fchunk(data0, meta=meta0, chunk_id=H(0))
    chunk1 = fchunk(data1, meta=meta1, chunk_id=H(1))
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # this test is written for exactly two objects per pack
        repository.put(H(0), chunk0)
        assert repository.chunks.is_pending(H(0))  # buffered: the pack is not full yet
        repository.put(H(1), chunk1)  # fills the pack, flushing both objects at once
        # both objects share one pack, written exactly once, laid out in put() order
        pack_id = repository.chunks[H(0)].pack_id
        assert not repository.chunks.is_pending(H(0))
        assert repository.chunks[H(1)].pack_id == pack_id
        assert [info.name for info in repository.store_list("packs")] == [bin_to_hex(pack_id)]
        assert repository.chunks[H(0)].obj_offset == 0
        assert repository.chunks[H(1)].obj_offset == len(chunk0)  # second object read from a non-zero offset
        # full reads return each object's exact bytes, the second one resolved from its non-zero offset
        assert repository.get(H(0)) == chunk0
        assert repository.get(H(1)) == chunk1
        # read_data=False returns header+meta only and stays inside the requested object
        hdr_size = RepoObj.obj_header.size
        assert repository.get(H(0), read_data=False) == chunk0[: hdr_size + len(meta0)]
        assert repository.get(H(1), read_data=False) == chunk1[: hdr_size + len(meta1)]


def test_get_many_one_load_per_pack(repo_fixtures, request):
    # get_many loads each pack once as a whole and slices every object out of the cached bytes.
    # stats["load_calls"] counts store.load() calls.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(6)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 3  # three objects per pack -> two packs for the six objects
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        ids = [chunk_id for chunk_id, _ in objects]
        assert len({repository.chunks[chunk_id].pack_id for chunk_id in ids}) == 2  # six ids, two packs
        one_by_one = [repository.get(chunk_id) for chunk_id in ids]  # reference bytes, one store.load each

        loads_before = repository.store.stats["load_calls"]
        assert list(repository.get_many(ids)) == one_by_one
        assert repository.store.stats["load_calls"] - loads_before == 2  # one store.load per pack


def test_get_many_keeps_request_order(repo_fixtures, request):
    # Ids requested out of their stored order come back in the requested order with their own bytes.
    # Interleaving two packs still loads each pack once: the pack cache serves the second visit.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(6)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 3  # two packs: {H0,H1,H2} and {H3,H4,H5}
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        ids = [H(0), H(3), H(1), H(4), H(2), H(5)]  # interleave the two packs
        one_by_one = [repository.get(chunk_id) for chunk_id in ids]

        loads_before = repository.store.stats["load_calls"]
        assert list(repository.get_many(ids)) == one_by_one  # same order, same bytes
        assert repository.store.stats["load_calls"] - loads_before == 2  # each pack loaded once


def test_get_many_missing_id_yields_none(repo_fixtures, request):
    # With raise_missing=False, an id that was never stored yields None in its position; the ids
    # before and after it read back unchanged.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(3)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 4  # above the object count, so the pack flushes on flush() only
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        repository.flush()
        ids = [H(0), H(99), H(2)]  # H(99) was never put
        result = list(repository.get_many(ids, raise_missing=False))
        assert result[0] == repository.get(H(0))
        assert result[1] is None  # never stored -> None
        assert result[2] == repository.get(H(2))


def test_get_many_missing_pack_raises_pack_not_found(repo_fixtures, request):
    # get_many raises PackNotFound when a chunk's index entry points to a pack that is not in the
    # store; with raise_missing=False it yields None instead.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(2)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # one pack: {H0, H1}
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        repository.flush()
        pack_id = repository.chunks[H(0)].pack_id
        repository.store_delete("packs/" + bin_to_hex(pack_id))  # delete the pack, keep its index entry

        with pytest.raises(Repository.PackNotFound):
            list(repository.get_many([H(0)]))
        with pytest.raises(Repository.PackNotFound):
            list(repository.get_many([H(0), H(1)]))  # one id's pack missing in a batch
        assert list(repository.get_many([H(0)], raise_missing=False)) == [None]  # raise_missing=False -> None


def test_get_many_repeated_ids(repo_fixtures, request):
    # A dedup'd item repeats chunk ids, e.g. [A, A, B, C, B]. Each repeat returns the right bytes
    # and each pack is loaded once: the cached pack serves the later visits.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(4)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # two packs: {H0,H1} and {H2,H3}
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        assert len({repository.chunks[H(i)].pack_id for i in range(4)}) == 2
        ids = [H(0), H(0), H(1), H(2), H(1)]  # A A B C B, A/B in one pack, C in the other
        one_by_one = [repository.get(chunk_id) for chunk_id in ids]

        loads_before = repository.store.stats["load_calls"]
        assert list(repository.get_many(ids)) == one_by_one  # every position, including repeats
        assert repository.store.stats["load_calls"] - loads_before == 2  # two packs, one load each


def test_get_many_evicts_least_recently_used(repo_fixtures, request):
    # Visiting more packs than the cache holds evicts the oldest; revisiting an evicted pack reloads it.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(8)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # four packs: {H0,H1} {H2,H3} {H4,H5} {H6,H7}
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        assert len({repository.chunks[H(i)].pack_id for i in range(8)}) == 4
        assert repository.PACK_READER_CACHE_SIZE == 3  # cache holds three of the four packs
        # touch packs 0,1,2 (fills cache), then 3 (evicts pack 0), then pack 0 again (reload).
        ids = [H(0), H(2), H(4), H(6), H(0)]
        one_by_one = [repository.get(chunk_id) for chunk_id in ids]

        loads_before = repository.store.stats["load_calls"]
        assert list(repository.get_many(ids)) == one_by_one
        assert repository.store.stats["load_calls"] - loads_before == 5  # 4 distinct packs + 1 reload


def test_get_reuses_cached_pack(repo_fixtures, request):
    # get() slices from a pack that get_many already cached, doing no store load; a get() whose pack
    # is not cached reads only its object's range and does not load the whole pack into the cache.
    objects = [(H(i), fchunk(b"payload-%02d" % i, chunk_id=H(i))) for i in range(2)]
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository._pack_writer.max_count = 2  # one pack: {H0, H1}
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)

        # cold cache: get() reads one range and leaves the cache empty, so the next get() reads again
        loads_before = repository.store.stats["load_calls"]
        reference = repository.get(H(0))
        assert repository.store.stats["load_calls"] - loads_before == 1  # one ranged read
        loads_before = repository.store.stats["load_calls"]
        repository.get(H(1))
        assert repository.store.stats["load_calls"] - loads_before == 1  # pack was not cached, another range

        list(repository.get_many([H(0), H(1)]))  # loads the whole pack into the cache

        loads_before = repository.store.stats["load_calls"]
        assert repository.get(H(0)) == reference
        assert repository.store.stats["load_calls"] - loads_before == 0  # sliced from the cached pack
        assert repository.get(H(1), read_data=False)  # read_data=False also peeks the cache
        assert repository.store.stats["load_calls"] - loads_before == 0


def build_one_pack(repository, objects):
    with repository:
        repository._pack_writer.max_count = len(objects) + 1  # prevent per-put flush; one pack on flush()
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        repository.flush()


def test_compact_pack_copy_forward(repo_fixtures, request):
    # Keep a subset of a multi-object pack: kept objects must read back, the dropped object and its bytes gone.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        assert repository.chunks[H(1)].pack_id == old_pack_id
        assert repository.chunks[H(2)].pack_id == old_pack_id

        new_pack_id, dropped = repository.compact_pack(old_pack_id, keep_ids={H(0), H(2)}, drop_ids={H(1)})

        assert new_pack_id is not None and new_pack_id != old_pack_id
        assert dropped == len(chunk1)  # reported freed bytes for --stats
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert pdchunk(repository.get(H(2))) == b"DATA2"
        assert repository.get(H(1), raise_missing=False) is None  # compact_pack removed its index entry
        packs = {info.name: info.size for info in repository.store_list("packs")}
        assert bin_to_hex(old_pack_id) not in packs
        assert packs[bin_to_hex(new_pack_id)] == len(chunk0) + len(chunk2)  # only the kept objects' bytes


def test_compact_pack_drops_whole_pack(repo_fixtures, request):
    # Dropping every object removes the pack and clears its index entries.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id

        new_pack_id, dropped = repository.compact_pack(old_pack_id, keep_ids=set(), drop_ids={H(0), H(1)})
        assert new_pack_id is None  # every byte dropped: no replacement pack
        assert dropped == len(chunk0) + len(chunk1)

        assert repository.get(H(0), raise_missing=False) is None
        assert repository.get(H(1), raise_missing=False) is None
        assert bin_to_hex(old_pack_id) not in [info.name for info in repository.store_list("packs")]


def test_compact_pack_keep_all_is_noop(repo_fixtures, request):
    # Keeping every object reproduces the same pack: same sha256 name, old pack not deleted. Ids passed
    # out of order must give the same result, since compact_pack sorts by offset.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id

        new_pack_id, dropped = repository.compact_pack(
            old_pack_id, keep_ids={H(1), H(0)}, drop_ids=set()
        )  # out of order

        assert new_pack_id == old_pack_id
        assert dropped == 0  # nothing dropped
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert pdchunk(repository.get(H(1))) == b"DATA1"


def test_compact_pack_keeps_gap(repo_fixtures, request):
    # A pack may hold bytes no index entry covers (a superseded copy of a chunk re-put elsewhere).
    # compact_pack must copy such gaps into the new pack rather than dropping data it was not told to
    # drop; only "borg check --repair" decides their fate (issue #9868). Drop the middle object's index
    # entry to make a gap, then rewrite dropping the first object and keeping the last: the gap survives.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        del repository.chunks[H(1)]  # H(1)'s bytes stay in the pack but are now unindexed (a gap)

        new_pack_id, _ = repository.compact_pack(old_pack_id, keep_ids={H(2)}, drop_ids={H(0)})

        assert new_pack_id is not None and new_pack_id != old_pack_id
        assert pdchunk(repository.get(H(2))) == b"DATA2"
        packs = {info.name: info.size for info in repository.store_list("packs")}
        assert bin_to_hex(old_pack_id) not in packs
        assert packs[bin_to_hex(new_pack_id)] == len(chunk1) + len(chunk2)  # gap bytes kept, only H(0) dropped


def test_compact_pack_keeps_trailing_bytes(repo_fixtures, request):
    # Same as the gap case, but the unindexed bytes are at the end of the pack: dropping the last
    # object's index entry leaves trailing bytes the listed objects do not reach. Rewrite dropping the
    # first object; the trailing bytes must be copied forward, not lost.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        del repository.chunks[H(2)]  # trailing unindexed bytes

        new_pack_id, _ = repository.compact_pack(old_pack_id, keep_ids={H(1)}, drop_ids={H(0)})

        assert new_pack_id is not None and new_pack_id != old_pack_id
        assert pdchunk(repository.get(H(1))) == b"DATA1"
        packs = {info.name: info.size for info in repository.store_list("packs")}
        assert packs[bin_to_hex(new_pack_id)] == len(chunk1) + len(chunk2)  # trailing bytes kept


def test_compact_pack_drops_superseded_gap(repo_fixtures, request):
    # A gap object whose chunk id is still in the index has its authoritative copy elsewhere, so it is
    # a superseded duplicate and compact_pack drops its bytes. Repoint H(1) to another pack: its bytes
    # here become an indexed-elsewhere gap. Rewrite keeping H(0) and H(2); the gap is dropped and H(1)'s
    # index entry (pointing elsewhere) stays.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        repository.chunks[H(1)] = repository.chunks[H(1)]._replace(pack_id=H(9))  # authoritative copy elsewhere

        new_pack_id, dropped = repository.compact_pack(old_pack_id, keep_ids={H(0), H(2)}, drop_ids=set())

        assert new_pack_id is not None and new_pack_id != old_pack_id
        assert dropped == len(chunk1)  # the superseded gap's bytes are counted as freed
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert pdchunk(repository.get(H(2))) == b"DATA2"
        packs = {info.name: info.size for info in repository.store_list("packs")}
        assert bin_to_hex(old_pack_id) not in packs
        assert packs[bin_to_hex(new_pack_id)] == len(chunk0) + len(chunk2)  # superseded H(1) gap dropped
        assert repository.chunks[H(1)].pack_id == H(9)  # index entry pointing elsewhere is untouched


def test_compact_pack_keeps_self_referencing_gap(repo_fixtures, request):
    # A gap object whose index entry points back at this very pack and offset is the object's only copy
    # (a caller that broke the keep+drop contract by not listing it). compact_pack must keep its bytes,
    # not destroy them. Leave H(1) out of keep_ids and drop_ids with its entry pointing here.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id

        new_pack_id, dropped = repository.compact_pack(old_pack_id, keep_ids={H(0), H(2)}, drop_ids=set())

        assert new_pack_id == old_pack_id  # nothing dropped, defrag reproduced the same pack
        assert dropped == 0  # the self-referencing gap is kept, nothing freed
        packs = {info.name: info.size for info in repository.store_list("packs")}
        assert packs[bin_to_hex(new_pack_id)] == len(chunk0) + len(chunk1) + len(chunk2)  # H(1) bytes kept


def test_compact_pack_detects_overlap(repo_fixtures, request):
    # Overlapping index entries mean index corruption: compact_pack must raise IntegrityError and
    # leave the pack in place. Point H(1) back at H(0)'s offset to overlap it.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        entry = repository.chunks[H(1)]
        repository.chunks[H(1)] = entry._replace(obj_offset=0)  # now overlaps H(0) at offset 0

        with pytest.raises(IntegrityError):
            repository.compact_pack(old_pack_id, keep_ids={H(0), H(1)}, drop_ids=set())
        assert bin_to_hex(old_pack_id) in [info.name for info in repository.store_list("packs")]


def test_compact_pack_detects_past_eof(repo_fixtures, request):
    # An index entry whose span ends past the pack file means index corruption: compact_pack must
    # raise IntegrityError and leave the pack in place, so defrag never short-reads a truncated object.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        entry = repository.chunks[H(1)]
        repository.chunks[H(1)] = entry._replace(obj_size=entry.obj_size + 1000)  # now claims to end past EOF

        with pytest.raises(IntegrityError):
            repository.compact_pack(old_pack_id, keep_ids={H(0), H(1)}, drop_ids=set())
        assert bin_to_hex(old_pack_id) in [info.name for info in repository.store_list("packs")]


def test_compact_pack_translates_read_range_error(repo_fixtures, request, monkeypatch):
    # On a truncated or corrupt pack a defrag span reads back short and borgstore raises ReadRangeError.
    # compact_pack translates it to IntegrityError, keeps the source pack and leaves the index unchanged.
    # store.defrag is patched to raise ReadRangeError.
    from borgstore.store import ReadRangeError

    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id

        def short_read(*args, **kwargs):
            raise ReadRangeError("requested 5 bytes at offset 0, got 3")

        monkeypatch.setattr(repository.store, "defrag", short_read)
        with pytest.raises(IntegrityError):
            repository.compact_pack(old_pack_id, keep_ids={H(0)}, drop_ids={H(1)})
        assert bin_to_hex(old_pack_id) in [info.name for info in repository.store_list("packs")]
        assert H(1) in repository.chunks  # still indexed: aborted before deleting the dropped id


def test_merge_packs_combines_whole_files(repo_fixtures, request):
    # Several one-object packs merge into one, and every object reads back from its new location.
    repository = get_repository_from_fixture(repo_fixtures, request)
    with repository:
        pack_ids = []
        for i in range(3):
            repository.put(H(i), fchunk(f"DATA{i}".encode(), chunk_id=H(i)))
            repository.flush()  # one object per pack
            pack_ids.append(repository.chunks[H(i)].pack_id)

        packs_before = {info.name for info in repository.store_list("packs")}
        assert len(packs_before) == 3

        repository.merge_packs(pack_ids)

        packs_after = {info.name for info in repository.store_list("packs")}
        assert len(packs_after) == 1
        assert packs_after.isdisjoint(packs_before)  # a brand-new pack, all originals deleted
        for i in range(3):
            assert pdchunk(repository.get(H(i))) == f"DATA{i}".encode()
            assert bin_to_hex(repository.chunks[H(i)].pack_id) in packs_after


def test_merge_packs_carries_unindexed_bytes_forward(repo_fixtures, request):
    # A pack byte range no index entry covers (e.g. a chunk copy superseded by a later put) must
    # survive a merge unchanged, not be silently dropped: merge_packs copies whole pack files.
    # Merged alongside a second pack, so the result is a genuinely new pack (a lone unchanged pack
    # would defrag to identical bytes and thus the same content-addressed name).
    chunk0 = fchunk(b"AAAA", chunk_id=H(0))
    chunk1 = fchunk(b"BBBB", chunk_id=H(1))  # this entry is removed from the index before merging
    chunk2 = fchunk(b"CCCC", chunk_id=H(2))  # lives in a second, separate pack
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        repository.put(H(2), chunk2)
        repository.flush()
        pack1_id = repository.chunks[H(0)].pack_id
        pack2_id = repository.chunks[H(2)].pack_id
        pack1_size_before = repository.store.info("packs/" + bin_to_hex(pack1_id)).size
        del repository.chunks[H(1)]  # H(1)'s bytes are now unindexed, but still on disk

        repository.merge_packs({pack1_id, pack2_id})

        new_pack_id = repository.chunks[H(0)].pack_id
        assert new_pack_id == repository.chunks[H(2)].pack_id  # both merged into the same new pack
        new_pack_size = repository.store.info("packs/" + bin_to_hex(new_pack_id)).size
        assert new_pack_size == pack1_size_before + len(chunk2)  # H(1)'s bytes carried forward, not dropped
        assert pdchunk(repository.get(H(0))) == b"AAAA"
        assert pdchunk(repository.get(H(2))) == b"CCCC"


def test_merge_packs_detects_past_eof(repo_fixtures, request):
    # An index entry claiming bytes past its pack's actual end means index corruption. merge_packs
    # must raise before writing anything, so the only intact copy of the pack is never deleted.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0)])
    with repository:
        pack_id = repository.chunks[H(0)].pack_id
        entry = repository.chunks[H(0)]
        repository.chunks[H(0)] = entry._replace(obj_size=entry.obj_size + 1)  # claims 1 byte past EOF

        with pytest.raises(IntegrityError):
            repository.merge_packs({pack_id})
        assert bin_to_hex(pack_id) in [info.name for info in repository.store_list("packs")]  # untouched


def test_merge_packs_skips_pack_already_gone(repo_fixtures, request):
    # A stale index entry pointing at a pack file the store no longer has (#9850) must not abort the
    # merge: the pack is excluded with a warning and the rest of the batch still merges.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    with repository:
        repository.put(H(0), chunk0)
        repository.flush()
        pack0_id = repository.chunks[H(0)].pack_id
        repository.put(H(1), chunk1)
        repository.flush()
        pack1_id = repository.chunks[H(1)].pack_id

        repository.store_delete("packs/" + bin_to_hex(pack0_id))  # pack gone, index entry left stale

        repository.merge_packs({pack0_id, pack1_id})

        assert pdchunk(repository.get(H(1))) == b"DATA1"  # the still-present pack merged normally


def test_assert_writable(repository):
    # Compaction needs write (w/W) and delete (D) on both packs/ and index/. assert_writable reads
    # self.permissions directly, so set it explicitly to cover each case.
    with repository:
        repository.permissions = None  # "all": no restrictions
        repository.assert_writable()  # does not raise

        repository.permissions = {"packs": "lrwWD", "index": "lrwWD"}
        repository.assert_writable()  # does not raise

        repository.permissions = {"packs": "lrw", "index": "lrwWD"}  # packs/ has no delete
        with pytest.raises(Repository.PermissionDenied):
            repository.assert_writable()

        repository.permissions = {"packs": "lrwWD", "index": "lrD"}  # index/ has no write
        with pytest.raises(Repository.PermissionDenied):
            repository.assert_writable()

        repository.permissions = {"": "lr"}  # neither namespace listed; "" fallback grants read only
        with pytest.raises(Repository.PermissionDenied):
            repository.assert_writable()


def test_list(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA", chunk_id=H(x)))  # unique bytes -> unique pack id
        repository.flush()  # flush the last partial pack so all 100 objects are listable
        repo_list = repository.list()
        assert len(repo_list) == 100
        first_half = repository.list(limit=50)
        assert len(first_half) == 50
        assert first_half == repo_list[:50]
        second_half = repository.list(marker=first_half[-1][0])
        assert len(second_half) == 50
        assert second_half == repo_list[50:]
        assert len(repository.list(limit=50)) == 50


def test_max_data_size(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        max_data = b"x" * (MAX_DATA_SIZE - RepoObj.obj_header.size)
        repository.put(H(0), fchunk(max_data))
        repository.flush()  # make the buffered pack durable before get()
        assert pdchunk(repository.get(H(0))) == max_data
        with pytest.raises(IntegrityError):
            repository.put(H(1), fchunk(max_data + b"x"))
        repository.delete(H(0))


def check(repository, repo_path, repair=False, status=True):
    assert repository.check(repair=repair) == status
    # Make sure no tmp files are left behind
    tmp_files = [name for name in os.listdir(repo_path) if "tmp" in name]
    assert tmp_files == [], "Found tmp files"


class MockStore:
    def __init__(self):
        self.stored = {}

    def store(self, key, data):
        self.stored[key] = data


class FailingPackStore:
    """Wraps a store but fails packs/* writes; every other call passes through to the inner store.

    Models the realistic failure where only a pack write broke while the rest of the repo (e.g. the
    index/* objects) stay writable.  In production PackWriter and the chunk index share
    one store, so a single object has to fail the pack write yet still let the index persist.
    """

    def __init__(self, inner):
        self._inner = inner

    def store(self, key, data):
        if key.startswith("packs/"):
            raise OSError("simulated pack store failure")
        return self._inner.store(key, data)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_pack_writer_returns_none_when_not_full():
    pw = PackWriter(MockStore(), max_count=2, chunks=ChunkIndex())
    assert pw.add(b"a" * 32, b"data") is None


def test_pack_writer_flush_returns_none_when_empty():
    pw = PackWriter(MockStore(), max_count=1, chunks=ChunkIndex())
    assert pw.flush() is None


def test_pack_writer_n1_flush():
    store = MockStore()
    chunk_id = b"c" * 32
    cdata = b"payload"
    pw = PackWriter(store, max_count=1, chunks=ChunkIndex())
    results = pw.add(chunk_id, cdata)
    assert results is not None
    assert len(results) == 1
    stored_id, pack_id, obj_offset, obj_size = results[0]
    assert stored_id == chunk_id
    assert pack_id == sha256(cdata).digest()
    assert obj_offset == 0
    assert obj_size == len(cdata)


def test_pack_writer_n2_flush():
    store = MockStore()
    id1, id2 = b"a" * 32, b"b" * 32
    data1, data2 = b"first", b"second"
    pw = PackWriter(store, max_count=2, chunks=ChunkIndex())
    assert pw.add(id1, data1) is None
    results = pw.add(id2, data2)
    assert results is not None
    assert len(results) == 2
    pack_data = data1 + data2
    expected_pack_id = sha256(pack_data).digest()
    assert results[0] == (id1, expected_pack_id, 0, len(data1))
    assert results[1] == (id2, expected_pack_id, len(data1), len(data2))


def test_pack_writer_flushes_on_max_size():
    # max_count is high, so the flush is driven by max_size alone.
    store = MockStore()
    pw = PackWriter(store, max_count=100, max_size=10, chunks=ChunkIndex())
    assert pw.add(b"a" * 32, b"12345") is None
    results = pw.add(b"b" * 32, b"67890")
    assert results is not None
    assert len(results) == 2


def test_pack_writer_max_size_none_is_count_only():
    store = MockStore()
    pw = PackWriter(store, max_count=2, max_size=None, chunks=ChunkIndex())
    assert pw.add(b"a" * 32, b"x" * 10_000) is None
    assert pw.add(b"b" * 32, b"y" * 10_000) is not None


def test_pack_writer_max_count_none_is_size_only():
    store = MockStore()
    pw = PackWriter(store, max_count=None, max_size=10, chunks=ChunkIndex())
    assert pw.add(b"a" * 32, b"12345") is None
    assert pw.add(b"b" * 32, b"67890") is not None


def test_pack_writer_requires_a_limit():
    with pytest.raises(ValueError):
        PackWriter(MockStore(), max_count=None, max_size=None, chunks=ChunkIndex())


def test_pack_writer_rolls_back_index_on_failed_store():
    # If store.store() fails, flush() must drop the entries add() pre-marked, otherwise the index
    # keeps a phantom (indexed but never stored) chunk that seen_chunk() reports as present and a
    # later identical chunk would dedup against -- silent data loss (#9744 review).
    chunks = ChunkIndex()
    chunk_id = b"e" * 32
    pw = PackWriter(FailingPackStore(MockStore()), max_count=1, chunks=chunks)
    with pytest.raises(OSError):
        pw.add(chunk_id, b"payload")  # max_count=1 -> add() flushes immediately and fails
    assert chunks.get(chunk_id) is None  # rolled back: no phantom entry left behind


def test_failed_store_phantom_not_persisted(tmp_path):
    # The phantom must not survive into the persisted repo index either: close() can write the
    # in-memory index on context exit, so the rollback has to happen before anything is serialized.
    from ..cache import write_chunkindex_to_repo, build_chunkindex_from_repo

    chunk_id = H(60)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        # fail only the pack write on the repository's own store; index/* writes still work,
        # so one store models "just the pack write broke" (PackWriter and the index share a
        # store in production). the failing store is thus load-bearing for every assertion below.
        repository.store = FailingPackStore(repository.store)
        pw = PackWriter(repository.store, max_count=1, repository=repository)
        with pytest.raises(OSError):
            pw.add(chunk_id, fchunk(b"DATA"))
        assert repository.chunks.get(chunk_id) is None  # rolled back from the in-memory index ...
        # ... and persisting + reloading the index (through that same store) does not bring it back:
        write_chunkindex_to_repo(repository, repository.chunks, incremental=True)
        reloaded = build_chunkindex_from_repo(repository)
        assert reloaded.get(chunk_id) is None


def test_get_read_data_false_with_range(tmp_path):
    # read_data=False with ChunkIndex entries limits the load to each object's boundary.
    hdr_size = RepoObj.obj_header.size
    chunk1 = fchunk(b"FIRST")
    chunk2 = fchunk(b"SECOND")
    pack = chunk1 + chunk2
    pack_id = H(43)
    id1, id2 = H(47), H(48)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store("packs/" + bin_to_hex(pack_id), pack)
        chunks = ChunkIndex()
        chunks.add(id1, len(chunk1))
        chunks.update_pack_info([(id1, pack_id, 0, len(chunk1))])
        chunks.add(id2, len(chunk2))
        chunks.update_pack_info([(id2, pack_id, len(chunk1), len(chunk2))])
        repository.chunks = chunks
        assert repository.get(id1, read_data=False) == chunk1[:hdr_size]
        assert repository.get(id2, read_data=False) == chunk2[:hdr_size]


def test_get_read_data_false_large_meta(tmp_path):
    # When meta_size > extra_size (975 bytes), get() retries with a larger load.
    hdr_size = RepoObj.obj_header.size
    # the first try loads ~1KB, so use a meta clearly past that boundary to force the retry path.
    big_meta = b"M" * 5000
    chunk = fchunk(b"DATA", meta=big_meta)
    pack_id = H(44)
    chunk_id = H(49)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store("packs/" + bin_to_hex(pack_id), chunk)
        chunks = ChunkIndex()
        chunks.add(chunk_id, len(chunk))
        chunks.update_pack_info([(chunk_id, pack_id, 0, len(chunk))])
        repository.chunks = chunks
        result = repository.get(chunk_id, read_data=False)
        assert result == chunk[: hdr_size + len(big_meta)]


def test_get_uses_chunk_index_location(tmp_path):
    # get() routes to the correct pack and offset when a ChunkIndex is assigned via the chunks property.
    chunk1 = fchunk(b"FIRST")
    chunk2 = fchunk(b"SECOND")
    pack = chunk1 + chunk2
    pack_id = H(55)
    id1, id2 = H(56), H(57)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        # Inject the pack directly; bypasses PackWriter to test routing independently.
        repository.store_store("packs/" + bin_to_hex(pack_id), pack)
        chunks = ChunkIndex()
        chunks.add(id1, len(chunk1))
        chunks.update_pack_info([(id1, pack_id, 0, len(chunk1))])
        chunks.add(id2, len(chunk2))
        chunks.update_pack_info([(id2, pack_id, len(chunk1), len(chunk2))])
        repository.chunks = chunks
        assert repository.get(id1) == chunk1
        assert repository.get(id2) == chunk2


def test_put_marks_id_in_chunk_index(tmp_path):
    # put() marks the id pending; flush() sets the real pack location and clears the pending flag.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        id1 = H(1)
        repository.put(id1, fchunk(b"ZEROS"))
        entry = repository._chunks.get(id1)
        assert entry is not None
        assert repository._chunks.is_pending(id1)  # buffered, not yet flushed
        repository.flush()
        entry = repository._chunks.get(id1)
        assert not repository._chunks.is_pending(id1)
        assert entry.pack_id == sha256(fchunk(b"ZEROS")).digest()
        assert entry.size == 0  # uncompressed size filled in by cache layer


def test_list_skips_pending_chunk(tmp_path):
    # list() skips a pending chunk and yields it once flushed.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.put(H(1), fchunk(b"BUFFERED"))  # buffered: the pack is not full yet
        assert repository._chunks.is_pending(H(1))
        assert repository.list() == []
        repository.flush()
        assert [chunk_id for chunk_id, _ in repository.list()] == [H(1)]


def test_get_pending_chunk_raises(tmp_path):
    # get() on a pending chunk raises PackLocationUnknown, also with raise_missing=False.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.put(H(1), fchunk(b"BUFFERED"))  # buffered: the pack is not full yet
        assert repository._chunks.is_pending(H(1))
        with pytest.raises(Repository.PackLocationUnknown):
            repository.get(H(1))
        with pytest.raises(Repository.PackLocationUnknown):
            repository.get(H(1), raise_missing=False)
        repository.flush()  # close() requires the buffer to be empty


def test_flush_store_failure_drops_pending_entries(tmp_path):
    # flush() removes the pending index entries when storing the pack fails.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.put(H(1), fchunk(b"BUFFERED"))
        assert repository._chunks.is_pending(H(1))

        def boom(*args, **kwargs):
            raise OSError("store failed")

        repository._pack_writer.store.store = boom
        with pytest.raises(OSError):
            repository.flush()
        assert H(1) not in repository._chunks


def test_check_detects_corruption_in_later_object(tmp_path):
    # Corruption anywhere in a multi-object pack must be caught, not just in the first object: the pack
    # is named by sha256(content), so flipping any byte makes its stored hash differ from its name.
    chunk1 = fchunk(b"FIRST", chunk_id=H(1))
    chunk2 = fchunk(b"SECOND", chunk_id=H(2))
    pack = chunk1 + chunk2
    pack_name = "packs/" + bin_to_hex(sha256(pack).digest())
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store(pack_name, pack)
        assert repository.check(repair=False) is True  # both objects are intact

        # flip a byte of the SECOND object's OBJ_MAGIC; the first object stays valid.
        corrupted = bytearray(pack)
        corrupted[len(chunk1)] ^= 0xFF
        repository.store_store(pack_name, bytes(corrupted))
        assert repository.check(repair=False) is False  # corruption past object 1 is detected


def test_check_detects_index_corruption(tmp_path):
    # index/ objects are named by sha256(content) like packs, so check verifies them the same way.
    content = b"pretend this is a serialized chunk index"
    index_name = "index/" + bin_to_hex(sha256(content).digest())
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store(index_name, content)
        assert repository.check(repair=False) is True  # index object intact (name == sha256(content))

        corrupted = bytearray(content)
        corrupted[0] ^= 0xFF
        repository.store_store(index_name, bytes(corrupted))  # same name, rotted content
        assert repository.check(repair=False) is False  # mismatch between content hash and name detected


def test_check_warns_on_invalid_chunk_index(tmp_path, caplog):
    # check warns about an invalid chunk index but does not fail, since the index is not part of
    # the repository's object integrity.
    import logging
    from ..cache import write_chunkindex_invalid

    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        write_chunkindex_invalid(repository)
        with caplog.at_level(logging.WARNING):
            assert repository.check(repair=False) is True
        assert "chunk index is invalid" in caplog.text


def test_check_intact_multi_object_pack_passes(tmp_path):
    # An intact pack with several objects passes: it is hashed as a whole, so the object count
    # does not matter.
    pack = fchunk(b"A", chunk_id=H(1)) + fchunk(b"BB", chunk_id=H(2)) + fchunk(b"CCC", chunk_id=H(3))
    pack_name = "packs/" + bin_to_hex(sha256(pack).digest())
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store(pack_name, pack)
        assert repository.check(repair=False) is True


def test_check_checked_packs_roundtrip(tmp_path):
    # the set survives a store/load round-trip; a rotted blob loads as empty.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        tracker = PackTracker.new(repository.store)
        tracker.table[H(1)] = PackTracker.Entry(timestamp=123, result=1)
        tracker.table[H(2)] = PackTracker.Entry(timestamp=456, result=0)
        tracker.save()

        loaded = PackTracker.load(repository.store)
        assert len(loaded) == 2
        assert H(1) in loaded.table and H(2) in loaded.table
        assert tuple(loaded.table[H(2)]) == (456, 0)

        corrupted = bytearray(repository.store.load(PackTracker.NAME))
        corrupted[0] ^= 0xFF  # break the appended sha256
        repository.store.store(PackTracker.NAME, bytes(corrupted))
        rotted = PackTracker.load(repository.store)
        assert len(rotted) == 0


def test_check_partial_rechecks_pack_sorting_before_checked_one(tmp_path):
    # a partial check verifies a new pack even when its id sorts before an already-checked pack.
    intact = fchunk(b"INTACT", chunk_id=H(1))
    intact_id = sha256(intact).digest()
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store("packs/" + bin_to_hex(intact_id), intact)

        # mark the intact pack as already checked in this cycle.
        tracker = PackTracker.new(repository.store)
        tracker.record(intact_id, ok=True)
        tracker.save()

        # add a corrupt pack (content does not hash to its name) whose id sorts before intact_id.
        early_id = b"\x00" * 32
        assert bin_to_hex(early_id) < bin_to_hex(intact_id)
        repository.store_store("packs/" + bin_to_hex(early_id), b"CORRUPT-does-not-match-name")

        assert repository.check(repair=False, max_duration=3600) is False


def test_check_partial_rechecks_pack_recorded_corrupt(tmp_path):
    # a pack recorded corrupt earlier in the cycle is re-verified, so the corruption keeps being reported.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        corrupt_id = H(1)  # stored content does not hash to this name
        repository.store_store("packs/" + bin_to_hex(corrupt_id), b"CORRUPT-does-not-match-name")

        tracker = PackTracker.new(repository.store)
        tracker.record(corrupt_id, ok=False)
        tracker.save()

        assert repository.check(repair=False, max_duration=3600) is False


def _spy_hash(repository, monkeypatch):
    # collect the keys passed to store.hash. check() hashes a pack exactly when it verifies it.
    hashed_keys = []
    orig_hash = repository.store.hash

    def spy_hash(key):
        hashed_keys.append(key)
        return orig_hash(key)

    monkeypatch.setattr(repository.store, "hash", spy_hash)
    return hashed_keys


def _store_intact_pack(repository):
    intact = fchunk(b"INTACT", chunk_id=H(1))
    intact_id = sha256(intact).digest()
    pack_key = "packs/" + bin_to_hex(intact_id)
    repository.store_store(pack_key, intact)
    return intact_id, pack_key


def test_check_partial_clears_recorded_corruption_when_intact(tmp_path, monkeypatch):
    # a pack recorded corrupt is re-verified, and an intact result replaces the stale record.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        intact_id, pack_key = _store_intact_pack(repository)

        tracker = PackTracker.new(repository.store)
        tracker.record(intact_id, ok=False)  # stale corrupt record
        tracker.save()

        hashed_keys = _spy_hash(repository, monkeypatch)

        assert repository.check(repair=False, max_duration=3600) is True
        assert pack_key in hashed_keys  # re-verified


def test_check_partial_skips_pack_recorded_intact(tmp_path, monkeypatch):
    # a pack recorded intact in this cycle is skipped when a partial check resumes.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        intact_id, pack_key = _store_intact_pack(repository)

        tracker = PackTracker.new(repository.store)
        tracker.record(intact_id, ok=True)
        tracker.save()

        hashed_keys = _spy_hash(repository, monkeypatch)

        assert repository.check(repair=False, max_duration=3600) is True
        assert pack_key not in hashed_keys  # skipped, not re-verified


def test_check_full_ignores_recorded_set(tmp_path, monkeypatch):
    # a full check verifies every pack regardless of the recorded set, then drops the set.
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        intact_id, pack_key = _store_intact_pack(repository)

        tracker = PackTracker.new(repository.store)
        tracker.record(intact_id, ok=True)
        tracker.save()

        hashed_keys = _spy_hash(repository, monkeypatch)

        assert repository.check(repair=False) is True
        assert pack_key in hashed_keys  # verified

        after = PackTracker.load(repository.store)
        assert len(after) == 0  # cycle complete, set dropped


def test_check_checked_packs_ignores_foreign_entry_layout(tmp_path):
    # load() drops a set whose entries have a different layout than Entry, even though its sha256 matches.
    OtherEntry = namedtuple("OtherEntry", "timestamp result extra")
    OtherFormat = namedtuple("OtherFormat", "timestamp result extra")
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        table = HashTableNT(
            key_size=32, value_type=OtherEntry, value_format=OtherFormat(timestamp="Q", result="B", extra="B")
        )
        table[H(1)] = OtherEntry(timestamp=123, result=1, extra=9)
        with io.BytesIO() as f:
            table.write(f)
            data = f.getvalue()
        repository.store_store(PackTracker.NAME, data + sha256(data).digest())

        tracker = PackTracker.load(repository.store)
        assert len(tracker) == 0


def test_check_progress_covers_packs_and_index(tmp_path, monkeypatch):
    # check() uses a separate progress indicator for index/ and for packs/. Each one is sized to its own
    # namespace and driven to 100% by a final show(current=total). A fake indicator records the wiring
    # without depending on log output.
    indicators = []

    class FakePI:
        def __init__(self, total=0, **kwargs):
            self.total = total
            self.position = 0
            indicators.append(self)

        def show(self, current=None, increase=0, *args, **kwargs):
            self.position = current if current is not None else self.position + increase

        def finish(self, *args, **kwargs):
            pass

    monkeypatch.setattr("borg.repository.ProgressIndicatorPercent", FakePI)
    pack = fchunk(b"A", chunk_id=H(1))
    pack_name = "packs/" + bin_to_hex(sha256(pack).digest())
    index_content = b"serialized chunk index"
    index_name = "index/" + bin_to_hex(sha256(index_content).digest())
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store(pack_name, pack)
        repository.store_store(index_name, index_content)
        # create() already wrote a chunk index, so don't assume a count: derive it from the store.
        n_packs = len(repository.store_list("packs"))
        n_index = len(repository.store_list("index"))
        assert repository.check(repair=False) is True
    # one indicator per namespace, each sized to its own object count ...
    assert sorted(pi.total for pi in indicators) == sorted([n_index, n_packs])
    # ... and each driven all the way to 100%.
    for pi in indicators:
        assert pi.position == pi.total


def test_pack_writer_final_partial_pack_uses_sha256():
    # A final flush with fewer pieces than max_count must still use SHA256(pack_bytes).
    store = MockStore()
    chunk_id = b"d" * 32
    cdata = b"solo"
    pw = PackWriter(store, max_count=3, chunks=ChunkIndex())
    assert pw.add(chunk_id, cdata) is None
    results = pw.flush()
    assert results is not None
    assert len(results) == 1
    _, pack_id, _, _ = results[0]
    assert pack_id == sha256(cdata).digest()
    assert pack_id != chunk_id


def test_pack_reader_in_memory_walks_objects():
    obj1 = fchunk(b"payload-one", meta=b"meta1", chunk_id=H(1))
    obj2 = fchunk(b"d2", meta=b"m2", chunk_id=H(2))
    pack = obj1 + obj2
    headers = PackReader(pack_contents=pack).iter_headers()
    assert list(headers) == [(H(1), 0, len(obj1)), (H(2), len(obj1), len(obj2))]


def test_pack_reader_empty_pack():
    assert list(PackReader(pack_contents=b"").iter_headers()) == []


def test_pack_reader_stops_on_trailing_partial_header():
    # a truncated trailing header is a clean stop, not an error
    obj = fchunk(b"data", meta=b"meta", chunk_id=H(3))
    pack = obj + b"\x00\x00\x00"
    assert list(PackReader(pack_contents=pack).iter_headers()) == [(H(3), 0, len(obj))]


def test_pack_reader_iter_headers_reads_through_store(tmp_path):
    obj1 = fchunk(b"FIRST", chunk_id=H(47))
    obj2 = fchunk(b"SECOND", chunk_id=H(48))
    pack = obj1 + obj2
    pack_id = H(43)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store("packs/" + bin_to_hex(pack_id), pack)
        reader = PackReader(repository.store, pack_id)
        assert list(reader.iter_headers()) == [(H(47), 0, len(obj1)), (H(48), len(obj1), len(obj2))]
