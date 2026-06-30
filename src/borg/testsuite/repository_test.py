import os
import sys
from hashlib import sha256

import pytest
from ..helpers import IntegrityError, Location, bin_to_hex
from ..hashindex import ChunkIndex
from ..repository import Repository, MAX_DATA_SIZE, rest_serve_command, PackWriter, PackReader
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
    monkeypatch.delenv("BORGSTORE_RSH", raising=False)
    monkeypatch.delenv("BORG_REMOTE_PATH", raising=False)
    cmd = rest_serve_command(Location("rest://user@host:2222/repo/path"))
    assert cmd[:4] == ["ssh", "-p", "2222", "user@host"]
    assert cmd[4:] == ["borg", "serve", "--rest", "--backend", "FILE:repo/path"]


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


def build_one_pack(repository, objects):
    with repository:
        repository._pack_writer.max_count = len(objects) + 1  # prevent per-put flush; one pack on flush()
        for chunk_id, chunk in objects:
            repository.put(chunk_id, chunk)
        repository.flush()


def test_compact_pack_copy_forward(repo_fixtures, request):
    # Keep a subset of a multi-object pack: survivors must read back, the dropped object and its bytes gone.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    chunk2 = fchunk(b"DATA2", chunk_id=H(2))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1), (H(2), chunk2)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        assert repository.chunks[H(1)].pack_id == old_pack_id
        assert repository.chunks[H(2)].pack_id == old_pack_id

        new_pack_id = repository.compact_pack(old_pack_id, keep_ids={H(0), H(2)}, drop_ids={H(1)})

        assert new_pack_id is not None and new_pack_id != old_pack_id
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

        assert repository.compact_pack(old_pack_id, keep_ids=set(), drop_ids={H(0), H(1)}) is None

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

        new_pack_id = repository.compact_pack(old_pack_id, keep_ids={H(1), H(0)}, drop_ids=set())  # out of order

        assert new_pack_id == old_pack_id
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert pdchunk(repository.get(H(1))) == b"DATA1"


def test_compact_pack_complete_detects_short_coverage(repo_fixtures, request):
    # complete=True must catch a pack whose listed objects do not reach its end: shrink the last
    # object's recorded obj_size so the summed coverage falls short of the actual pack file size.
    chunk0 = fchunk(b"DATA0", chunk_id=H(0))
    chunk1 = fchunk(b"DATA1", chunk_id=H(1))
    repository = get_repository_from_fixture(repo_fixtures, request)
    build_one_pack(repository, [(H(0), chunk0), (H(1), chunk1)])
    with repository:
        old_pack_id = repository.chunks[H(0)].pack_id
        entry = repository.chunks[H(1)]
        repository.chunks[H(1)] = entry._replace(obj_size=entry.obj_size - 1)  # leave 1 trailing byte unaccounted

        with pytest.raises(AssertionError):
            repository.compact_pack(old_pack_id, keep_ids={H(0), H(1)}, drop_ids=set())
        assert bin_to_hex(old_pack_id) in [info.name for info in repository.store_list("packs")]


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
    # The phantom must not survive into the persisted repo cache either: close() can write the
    # in-memory index on context exit, so the rollback has to happen before anything is serialized.
    from ..cache import write_chunkindex_to_repo, build_chunkindex_from_repo

    chunk_id = H(60)
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        # fail only the pack write on the repository's own store; index/* writes still work,
        # so one store models "just the pack write broke" (PackWriter and the index cache share a
        # store in production). the failing store is thus load-bearing for every assertion below.
        repository.store = FailingPackStore(repository.store)
        pw = PackWriter(repository.store, max_count=1, repository=repository)
        with pytest.raises(OSError):
            pw.add(chunk_id, fchunk(b"DATA"))
        assert repository.chunks.get(chunk_id) is None  # rolled back from the in-memory index ...
        # ... and persisting + reloading the cache (through that same store) does not bring it back:
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


def test_check_intact_multi_object_pack_passes(tmp_path):
    # An intact pack with several objects passes: it is hashed as a whole, so the object count
    # does not matter.
    pack = fchunk(b"A", chunk_id=H(1)) + fchunk(b"BB", chunk_id=H(2)) + fchunk(b"CCC", chunk_id=H(3))
    pack_name = "packs/" + bin_to_hex(sha256(pack).digest())
    with Repository(str(tmp_path / "repo"), exclusive=True, create=True) as repository:
        repository.store_store(pack_name, pack)
        assert repository.check(repair=False) is True


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
