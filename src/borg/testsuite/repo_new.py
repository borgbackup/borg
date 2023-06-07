import os
import shutil
from contextlib import contextmanager

import pytest

from ..helpers import IntegrityError
from ..repository import Repository, MAX_DATA_SIZE, TAG_DELETE, TAG_PUT2, TAG_PUT, TAG_COMMIT, MAGIC
from ..repoobj import RepoObj
from .hashindex import H

UNSPECIFIED = object()  # for default values where we can't use None
EXCLUSIVE = True


@pytest.fixture()
def repository(tmpdir, exclusive=UNSPECIFIED, create=True):
    if exclusive is UNSPECIFIED:
        exclusive = EXCLUSIVE
    repository_location = os.path.join(str(tmpdir), "repository")
    repository = Repository(repository_location, exclusive=exclusive, create=create)
    yield repository.__enter__()
    repository.__exit__(None, None, None)
    shutil.rmtree(str(tmpdir))


@pytest.fixture()
@contextmanager
def reopened_repository(repository, exclusive=UNSPECIFIED):
    repository.__exit__(None, None, None)
    reopened_repository = Repository(repository.path, exclusive=exclusive, create=False)
    yield reopened_repository.__enter__()
    repository.__exit__(None, None, None)


def fchunk(data, meta=b""):
    # create a raw chunk that has valid RepoObj layout, but does not use encryption or compression.
    meta_len = RepoObj.meta_len_hdr.pack(len(meta))
    assert isinstance(data, bytes)
    chunk = meta_len + meta + data
    return chunk


def pchunk(chunk):
    # parse data and meta from a raw chunk made by fchunk
    meta_len_size = RepoObj.meta_len_hdr.size
    meta_len = chunk[:meta_len_size]
    meta_len = RepoObj.meta_len_hdr.unpack(meta_len)[0]
    meta = chunk[meta_len_size : meta_len_size + meta_len]
    data = chunk[meta_len_size + meta_len :]
    return data, meta


def pdchunk(chunk):
    # parse only data from a raw chunk made by fchunk
    return pchunk(chunk)[0]


def add_keys(repository):
    repository.put(H(0), fchunk(b"foo"))
    repository.put(H(1), fchunk(b"bar"))
    repository.put(H(3), fchunk(b"bar"))
    repository.commit(compact=False)
    repository.put(H(1), fchunk(b"bar2"))
    repository.put(H(2), fchunk(b"boo"))
    repository.delete(H(3))


def repo_dump(repository, label=None):
    label = label + ": " if label is not None else ""
    H_trans = {H(i): i for i in range(10)}
    H_trans[None] = -1  # key == None appears in commits
    tag_trans = {TAG_PUT2: "put2", TAG_PUT: "put", TAG_DELETE: "del", TAG_COMMIT: "comm"}
    for segment, fn in repository.io.segment_iterator():
        for tag, key, offset, size, _ in repository.io.iter_objects(segment):
            print("%s%s H(%d) -> %s[%d..+%d]" % (label, tag_trans[tag], H_trans[key], fn, offset, size))
    print()


def test1(repository, reopened_repository):
    for x in range(100):
        repository.put(H(x), fchunk(b"SOMEDATA"))
    key50 = H(50)
    assert pdchunk(repository.get(key50)) == b"SOMEDATA"
    repository.delete(key50)
    with pytest.raises(Repository.ObjectNotFound):
        repository.get(key50)
    repository.commit(compact=False)
    with reopened_repository as repository:
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(key50)
        for x in range(100):
            if x == 50:
                continue
            assert pdchunk(repository.get(H(x))) == b"SOMEDATA"


def test2(repository):
    """Test multiple sequential transactions"""
    repository.put(H(0), fchunk(b"foo"))
    repository.put(H(1), fchunk(b"foo"))
    repository.commit(compact=False)
    repository.delete(H(0))
    repository.put(H(1), fchunk(b"bar"))
    repository.commit(compact=False)
    assert pdchunk(repository.get(H(1))) == b"bar"


def test_read_data(repository):
    meta, data = b"meta", b"data"
    meta_len = RepoObj.meta_len_hdr.pack(len(meta))
    chunk_complete = meta_len + meta + data
    chunk_short = meta_len + meta
    repository.put(H(0), chunk_complete)
    repository.commit(compact=False)
    assert repository.get(H(0)) == chunk_complete
    assert repository.get(H(0), read_data=True) == chunk_complete
    assert repository.get(H(0), read_data=False) == chunk_short


def test_consistency(repository):
    repository.put(H(0), fchunk(b"foo"))
    assert pdchunk(repository.get(H(0))) == b"foo"
    repository.put(H(0), fchunk(b"foo2"))
    assert pdchunk(repository.get(H(0))) == b"foo2"
    repository.put(H(0), fchunk(b"bar"))
    assert pdchunk(repository.get(H(0))) == b"bar"
    repository.delete(H(0))
    with pytest.raises(Repository.ObjectNotFound):
        repository.get(H(0))


def test_consistency2(repository):
    repository.put(H(0), fchunk(b"foo"))
    assert pdchunk(repository.get(H(0))) == b"foo"
    repository.commit(compact=False)
    repository.put(H(0), fchunk(b"foo2"))
    assert pdchunk(repository.get(H(0))) == b"foo2"
    repository.rollback()
    assert pdchunk(repository.get(H(0))) == b"foo"


def test_overwrite_in_same_transaction(repository):
    repository.put(H(0), fchunk(b"foo"))
    repository.put(H(0), fchunk(b"foo2"))
    repository.commit(compact=False)
    assert pdchunk(repository.get(H(0))) == b"foo2"


def test_single_kind_transactions(repository):
    # put
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=False)
    # replace
    repository.put(H(0), fchunk(b"bar"))
    repository.commit(compact=False)
    # delete
    repository.delete(H(0))
    repository.commit(compact=False)


def test_list(repository):
    for x in range(100):
        repository.put(H(x), fchunk(b"SOMEDATA"))
    repository.commit(compact=False)
    repo_list = repository.list()
    assert len(repo_list) == 100
    first_half = repository.list(limit=50)
    assert len(first_half) == 50
    assert first_half == repo_list[:50]
    second_half = repository.list(marker=first_half[-1])
    assert len(second_half) == 50
    assert second_half == repo_list[50:]
    assert len(repository.list(limit=50)) == 50


def test_scan(repository):
    for x in range(100):
        repository.put(H(x), fchunk(b"SOMEDATA"))
    repository.commit(compact=False)
    ids, _ = repository.scan()
    assert len(ids) == 100
    first_half, state = repository.scan(limit=50)
    assert len(first_half) == 50
    assert first_half == ids[:50]
    second_half, _ = repository.scan(state=state)
    assert len(second_half) == 50
    assert second_half == ids[50:]
    # check result order == on-disk order (which is hash order)
    for x in range(100):
        assert ids[x] == H(x)


def test_scan_modify(repository):
    for x in range(100):
        repository.put(H(x), fchunk(b"ORIGINAL"))
    repository.commit(compact=False)
    # now we scan, read and modify chunks at the same time
    count = 0
    ids, _ = repository.scan()
    for id in ids:
        # scan results are in same order as we put the chunks into the repo (into the segment file)
        assert id == H(count)
        chunk = repository.get(id)
        # check that we **only** get data that was committed when we started scanning
        # and that we do not run into the new data we put into the repo.
        assert pdchunk(chunk) == b"ORIGINAL"
        count += 1
        repository.put(id, fchunk(b"MODIFIED"))
    assert count == 100
    repository.commit()

    # now we have committed all the modified chunks, and **only** must get the modified ones.
    count = 0
    ids, _ = repository.scan()
    for id in ids:
        # scan results are in same order as we put the chunks into the repo (into the segment file)
        assert id == H(count)
        chunk = repository.get(id)
        assert pdchunk(chunk) == b"MODIFIED"
        count += 1
    assert count == 100


def test_max_data_size(repository):
    max_data = b"x" * (MAX_DATA_SIZE - RepoObj.meta_len_hdr.size)
    repository.put(H(0), fchunk(max_data))
    assert pdchunk(repository.get(H(0))) == max_data
    with pytest.raises(IntegrityError):
        repository.put(H(1), fchunk(max_data + b"x"))


def test_set_flags(repository):
    id = H(0)
    repository.put(id, fchunk(b""))
    assert repository.flags(id) == 0x00000000  # init == all zero
    repository.flags(id, mask=0x00000001, value=0x00000001)
    assert repository.flags(id) == 0x00000001
    repository.flags(id, mask=0x00000002, value=0x00000002)
    assert repository.flags(id) == 0x00000003
    repository.flags(id, mask=0x00000001, value=0x00000000)
    assert repository.flags(id) == 0x00000002
    repository.flags(id, mask=0x00000002, value=0x00000000)
    assert repository.flags(id) == 0x00000000


def test_get_flags(repository):
    id = H(0)
    repository.put(id, fchunk(b""))
    assert repository.flags(id) == 0x00000000  # init == all zero
    repository.flags(id, mask=0xC0000003, value=0x80000001)
    assert repository.flags(id, mask=0x00000001) == 0x00000001
    assert repository.flags(id, mask=0x00000002) == 0x00000000
    assert repository.flags(id, mask=0x40000008) == 0x00000000
    assert repository.flags(id, mask=0x80000000) == 0x80000000


def test_flags_many(repository):
    ids_flagged = [H(0), H(1)]
    ids_default_flags = [H(2), H(3)]
    [repository.put(id, fchunk(b"")) for id in ids_flagged + ids_default_flags]
    repository.flags_many(ids_flagged, mask=0xFFFFFFFF, value=0xDEADBEEF)
    assert list(repository.flags_many(ids_default_flags)) == [0x00000000, 0x00000000]
    assert list(repository.flags_many(ids_flagged)) == [0xDEADBEEF, 0xDEADBEEF]
    assert list(repository.flags_many(ids_flagged, mask=0xFFFF0000)) == [0xDEAD0000, 0xDEAD0000]
    assert list(repository.flags_many(ids_flagged, mask=0x0000FFFF)) == [0x0000BEEF, 0x0000BEEF]


def test_flags_persistence(repository, reopened_repository):
    repository.put(H(0), fchunk(b"default"))
    repository.put(H(1), fchunk(b"one one zero"))
    # we do not set flags for H(0), so we can later check their default state.
    repository.flags(H(1), mask=0x00000007, value=0x00000006)
    repository.commit(compact=False)
    with reopened_repository as repository:
        # we query all flags to check if the initial flags were all zero and
        # only the ones we explicitly set to one are as expected.
        assert repository.flags(H(0), mask=0xFFFFFFFF) == 0x00000000
        assert repository.flags(H(1), mask=0xFFFFFFFF) == 0x00000006
        # test case that doesn't work with remote repositories


def _assert_sparse(repository):
    # The superseded 123456... PUT
    assert repository.compact[0] == 41 + 8 + len(fchunk(b"123456789"))
    # a COMMIT
    assert repository.compact[1] == 9
    # The DELETE issued by the superseding PUT (or issued directly)
    assert repository.compact[2] == 41
    repository._rebuild_sparse(0)
    assert repository.compact[0] == 41 + 8 + len(fchunk(b"123456789"))  # 9 is chunk or commit?


def test_sparse1(repository):
    repository.put(H(0), fchunk(b"foo"))
    repository.put(H(1), fchunk(b"123456789"))
    repository.commit(compact=False)
    repository.put(H(1), fchunk(b"bar"))
    _assert_sparse(repository)


def test_sparse2(repository):
    repository.put(H(0), fchunk(b"foo"))
    repository.put(H(1), fchunk(b"123456789"))
    repository.commit(compact=False)
    repository.delete(H(1))
    _assert_sparse(repository)


def test_sparse_delete(repository):
    chunk0 = fchunk(b"1245")
    repository.put(H(0), chunk0)
    repository.delete(H(0))
    repository.io._write_fd.sync()
    # The on-line tracking works on a per-object basis...
    assert repository.compact[0] == 41 + 8 + 41 + len(chunk0)
    repository._rebuild_sparse(0)
    # ...while _rebuild_sparse can mark whole segments as completely sparse (which then includes the segment magic)
    assert repository.compact[0] == 41 + 8 + 41 + len(chunk0) + len(MAGIC)
    repository.commit(compact=True)
    assert 0 not in [segment for segment, _ in repository.io.segment_iterator()]


def test_uncommitted_garbage(repository, reopened_repository):
    # uncommitted garbage should be no problem, it is cleaned up automatically.
    # we just have to be careful with invalidation of cached FDs in LoggedIO.
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=False)
    # write some crap to an uncommitted segment file
    last_segment = repository.io.get_latest_segment()
    with open(repository.io.segment_filename(last_segment + 1), "wb") as f:
        f.write(MAGIC + b"crapcrapcrap")
    with reopened_repository as repository:
        # usually, opening the repo and starting a transaction should trigger a cleanup.
        repository.put(H(0), fchunk(b"bar"))  # this may trigger compact_segments()
        repository.commit(compact=True)
        # the point here is that nothing blows up with an exception.


def test_replay_of_missing_index(repository, reopened_repository):
    add_keys(repository)
    for name in os.listdir(repository.path):
        if name.startswith("index."):
            os.unlink(os.path.join(repository.path, name))
    with reopened_repository as repository:
        assert len(repository) == 3
        assert repository.check() is True


def test_crash_before_compact_segments(repository, reopened_repository):
    add_keys(repository)
    repository.compact_segments = None
    try:
        repository.commit(compact=True)
    except TypeError:
        pass
    with reopened_repository as repository:
        assert len(repository) == 3
        assert repository.check() is True


def test_crash_before_write_index(repository, reopened_repository):
    add_keys(repository)
    repository.write_index = None
    try:
        repository.commit(compact=False)
    except TypeError:
        pass
    with reopened_repository as repository:
        assert len(repository) == 3
        assert repository.check() is True
