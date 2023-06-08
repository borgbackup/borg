import os
import shutil
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from borg.hashindex import NSIndex

from ..helpers import IntegrityError, msgpack
from ..locking import Lock, LockFailed
from ..repository import Repository, MAX_DATA_SIZE, TAG_DELETE, TAG_PUT2, TAG_PUT, TAG_COMMIT, MAGIC, LoggedIO
from ..repoobj import RepoObj
from .hashindex import H

UNSPECIFIED = object()  # for default values where we can't use None
exclusive = UNSPECIFIED


def get_exclusive():
    global exclusive
    if exclusive is True:
        return True
    elif exclusive is False:
        return False
    else:
        return UNSPECIFIED


def set_exclusive(value):
    global exclusive
    exclusive = value


@pytest.fixture()
def repository(tmpdir):
    set_exclusive(True)
    repository_location = os.path.join(str(tmpdir), "repository")
    repository = Repository(repository_location, exclusive=get_exclusive(), create=True)
    yield repository.__enter__()
    repository.__exit__(None, None, None)
    shutil.rmtree(str(tmpdir))


@pytest.fixture()
@contextmanager
def reopened_repository(repository):
    repository.__exit__(None, None, None)
    reopened_repository = Repository(repository.path, exclusive=get_exclusive(), create=False)
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


""" REPOSITORY TESTS """


def test_basic_operations(repository, reopened_repository):
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


def test_multiple_transactions(repository):
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


""" LOCAL REPOSITORY TESTS """


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


""" COMMIT TESTS """


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


def test_replay_lock_upgrade(repository, reopened_repository):
    add_keys(repository)
    for name in os.listdir(repository.path):
        if name.startswith("index."):
            os.unlink(os.path.join(repository.path, name))
    with patch.object(Lock, "upgrade", side_effect=LockFailed) as upgrade:
        set_exclusive(False)
        with reopened_repository as repository:
            # current client usually does not do lock upgrade, except for replay
            # the repo is only locked by a shared read lock, but to replay segments,
            # we need an exclusive write lock - check if the lock gets upgraded.
            with pytest.raises(LockFailed):
                len(repository)
            upgrade.assert_called_once_with()


def test_crash_before_deleting_compacted_segments(repository, reopened_repository):
    add_keys(repository)
    repository.io.delete_segment = None
    try:
        repository.commit(compact=False)
    except TypeError:
        pass
    with reopened_repository as repository:
        assert len(repository) == 3
        assert repository.check() is True
        assert len(repository) == 3


def test_ignores_commit_tag_in_data(repository, reopened_repository):
    repository.put(H(0), LoggedIO.COMMIT)
    with reopened_repository as repository:
        io = repository.io
        assert not io.is_committed_segment(io.get_latest_segment())


def test_moved_deletes_are_tracked(repository):
    repository.put(H(1), fchunk(b"1"))
    repository.put(H(2), fchunk(b"2"))
    repository.commit(compact=False)
    repo_dump(repository, "p1 p2 c")
    repository.delete(H(1))
    repository.commit(compact=True)
    repo_dump(repository, "d1 cc")
    last_segment = repository.io.get_latest_segment() - 1
    num_deletes = 0
    for tag, key, offset, size, _ in repository.io.iter_objects(last_segment):
        if tag == TAG_DELETE:
            assert key == H(1)
            num_deletes += 1
    assert num_deletes == 1
    assert last_segment in repository.compact
    repository.put(H(3), fchunk(b"3"))
    repository.commit(compact=True)
    repo_dump(repository, "p3 cc")
    assert last_segment not in repository.compact
    assert not repository.io.segment_exists(last_segment)
    for segment, _ in repository.io.segment_iterator():
        for tag, key, offset, size, _ in repository.io.iter_objects(segment):
            assert tag != TAG_DELETE
            assert key != H(1)
    # after compaction, there should be no empty shadowed_segments lists left over.
    # we have no put or del anymore for H(1), so we lost knowledge about H(1).
    assert H(1) not in repository.shadow_index


def test_shadowed_entries_are_preserved(repository):
    get_latest_segment = repository.io.get_latest_segment
    repository.put(H(1), fchunk(b"1"))
    # This is the segment with our original PUT of interest
    put_segment = get_latest_segment()
    repository.commit(compact=False)

    # We now delete H(1), and force this segment not to be compacted, which can happen
    # if it's not sparse enough (symbolized by H(2) here).
    repository.delete(H(1))
    repository.put(H(2), fchunk(b"1"))
    delete_segment = get_latest_segment()

    # We pretend these are mostly dense (not sparse) and won't be compacted
    del repository.compact[put_segment]
    del repository.compact[delete_segment]

    repository.commit(compact=True)

    # Now we perform an unrelated operation on the segment containing the DELETE,
    # causing it to be compacted.
    repository.delete(H(2))
    repository.commit(compact=True)

    assert repository.io.segment_exists(put_segment)
    assert not repository.io.segment_exists(delete_segment)

    # Basic case, since the index survived this must be ok
    assert H(1) not in repository
    # Nuke index, force replay
    os.unlink(os.path.join(repository.path, "index.%d" % get_latest_segment()))
    # Must not reappear
    assert H(1) not in repository


def test_shadow_index_rollback(repository):
    repository.put(H(1), fchunk(b"1"))
    repository.delete(H(1))
    assert repository.shadow_index[H(1)] == [0]
    repository.commit(compact=True)
    repo_dump(repository, "p1 d1 cc")
    # note how an empty list means that nothing is shadowed for sure
    assert repository.shadow_index[H(1)] == []  # because the delete is considered unstable
    repository.put(H(1), b"1")
    repository.delete(H(1))
    repo_dump(repository, "p1 d1")
    # 0 put/delete; 1 commit; 2 compacted; 3 commit; 4 put/delete
    assert repository.shadow_index[H(1)] == [4]
    repository.rollback()
    repo_dump(repository, "r")
    repository.put(H(2), fchunk(b"1"))
    # After the rollback segment 4 shouldn't be considered anymore
    assert repository.shadow_index[H(1)] == []  # because the delete is considered unstable


""" APPEND-ONLY TESTS """


def test_destroy_append_only(repository):
    # Can't destroy append only repo (via the API)
    repository.append_only = True
    with pytest.raises(ValueError):
        repository.destroy()
    assert repository.append_only


def test_append_only(repository):
    def segments_in_repository(repo):
        return len(list(repo.io.segment_iterator()))

    repository.append_only = True
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=False)

    repository.append_only = False
    assert segments_in_repository(repository) == 2
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=True)
    # normal: compact squashes the data together, only one segment
    assert segments_in_repository(repository) == 2

    repository.append_only = True
    assert segments_in_repository(repository) == 2
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=False)
    # append only: does not compact, only new segments written
    assert segments_in_repository(repository) == 4


""" Free Space Tests """


def test_additional_free_space(repository, reopened_repository):
    add_keys(repository)
    repository.config.set("repository", "additional_free_space", "1000T")
    repository.save_key(b"shortcut to save_config")
    with reopened_repository as repository:
        repository.put(H(0), fchunk(b"foobar"))
        with pytest.raises(Repository.InsufficientFreeSpaceError):
            repository.commit(compact=False)
        assert os.path.exists(repository.path)


def test_create_free_space(repository):
    repository.additional_free_space = 1e20
    with pytest.raises(Repository.InsufficientFreeSpaceError):
        add_keys(repository)
    assert not os.path.exists(repository.path)


""" QUOTA TESTS """


def test_tracking(repository, reopened_repository):
    assert repository.storage_quota_use == 0
    ch1 = fchunk(bytes(1234))
    repository.put(H(1), ch1)
    assert repository.storage_quota_use == len(ch1) + 41 + 8
    ch2 = fchunk(bytes(5678))
    repository.put(H(2), ch2)
    assert repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)
    repository.delete(H(1))
    assert repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)  # we have not compacted yet
    repository.commit(compact=False)
    assert repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)  # we have not compacted yet
    with reopened_repository as repository:
        # Open new transaction; hints and thus quota data is not loaded unless needed.
        ch3 = fchunk(b"")
        repository.put(H(3), ch3)
        repository.delete(H(3))
        assert repository.storage_quota_use == len(ch1) + len(ch2) + len(ch3) + 3 * (
            41 + 8
        )  # we have not compacted yet
        repository.commit(compact=True)
        assert repository.storage_quota_use == len(ch2) + 41 + 8


def test_exceed_quota(repository, reopened_repository):
    assert repository.storage_quota_use == 0
    repository.storage_quota = 80
    ch1 = fchunk(b"x" * 7)
    repository.put(H(1), ch1)
    assert repository.storage_quota_use == len(ch1) + 41 + 8
    repository.commit(compact=False)
    with pytest.raises(Repository.StorageQuotaExceeded):
        ch2 = fchunk(b"y" * 13)
        repository.put(H(2), ch2)
    assert repository.storage_quota_use == len(ch1) + len(ch2) + (41 + 8) * 2  # check ch2!?
    with pytest.raises(Repository.StorageQuotaExceeded):
        repository.commit(compact=False)
    assert repository.storage_quota_use == len(ch1) + len(ch2) + (41 + 8) * 2  # check ch2!?
    with reopened_repository as repository:
        repository.storage_quota = 150
        # Open new transaction; hints and thus quota data is not loaded unless needed.
        repository.put(H(1), ch1)
        assert (
            repository.storage_quota_use == len(ch1) * 2 + (41 + 8) * 2
        )  # we have 2 puts for H(1) here and not yet compacted.
        repository.commit(compact=True)
        assert repository.storage_quota_use == len(ch1) + 41 + 8  # now we have compacted.


""" AUXILIARY CORRUPTION TESTS """


@pytest.fixture()
def auxiliary_repository(repository):
    repository.put(H(0), fchunk(b"foo"))
    repository.commit(compact=False)
    repository.close()
    yield repository


def do_commit(repository):
    with repository:
        repository.put(H(0), fchunk(b"fox"))
        repository.commit(compact=False)


def test_corrupted_hints(auxiliary_repository):
    with auxiliary_repository as repository:
        with open(os.path.join(repository.path, "hints.1"), "ab") as fd:
            fd.write(b"123456789")
        do_commit(repository)


def test_deleted_hints(auxiliary_repository):
    with auxiliary_repository as repository:
        os.unlink(os.path.join(repository.path, "hints.1"))
        do_commit(repository)


def test_deleted_index(auxiliary_repository):
    with auxiliary_repository as repository:
        os.unlink(os.path.join(repository.path, "index.1"))
        do_commit(repository)


def test_unreadable_hints(auxiliary_repository):
    with auxiliary_repository as repository:
        hints = os.path.join(repository.path, "hints.1")
        os.unlink(hints)
        os.mkdir(hints)
        with pytest.raises(OSError):
            do_commit(repository)


def test_index(auxiliary_repository):
    with auxiliary_repository as repository:
        with open(os.path.join(repository.path, "index.1"), "wb") as fd:
            fd.write(b"123456789")
        do_commit(repository)


def test_index_outside_transaction(auxiliary_repository):
    with auxiliary_repository as repository:
        with open(os.path.join(repository.path, "index.1"), "wb") as fd:
            fd.write(b"123456789")
        with repository:
            assert len(repository) == 1


def _corrupt_index(repository):
    # HashIndex is able to detect incorrect headers and file lengths,
    # but on its own it can't tell if the data is correct.
    index_path = os.path.join(repository.path, "index.1")
    with open(index_path, "r+b") as fd:
        index_data = fd.read()
        # Flip one bit in a key stored in the index
        corrupted_key = (int.from_bytes(H(0), "little") ^ 1).to_bytes(32, "little")
        corrupted_index_data = index_data.replace(H(0), corrupted_key)
        assert corrupted_index_data != index_data
        assert len(corrupted_index_data) == len(index_data)
        fd.seek(0)
        fd.write(corrupted_index_data)


def test_index_corrupted(auxiliary_repository):
    # HashIndex is able to detect incorrect headers and file lengths,
    # but on its own it can't tell if the data itself is correct.
    with auxiliary_repository as repository:
        _corrupt_index(repository)
        with repository:
            # Data corruption is detected due to mismatching checksums
            # and fixed by rebuilding the index.
            assert len(repository) == 1
            assert pdchunk(repository.get(H(0))) == b"foo"


def test_index_corrupted_without_integrity(auxiliary_repository):
    with auxiliary_repository as repository:
        _corrupt_index(repository)
        integrity_path = os.path.join(repository.path, "integrity.1")
        os.unlink(integrity_path)
        with repository:
            # Since the corrupted key is not noticed, the repository still thinks
            # it contains one key...
            assert len(repository) == 1
            with pytest.raises(Repository.ObjectNotFound):
                # ... but the real, uncorrupted key is not found in the corrupted index.
                repository.get(H(0))


def test_unreadable_index(auxiliary_repository):
    with auxiliary_repository as repository:
        index = os.path.join(repository.path, "index.1")
        os.unlink(index)
        os.mkdir(index)
        with pytest.raises(OSError):
            do_commit(repository)


def test_unknown_integrity_version(auxiliary_repository):
    # For now an unknown integrity data version is ignored and not an error.
    with auxiliary_repository as repository:
        integrity_path = os.path.join(repository.path, "integrity.1")
        with open(integrity_path, "r+b") as fd:
            msgpack.pack(
                {
                    # Borg only understands version 2
                    b"version": 4.7
                },
                fd,
            )
            fd.truncate()
        with repository:
            # No issues accessing the repository
            assert len(repository) == 1
            assert pdchunk(repository.get(H(0))) == b"foo"


def _subtly_corrupted_hints_setup(repository):
    with repository:
        repository.append_only = True
        assert len(repository) == 1
        assert pdchunk(repository.get(H(0))) == b"foo"
        repository.put(H(1), fchunk(b"bar"))
        repository.put(H(2), fchunk(b"baz"))
        repository.commit(compact=False)
        repository.put(H(2), fchunk(b"bazz"))
        repository.commit(compact=False)

        hints_path = os.path.join(repository.path, "hints.5")
        with open(hints_path, "r+b") as fd:
            hints = msgpack.unpack(fd)
            fd.seek(0)
            # Corrupt segment refcount
            assert hints["segments"][2] == 1
            hints["segments"][2] = 0
            msgpack.pack(hints, fd)
            fd.truncate()


def test_subtly_corrupted_hints(auxiliary_repository):
    with auxiliary_repository as repository:
        _subtly_corrupted_hints_setup(repository)
        with repository:
            repository.append_only = False
            repository.put(H(3), fchunk(b"1234"))
            # Do a compaction run. Succeeds, since the failed checksum prompted a rebuild of the index+hints.
            repository.commit(compact=True)

            assert len(repository) == 4
            assert pdchunk(repository.get(H(0))) == b"foo"
            assert pdchunk(repository.get(H(1))) == b"bar"
            assert pdchunk(repository.get(H(2))) == b"bazz"


def test_subtly_corrupted_hints_without_integrity(auxiliary_repository):
    with auxiliary_repository as repository:
        _subtly_corrupted_hints_setup(repository)
        integrity_path = os.path.join(repository.path, "integrity.5")
        os.unlink(integrity_path)
        with repository:
            repository.append_only = False
            repository.put(H(3), fchunk(b"1234"))
            # Do a compaction run.
            # Fails, since the corrupted refcount was not detected and leads to an assertion failure.
            with pytest.raises(AssertionError) as exc_info:
                repository.commit(compact=True)
            assert "Corrupted segment reference count" in str(exc_info.value)


""" REPOSITORY CHECK TESTS """


def list_indices(repo_path):
    return [name for name in os.listdir(repo_path) if name.startswith("index.")]


def check(repository: Repository, repair=False, status=True):
    assert repository.check(repair=repair) == status
    # Make sure no tmp files are left behind
    tmp_files = [name for name in os.listdir(repository.path) if "tmp" in name]
    assert tmp_files == [], "Found tmp files"


def get_objects(repository: Repository, *ids):
    for id_ in ids:
        pdchunk(repository.get(H(id_)))


def add_objects(repository: Repository, segments):
    for ids in segments:
        for id_ in ids:
            repository.put(H(id_), fchunk(b"data"))
        repository.commit(compact=False)


def get_head(repo_path):
    return sorted(int(n) for n in os.listdir(os.path.join(repo_path, "data", "0")) if n.isdigit())[-1]


def open_index(repo_path):
    return NSIndex.read(os.path.join(repo_path, f"index.{get_head(repo_path)}"))


def corrupt_object(repo_path, id_):
    idx = open_index(repo_path)
    segment, offset, _ = idx[H(id_)]
    with open(os.path.join(repo_path, "data", "0", str(segment)), "r+b") as fd:
        fd.seek(offset)
        fd.write(b"BOOM")


def delete_segment(repository: Repository, segment):
    repository.io.delete_segment(segment)


def delete_index(repo_path):
    os.unlink(os.path.join(repo_path, f"index.{get_head(repo_path)}"))


def rename_index(repo_path, new_name):
    os.replace(os.path.join(repo_path, f"index.{get_head(repo_path)}"), os.path.join(repo_path, "repository", new_name))


def list_objects(repository: Repository):
    return {int(key) for key in repository.list()}


def test_repair_corrupted_segment(repository):
    add_objects(repository, [[1, 2, 3], [4, 5], [6]])
    assert {1, 2, 3, 4, 5, 6} == list_objects(repository)
    check(repository, status=True)
    corrupt_object(repository.path, 5)
    with pytest.raises(IntegrityError):
        get_objects(repository, 5)
    repository.rollback()
    # Make sure a regular check does not repair anything
    check(repository, status=False)
    check(repository, status=False)
    # Make sure a repair actually repairs the repo
    check(repository, repair=True, status=True)
    get_objects(repository, 4)
    check(repository, status=True)
    assert {1, 2, 3, 4, 6} == list_objects(repository)
