import logging
import os
import sys
from unittest.mock import patch

import pytest

from ..checksums import xxh64
from ..hashindex import NSIndex1
from ..helpers import Location
from ..helpers import IntegrityError
from ..helpers import msgpack
from ..fslocking import Lock, LockFailed
from ..platformflags import is_win32
from ..legacyremote import LegacyRemoteRepository, InvalidRPCMethod, PathNotAllowed
from ..legacyrepository import LegacyRepository, LoggedIO
from ..legacyrepository import MAGIC, MAX_DATA_SIZE, TAG_DELETE, TAG_PUT2, TAG_PUT, TAG_COMMIT
from ..repoobj import RepoObj
from .hashindex_test import H


@pytest.fixture()
def repository(tmp_path):
    repository_location = os.fspath(tmp_path / "repository")
    yield LegacyRepository(repository_location, exclusive=True, create=True)


@pytest.fixture()
def remote_repository(tmp_path):
    if is_win32:
        pytest.skip("Remote repository does not yet work on Windows.")
    repository_location = Location("ssh://__testsuite__/" + os.fspath(tmp_path / "repository"))
    yield LegacyRemoteRepository(repository_location, exclusive=True, create=True)


def pytest_generate_tests(metafunc):
    # Generates tests that run on both local and remote repos
    if "repo_fixtures" in metafunc.fixturenames:
        metafunc.parametrize("repo_fixtures", ["repository", "remote_repository"])


def get_repository_from_fixture(repo_fixtures, request):
    # returns the repo object from the fixture for tests that run on both local and remote repos
    return request.getfixturevalue(repo_fixtures)


def reopen(repository, exclusive: bool | None = True, create=False):
    if isinstance(repository, LegacyRepository):
        if repository.io is not None or repository.lock is not None:
            raise RuntimeError("Repo must be closed before a reopen. Cannot support nested repository contexts.")
        return LegacyRepository(repository.path, exclusive=exclusive, create=create)

    if isinstance(repository, LegacyRemoteRepository):
        if repository.p is not None or repository.sock is not None:
            raise RuntimeError("Remote repo must be closed before a reopen. Cannot support nested repository contexts.")
        return LegacyRemoteRepository(repository.location, exclusive=exclusive, create=create)

    raise TypeError(
        f"Invalid argument type. Expected 'Repository' or 'RemoteRepository', received '{type(repository).__name__}'."
    )


def get_path(repository):
    if isinstance(repository, LegacyRepository):
        return repository.path

    if isinstance(repository, LegacyRemoteRepository):
        return repository.location.path

    raise TypeError(
        f"Invalid argument type. Expected 'Repository' or 'RemoteRepository', received '{type(repository).__name__}'."
    )


def fchunk(data, meta=b""):
    # create a raw chunk that has valid RepoObj layout, but does not use encryption or compression.
    hdr = RepoObj.obj_header.pack(len(meta), len(data), xxh64(meta), xxh64(data))
    assert isinstance(data, bytes)
    chunk = hdr + meta + data
    return chunk


def pchunk(chunk):
    # parse data and meta from a raw chunk made by fchunk
    hdr_size = RepoObj.obj_header.size
    hdr = chunk[:hdr_size]
    meta_size, data_size = RepoObj.obj_header.unpack(hdr)[0:2]
    meta = chunk[hdr_size : hdr_size + meta_size]
    data = chunk[hdr_size + meta_size : hdr_size + meta_size + data_size]
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


def test_basic_operations(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA"))
        key50 = H(50)
        assert pdchunk(repository.get(key50)) == b"SOMEDATA"
        repository.delete(key50)
        with pytest.raises(LegacyRepository.ObjectNotFound):
            repository.get(key50)
        repository.commit(compact=False)
    with reopen(repository) as repository:
        with pytest.raises(LegacyRepository.ObjectNotFound):
            repository.get(key50)
        for x in range(100):
            if x == 50:
                continue
            assert pdchunk(repository.get(H(x))) == b"SOMEDATA"


def test_multiple_transactions(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.put(H(1), fchunk(b"foo"))
        repository.commit(compact=False)
        repository.delete(H(0))
        repository.put(H(1), fchunk(b"bar"))
        repository.commit(compact=False)
        assert pdchunk(repository.get(H(1))) == b"bar"


def test_read_data(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        meta, data = b"meta", b"data"
        hdr = RepoObj.obj_header.pack(len(meta), len(data), xxh64(meta), xxh64(data))
        chunk_complete = hdr + meta + data
        chunk_short = hdr + meta
        repository.put(H(0), chunk_complete)
        repository.commit(compact=False)
        assert repository.get(H(0)) == chunk_complete
        assert repository.get(H(0), read_data=True) == chunk_complete
        assert repository.get(H(0), read_data=False) == chunk_short


def test_consistency(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        assert pdchunk(repository.get(H(0))) == b"foo"
        repository.put(H(0), fchunk(b"foo2"))
        assert pdchunk(repository.get(H(0))) == b"foo2"
        repository.put(H(0), fchunk(b"bar"))
        assert pdchunk(repository.get(H(0))) == b"bar"
        repository.delete(H(0))
        with pytest.raises(LegacyRepository.ObjectNotFound):
            repository.get(H(0))


def test_consistency2(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        assert pdchunk(repository.get(H(0))) == b"foo"
        repository.commit(compact=False)
        repository.put(H(0), fchunk(b"foo2"))
        assert pdchunk(repository.get(H(0))) == b"foo2"
        repository.rollback()
        assert pdchunk(repository.get(H(0))) == b"foo"


def test_overwrite_in_same_transaction(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.put(H(0), fchunk(b"foo2"))
        repository.commit(compact=False)
        assert pdchunk(repository.get(H(0))) == b"foo2"


def test_single_kind_transactions(repo_fixtures, request):
    # put
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.commit(compact=False)
    # replace
    with reopen(repository) as repository:
        repository.put(H(0), fchunk(b"bar"))
        repository.commit(compact=False)
    # delete
    with reopen(repository) as repository:
        repository.delete(H(0))
        repository.commit(compact=False)


def test_list(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
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


def test_max_data_size(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        max_data = b"x" * (MAX_DATA_SIZE - RepoObj.obj_header.size)
        repository.put(H(0), fchunk(max_data))
        assert pdchunk(repository.get(H(0))) == max_data
        with pytest.raises(IntegrityError):
            repository.put(H(1), fchunk(max_data + b"x"))
        repository.delete(H(0))


def _assert_sparse(repository):
    # the superseded 123456... PUT
    assert repository.compact[0] == 41 + 8 + 0  # len(fchunk(b"123456789"))
    # a COMMIT
    assert repository.compact[1] == 9
    # the DELETE issued by the superseding PUT (or issued directly)
    assert repository.compact[2] == 41
    repository._rebuild_sparse(0)
    assert repository.compact[0] == 41 + 8 + len(fchunk(b"123456789"))  # 9 is chunk or commit?


def test_sparse1(repository):
    with repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.put(H(1), fchunk(b"123456789"))
        repository.commit(compact=False)
        repository.put(H(1), fchunk(b"bar"))
        _assert_sparse(repository)


def test_sparse2(repository):
    with repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.put(H(1), fchunk(b"123456789"))
        repository.commit(compact=False)
        repository.delete(H(1))
        _assert_sparse(repository)


def test_sparse_delete(repository):
    with repository:
        chunk0 = fchunk(b"1245")
        repository.put(H(0), chunk0)
        repository.delete(H(0))
        repository.io._write_fd.sync()
        # the on-line tracking works on a per-object basis...
        assert repository.compact[0] == 41 + 8 + 41 + 0  # len(chunk0) information is lost
        repository._rebuild_sparse(0)
        # ...while _rebuild_sparse can mark whole segments as completely sparse (which then includes the segment magic)
        assert repository.compact[0] == 41 + 8 + 41 + len(chunk0) + len(MAGIC)
        repository.commit(compact=True)
        assert 0 not in [segment for segment, _ in repository.io.segment_iterator()]


def test_uncommitted_garbage(repository):
    with repository:
        # uncommitted garbage should be no problem, it is cleaned up automatically.
        # we just have to be careful with invalidation of cached FDs in LoggedIO.
        repository.put(H(0), fchunk(b"foo"))
        repository.commit(compact=False)
        # write some crap to an uncommitted segment file
        last_segment = repository.io.get_latest_segment()
        with open(repository.io.segment_filename(last_segment + 1), "wb") as f:
            f.write(MAGIC + b"crapcrapcrap")
    with reopen(repository) as repository:
        # usually, opening the repo and starting a transaction should trigger a cleanup.
        repository.put(H(0), fchunk(b"bar"))  # this may trigger compact_segments()
        repository.commit(compact=True)
        # the point here is that nothing blows up with an exception.


def test_replay_of_missing_index(repository):
    with repository:
        add_keys(repository)
        for name in os.listdir(repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(repository.path, name))
    with reopen(repository) as repository:
        assert len(repository) == 3
        assert repository.check() is True


def test_crash_before_compact_segments(repository):
    with repository:
        add_keys(repository)
        repository.compact_segments = None
        try:
            repository.commit(compact=True)
        except TypeError:
            pass
    with reopen(repository) as repository:
        assert len(repository) == 3
        assert repository.check() is True


def test_crash_before_write_index(repository):
    with repository:
        add_keys(repository)
        repository.write_index = None
        try:
            repository.commit(compact=False)
        except TypeError:
            pass
    with reopen(repository) as repository:
        assert len(repository) == 3
        assert repository.check() is True


def test_replay_lock_upgrade_old(repository):
    with repository:
        add_keys(repository)
        for name in os.listdir(repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(repository.path, name))
    with patch.object(Lock, "upgrade", side_effect=LockFailed) as upgrade:
        with reopen(repository, exclusive=None) as repository:
            # simulate old client that always does lock upgrades
            # the repo is only locked by a shared read lock, but to replay segments,
            # we need an exclusive write lock - check if the lock gets upgraded.
            with pytest.raises(LockFailed):
                len(repository)
            upgrade.assert_called_once_with()


def test_replay_lock_upgrade(repository):
    with repository:
        add_keys(repository)
        for name in os.listdir(repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(repository.path, name))
    with patch.object(Lock, "upgrade", side_effect=LockFailed) as upgrade:
        with reopen(repository, exclusive=False) as repository:
            # current client usually does not do lock upgrade, except for replay
            # the repo is only locked by a shared read lock, but to replay segments,
            # we need an exclusive write lock - check if the lock gets upgraded.
            with pytest.raises(LockFailed):
                len(repository)
            upgrade.assert_called_once_with()


def test_crash_before_deleting_compacted_segments(repository):
    with repository:
        add_keys(repository)
        repository.io.delete_segment = None
        try:
            repository.commit(compact=False)
        except TypeError:
            pass
    with reopen(repository) as repository:
        assert len(repository) == 3
        assert repository.check() is True
        assert len(repository) == 3


def test_ignores_commit_tag_in_data(repository):
    with repository:
        repository.put(H(0), LoggedIO.COMMIT)
    with reopen(repository) as repository:
        io = repository.io
        assert not io.is_committed_segment(io.get_latest_segment())


def test_moved_deletes_are_tracked(repository):
    with repository:
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


def test_shadowed_entries_are_preserved1(repository):
    # this tests the shadowing-by-del behaviour
    with repository:
        get_latest_segment = repository.io.get_latest_segment
        repository.put(H(1), fchunk(b"1"))
        # This is the segment with our original PUT of interest
        put_segment = get_latest_segment()
        repository.commit(compact=False)
        # we now delete H(1), and force this segment not to be compacted, which can happen
        # if it's not sparse enough (symbolized by H(2) here).
        repository.delete(H(1))
        repository.put(H(2), fchunk(b"1"))
        del_segment = get_latest_segment()
        # we pretend these are mostly dense (not sparse) and won't be compacted
        del repository.compact[put_segment]
        del repository.compact[del_segment]
        repository.commit(compact=True)
        # we now perform an unrelated operation on the segment containing the DELETE,
        # causing it to be compacted.
        repository.delete(H(2))
        repository.commit(compact=True)
        assert repository.io.segment_exists(put_segment)
        assert not repository.io.segment_exists(del_segment)
        # basic case, since the index survived this must be ok
        assert H(1) not in repository
        # nuke index, force replay
        os.unlink(os.path.join(repository.path, "index.%d" % get_latest_segment()))
        # must not reappear
        assert H(1) not in repository


def test_shadowed_entries_are_preserved2(repository):
    # this tests the shadowing-by-double-put behaviour, see issue #5661
    # assume this repo state:
    # seg1: PUT H1
    # seg2: COMMIT
    # seg3: DEL H1, PUT H1, DEL H1, PUT H2
    # seg4: COMMIT
    # Note how due to the final DEL H1 in seg3, H1 is effectively deleted.
    #
    # compaction of only seg3:
    # PUT H1 gets dropped because it is not needed any more.
    # DEL H1 must be kept, because there is still a PUT H1 in seg1 which must not
    # "reappear" in the index if the index gets rebuilt.
    with repository:
        get_latest_segment = repository.io.get_latest_segment
        repository.put(H(1), fchunk(b"1"))
        # This is the segment with our original PUT of interest
        put_segment = get_latest_segment()
        repository.commit(compact=False)
        # We now put H(1) again (which implicitly does DEL(H(1)) followed by PUT(H(1), ...)),
        # delete H(1) afterwards, and force this segment to not be compacted, which can happen
        # if it's not sparse enough (symbolized by H(2) here).
        repository.put(H(1), fchunk(b"1"))
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
        assert H(1) not in repository  # F


def test_shadow_index_rollback(repository):
    with repository:
        repository.put(H(1), fchunk(b"1"))
        repository.delete(H(1))
        assert repository.shadow_index[H(1)] == [0]
        repository.commit(compact=True)
        repo_dump(repository, "p1 d1 cc")
        # note how an empty list means that nothing is shadowed for sure
        assert repository.shadow_index[H(1)] == []  # because the deletion is considered unstable
        repository.put(H(1), b"1")
        repository.delete(H(1))
        repo_dump(repository, "p1 d1")
        # 0 put/delete; 1 commit; 2 compacted; 3 commit; 4 put/delete
        assert repository.shadow_index[H(1)] == [4]
        repository.rollback()
        repo_dump(repository, "r")
        repository.put(H(2), fchunk(b"1"))
        # after the rollback, segment 4 shouldn't be considered anymore
        assert repository.shadow_index[H(1)] == []  # because the deletion is considered unstable


def test_additional_free_space(repository):
    with repository:
        add_keys(repository)
        repository.config.set("repository", "additional_free_space", "1000T")
        repository.save_key(b"shortcut to save_config")
    with reopen(repository) as repository:
        repository.put(H(0), fchunk(b"foobar"))
        with pytest.raises(LegacyRepository.InsufficientFreeSpaceError):
            repository.commit(compact=False)
        assert os.path.exists(repository.path)


def test_create_free_space(repository):
    with repository:
        repository.additional_free_space = 1e20
        with pytest.raises(LegacyRepository.InsufficientFreeSpaceError):
            add_keys(repository)
        assert not os.path.exists(repository.path)


def make_auxiliary(repository):
    with repository:
        repository.put(H(0), fchunk(b"foo"))
        repository.commit(compact=False)


def do_commit(repository):
    with repository:
        repository.put(H(0), fchunk(b"fox"))
        repository.commit(compact=False)


def test_corrupted_hints(repository):
    make_auxiliary(repository)
    with open(os.path.join(repository.path, "hints.1"), "ab") as fd:
        fd.write(b"123456789")
    do_commit(repository)


def test_deleted_hints(repository):
    make_auxiliary(repository)
    os.unlink(os.path.join(repository.path, "hints.1"))
    do_commit(repository)


def test_deleted_index(repository):
    make_auxiliary(repository)
    os.unlink(os.path.join(repository.path, "index.1"))
    do_commit(repository)


def test_unreadable_hints(repository):
    make_auxiliary(repository)
    hints = os.path.join(repository.path, "hints.1")
    os.unlink(hints)
    os.mkdir(hints)
    with pytest.raises(OSError):
        do_commit(repository)


def test_index(repository):
    make_auxiliary(repository)
    with open(os.path.join(repository.path, "index.1"), "wb") as fd:
        fd.write(b"123456789")
    do_commit(repository)


def test_index_outside_transaction(repository):
    make_auxiliary(repository)
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


def test_index_corrupted(repository):
    make_auxiliary(repository)
    _corrupt_index(repository)
    with repository:
        # data corruption is detected due to mismatching checksums, and fixed by rebuilding the index.
        assert len(repository) == 1
        assert pdchunk(repository.get(H(0))) == b"foo"


def test_index_corrupted_without_integrity(repository):
    make_auxiliary(repository)
    _corrupt_index(repository)
    integrity_path = os.path.join(repository.path, "integrity.1")
    os.unlink(integrity_path)
    with repository:
        # since the corrupted key is not noticed, the repository still thinks it contains one key...
        assert len(repository) == 1
        with pytest.raises(LegacyRepository.ObjectNotFound):
            # ... but the real, uncorrupted key is not found in the corrupted index.
            repository.get(H(0))


def test_unreadable_index(repository):
    make_auxiliary(repository)
    index = os.path.join(repository.path, "index.1")
    os.unlink(index)
    os.mkdir(index)
    with pytest.raises(OSError):
        do_commit(repository)


def test_unknown_integrity_version(repository):
    make_auxiliary(repository)
    # for now an unknown integrity data version is ignored and not an error.
    integrity_path = os.path.join(repository.path, "integrity.1")
    with open(integrity_path, "r+b") as fd:
        msgpack.pack({b"version": 4.7}, fd)  # borg only understands version 2
        fd.truncate()
    with repository:
        # no issues accessing the repository
        assert len(repository) == 1
        assert pdchunk(repository.get(H(0))) == b"foo"


def _subtly_corrupted_hints_setup(repository):
    with repository:
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
        # corrupt segment refcount
        assert hints["segments"][2] == 1
        hints["segments"][2] = 0
        msgpack.pack(hints, fd)
        fd.truncate()


def test_subtly_corrupted_hints(repository):
    make_auxiliary(repository)
    _subtly_corrupted_hints_setup(repository)
    with repository:
        repository.put(H(3), fchunk(b"1234"))
        # do a compaction run, which succeeds since the failed checksum prompted a rebuild of the index+hints.
        repository.commit(compact=True)
        assert len(repository) == 4
        assert pdchunk(repository.get(H(0))) == b"foo"
        assert pdchunk(repository.get(H(1))) == b"bar"
        assert pdchunk(repository.get(H(2))) == b"bazz"


def test_subtly_corrupted_hints_without_integrity(repository):
    make_auxiliary(repository)
    _subtly_corrupted_hints_setup(repository)
    integrity_path = os.path.join(repository.path, "integrity.5")
    os.unlink(integrity_path)
    with repository:
        repository.put(H(3), fchunk(b"1234"))
        # do a compaction run, which fails since the corrupted refcount wasn't detected and causes an assertion failure.
        with pytest.raises(AssertionError) as exc_info:
            repository.commit(compact=True)
        assert "Corrupted segment reference count" in str(exc_info.value)


def list_indices(repo_path):
    return [name for name in os.listdir(repo_path) if name.startswith("index.")]


def check(repository, repo_path, repair=False, status=True):
    assert repository.check(repair=repair) == status
    # Make sure no tmp files are left behind
    tmp_files = [name for name in os.listdir(repo_path) if "tmp" in name]
    assert tmp_files == [], "Found tmp files"


def get_objects(repository, *ids):
    for id_ in ids:
        pdchunk(repository.get(H(id_)))


def add_objects(repository, segments):
    for ids in segments:
        for id_ in ids:
            repository.put(H(id_), fchunk(b"data"))
        repository.commit(compact=False)


def get_head(repo_path):
    return sorted(int(n) for n in os.listdir(os.path.join(repo_path, "data", "0")) if n.isdigit())[-1]


def open_index(repo_path):
    return NSIndex1.read(os.path.join(repo_path, f"index.{get_head(repo_path)}"))


def corrupt_object(repo_path, id_):
    idx = open_index(repo_path)
    segment, offset = idx[H(id_)]
    with open(os.path.join(repo_path, "data", "0", str(segment)), "r+b") as fd:
        fd.seek(offset)
        fd.write(b"BOOM")


def delete_segment(repository, segment):
    repository.io.delete_segment(segment)


def delete_index(repo_path):
    os.unlink(os.path.join(repo_path, f"index.{get_head(repo_path)}"))


def rename_index(repo_path, new_name):
    os.replace(os.path.join(repo_path, f"index.{get_head(repo_path)}"), os.path.join(repo_path, new_name))


def list_objects(repository):
    return {int(key) for key in repository.list()}


def test_repair_corrupted_segment(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repo_path = get_path(repository)
        add_objects(repository, [[1, 2, 3], [4, 5], [6]])
        assert {1, 2, 3, 4, 5, 6} == list_objects(repository)
        check(repository, repo_path, status=True)
        corrupt_object(repo_path, 5)
        with pytest.raises(IntegrityError):
            get_objects(repository, 5)
        repository.rollback()
        # make sure a regular check does not repair anything
        check(repository, repo_path, status=False)
        check(repository, repo_path, status=False)
        # make sure a repair actually repairs the repo
        check(repository, repo_path, repair=True, status=True)
        get_objects(repository, 4)
        check(repository, repo_path, status=True)
        assert {1, 2, 3, 4, 6} == list_objects(repository)


def test_repair_missing_segment(repository):
    # only test on local repo - files in RemoteRepository cannot be deleted
    with repository:
        add_objects(repository, [[1, 2, 3], [4, 5, 6]])
        assert {1, 2, 3, 4, 5, 6} == list_objects(repository)
        check(repository, repository.path, status=True)
        delete_segment(repository, 2)
        repository.rollback()
        check(repository, repository.path, repair=True, status=True)
        assert {1, 2, 3} == list_objects(repository)


def test_repair_missing_commit_segment(repository):
    # only test on local repo - files in RemoteRepository cannot be deleted
    with repository:
        add_objects(repository, [[1, 2, 3], [4, 5, 6]])
        delete_segment(repository, 3)
        with pytest.raises(LegacyRepository.ObjectNotFound):
            get_objects(repository, 4)
        assert {1, 2, 3} == list_objects(repository)


def test_repair_corrupted_commit_segment(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repo_path = get_path(repository)
        add_objects(repository, [[1, 2, 3], [4, 5, 6]])
        with open(os.path.join(repo_path, "data", "0", "3"), "r+b") as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b"X")
        with pytest.raises(LegacyRepository.ObjectNotFound):
            get_objects(repository, 4)
        check(repository, repo_path, status=True)
        get_objects(repository, 3)
        assert {1, 2, 3} == list_objects(repository)


def test_repair_no_commits(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repo_path = get_path(repository)
        add_objects(repository, [[1, 2, 3]])
        with open(os.path.join(repo_path, "data", "0", "1"), "r+b") as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b"X")
        with pytest.raises(LegacyRepository.CheckNeeded):
            get_objects(repository, 4)
        check(repository, repo_path, status=False)
        check(repository, repo_path, status=False)
        assert list_indices(repo_path) == ["index.1"]
        check(repository, repo_path, repair=True, status=True)
        assert list_indices(repo_path) == ["index.2"]
        check(repository, repo_path, status=True)
        get_objects(repository, 3)
        assert {1, 2, 3} == list_objects(repository)


def test_repair_missing_index(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repo_path = get_path(repository)
        add_objects(repository, [[1, 2, 3], [4, 5, 6]])
        delete_index(repo_path)
        check(repository, repo_path, status=True)
        get_objects(repository, 4)
        assert {1, 2, 3, 4, 5, 6} == list_objects(repository)


def test_repair_index_too_new(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repo_path = get_path(repository)
        add_objects(repository, [[1, 2, 3], [4, 5, 6]])
        assert list_indices(repo_path) == ["index.3"]
        rename_index(repo_path, "index.100")
        check(repository, repo_path, status=True)
        assert list_indices(repo_path) == ["index.3"]
        get_objects(repository, 4)
        assert {1, 2, 3, 4, 5, 6} == list_objects(repository)


def test_crash_before_compact(repository):
    # only test on local repo - we can't mock-patch a RemoteRepository class in another process!
    with repository:
        repository.put(H(0), fchunk(b"data"))
        repository.put(H(0), fchunk(b"data2"))
        # simulate a crash before compact
        with patch.object(LegacyRepository, "compact_segments") as compact:
            repository.commit(compact=True)
            compact.assert_called_once_with(0.1)
    with reopen(repository) as repository:
        check(repository, repository.path, repair=True)
        assert pdchunk(repository.get(H(0))) == b"data2"


def test_hints_persistence(repository):
    with repository:
        repository.put(H(0), fchunk(b"data"))
        repository.delete(H(0))
        repository.commit(compact=False)
        shadow_index_expected = repository.shadow_index
        compact_expected = repository.compact
        segments_expected = repository.segments
    # close and re-open the repository (create fresh Repository instance) to
    # check whether hints were persisted to / reloaded from disk
    with reopen(repository) as repository:
        repository.put(H(42), fchunk(b"foobar"))  # this will call prepare_txn() and load the hints data
        # check if hints persistence worked:
        assert shadow_index_expected == repository.shadow_index
        assert compact_expected == repository.compact
        del repository.segments[2]  # ignore the segment created by put(H(42), ...)
        assert segments_expected == repository.segments
    with reopen(repository) as repository:
        check(repository, repository.path, repair=True)
    with reopen(repository) as repository:
        repository.put(H(42), fchunk(b"foobar"))  # this will call prepare_txn() and load the hints data
        assert shadow_index_expected == repository.shadow_index
        # sizes do not match, with vs. without header?
        # assert compact_expected == repository.compact
        del repository.segments[2]  # ignore the segment created by put(H(42), ...)
        assert segments_expected == repository.segments


def test_hints_behaviour(repository):
    with repository:
        repository.put(H(0), fchunk(b"data"))
        assert repository.shadow_index == {}
        assert len(repository.compact) == 0
        repository.delete(H(0))
        repository.commit(compact=False)
        # now there should be an entry for H(0) in shadow_index
        assert H(0) in repository.shadow_index
        assert len(repository.shadow_index[H(0)]) == 1
        assert 0 in repository.compact  # segment 0 can be compacted
        repository.put(H(42), fchunk(b"foobar"))  # see also do_compact()
        repository.commit(compact=True, threshold=0.0)  # compact completely!
        # nothing to compact anymore! no info left about stuff that does not exist anymore:
        assert H(0) not in repository.shadow_index
        # segment 0 was compacted away, no info about it left:
        assert 0 not in repository.compact
        assert 0 not in repository.segments


def _get_mock_args():
    class MockArgs:
        remote_path = "borg"
        umask = 0o077
        debug_topics = []
        rsh = None

        def __contains__(self, item):
            # to behave like argparse.Namespace
            return hasattr(self, item)

    return MockArgs()


def test_remote_invalid_rpc(remote_repository):
    with remote_repository:
        with pytest.raises(InvalidRPCMethod):
            remote_repository.call("__init__", {})


def test_remote_rpc_exception_transport(remote_repository):
    with remote_repository:
        s1 = "test string"

        try:
            remote_repository.call("inject_exception", {"kind": "DoesNotExist"})
        except LegacyRepository.DoesNotExist as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "AlreadyExists"})
        except LegacyRepository.AlreadyExists as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "CheckNeeded"})
        except LegacyRepository.CheckNeeded as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "IntegrityError"})
        except IntegrityError as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            remote_repository.call("inject_exception", {"kind": "PathNotAllowed"})
        except PathNotAllowed as e:
            assert len(e.args) == 1
            assert e.args[0] == "foo"

        try:
            remote_repository.call("inject_exception", {"kind": "ObjectNotFound"})
        except LegacyRepository.ObjectNotFound as e:
            assert len(e.args) == 2
            assert e.args[0] == s1
            assert e.args[1] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "InvalidRPCMethod"})
        except InvalidRPCMethod as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            remote_repository.call("inject_exception", {"kind": "divide"})
        except LegacyRemoteRepository.RPCError as e:
            assert e.unpacked
            assert e.get_message().startswith("ZeroDivisionError:")
            assert e.exception_class == "ZeroDivisionError"
            assert len(e.exception_full) > 0


def test_remote_ssh_cmd(remote_repository):
    with remote_repository:
        args = _get_mock_args()
        remote_repository._args = args
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "example.com"]
        assert remote_repository.ssh_cmd(Location("ssh://user@example.com/foo")) == ["ssh", "user@example.com"]
        assert remote_repository.ssh_cmd(Location("ssh://user@example.com:1234/foo")) == [
            "ssh",
            "-p",
            "1234",
            "user@example.com",
        ]
        os.environ["BORG_RSH"] = "ssh --foo"
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "--foo", "example.com"]


def test_remote_borg_cmd(remote_repository):
    with remote_repository:
        assert remote_repository.borg_cmd(None, testing=True) == [sys.executable, "-m", "borg", "serve"]
        args = _get_mock_args()
        # XXX without next line we get spurious test fails when using pytest-xdist, root cause unknown:
        logging.getLogger().setLevel(logging.INFO)
        # note: test logger is on info log level, so --info gets added automagically
        assert remote_repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.remote_path = "borg-0.28.2"
        assert remote_repository.borg_cmd(args, testing=False) == ["borg-0.28.2", "serve", "--info"]
        args.debug_topics = ["something_client_side", "repository_compaction"]
        assert remote_repository.borg_cmd(args, testing=False) == [
            "borg-0.28.2",
            "serve",
            "--info",
            "--debug-topic=borg.debug.repository_compaction",
        ]
        args = _get_mock_args()
        assert remote_repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.rsh = "ssh -i foo"
        remote_repository._args = args
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "-i", "foo", "example.com"]
