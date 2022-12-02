import io
import logging
import os
import shutil
import sys
import tempfile
from unittest.mock import patch

import pytest

from ..hashindex import NSIndex
from ..helpers import Location
from ..helpers import IntegrityError
from ..helpers import msgpack
from ..locking import Lock, LockFailed
from ..remote import RemoteRepository, InvalidRPCMethod, PathNotAllowed, handle_remote_line
from ..repository import Repository, LoggedIO, MAGIC, MAX_DATA_SIZE, TAG_DELETE, TAG_PUT2, TAG_PUT, TAG_COMMIT
from ..repoobj import RepoObj
from . import BaseTestCase
from .hashindex import H


UNSPECIFIED = object()  # for default values where we can't use None


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


class RepositoryTestCaseBase(BaseTestCase):
    key_size = 32
    exclusive = True

    def open(self, create=False, exclusive=UNSPECIFIED):
        if exclusive is UNSPECIFIED:
            exclusive = self.exclusive
        return Repository(os.path.join(self.tmppath, "repository"), exclusive=exclusive, create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)
        self.repository.__enter__()

    def tearDown(self):
        self.repository.close()
        shutil.rmtree(self.tmppath)

    def reopen(self, exclusive=UNSPECIFIED):
        if self.repository:
            self.repository.close()
        self.repository = self.open(exclusive=exclusive)

    def add_keys(self):
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.put(H(1), fchunk(b"bar"))
        self.repository.put(H(3), fchunk(b"bar"))
        self.repository.commit(compact=False)
        self.repository.put(H(1), fchunk(b"bar2"))
        self.repository.put(H(2), fchunk(b"boo"))
        self.repository.delete(H(3))

    def repo_dump(self, label=None):
        label = label + ": " if label is not None else ""
        H_trans = {H(i): i for i in range(10)}
        H_trans[None] = -1  # key == None appears in commits
        tag_trans = {TAG_PUT2: "put2", TAG_PUT: "put", TAG_DELETE: "del", TAG_COMMIT: "comm"}
        for segment, fn in self.repository.io.segment_iterator():
            for tag, key, offset, size, _ in self.repository.io.iter_objects(segment):
                print("%s%s H(%d) -> %s[%d..+%d]" % (label, tag_trans[tag], H_trans[key], fn, offset, size))
        print()


class RepositoryTestCase(RepositoryTestCaseBase):
    def test1(self):
        for x in range(100):
            self.repository.put(H(x), fchunk(b"SOMEDATA"))
        key50 = H(50)
        self.assert_equal(pdchunk(self.repository.get(key50)), b"SOMEDATA")
        self.repository.delete(key50)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(key50))
        self.repository.commit(compact=False)
        self.repository.close()
        with self.open() as repository2:
            self.assert_raises(Repository.ObjectNotFound, lambda: repository2.get(key50))
            for x in range(100):
                if x == 50:
                    continue
                self.assert_equal(pdchunk(repository2.get(H(x))), b"SOMEDATA")

    def test2(self):
        """Test multiple sequential transactions"""
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.put(H(1), fchunk(b"foo"))
        self.repository.commit(compact=False)
        self.repository.delete(H(0))
        self.repository.put(H(1), fchunk(b"bar"))
        self.repository.commit(compact=False)
        self.assert_equal(pdchunk(self.repository.get(H(1))), b"bar")

    def test_read_data(self):
        meta, data = b"meta", b"data"
        meta_len = RepoObj.meta_len_hdr.pack(len(meta))
        chunk_complete = meta_len + meta + data
        chunk_short = meta_len + meta
        self.repository.put(H(0), chunk_complete)
        self.repository.commit(compact=False)
        self.assert_equal(self.repository.get(H(0)), chunk_complete)
        self.assert_equal(self.repository.get(H(0), read_data=True), chunk_complete)
        self.assert_equal(self.repository.get(H(0), read_data=False), chunk_short)

    def test_consistency(self):
        """Test cache consistency"""
        self.repository.put(H(0), fchunk(b"foo"))
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo")
        self.repository.put(H(0), fchunk(b"foo2"))
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo2")
        self.repository.put(H(0), fchunk(b"bar"))
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"bar")
        self.repository.delete(H(0))
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(H(0)))

    def test_consistency2(self):
        """Test cache consistency2"""
        self.repository.put(H(0), fchunk(b"foo"))
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo")
        self.repository.commit(compact=False)
        self.repository.put(H(0), fchunk(b"foo2"))
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo2")
        self.repository.rollback()
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo")

    def test_overwrite_in_same_transaction(self):
        """Test cache consistency2"""
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.put(H(0), fchunk(b"foo2"))
        self.repository.commit(compact=False)
        self.assert_equal(pdchunk(self.repository.get(H(0))), b"foo2")

    def test_single_kind_transactions(self):
        # put
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)
        self.repository.close()
        # replace
        self.repository = self.open()
        with self.repository:
            self.repository.put(H(0), fchunk(b"bar"))
            self.repository.commit(compact=False)
        # delete
        self.repository = self.open()
        with self.repository:
            self.repository.delete(H(0))
            self.repository.commit(compact=False)

    def test_list(self):
        for x in range(100):
            self.repository.put(H(x), fchunk(b"SOMEDATA"))
        self.repository.commit(compact=False)
        all = self.repository.list()
        self.assert_equal(len(all), 100)
        first_half = self.repository.list(limit=50)
        self.assert_equal(len(first_half), 50)
        self.assert_equal(first_half, all[:50])
        second_half = self.repository.list(marker=first_half[-1])
        self.assert_equal(len(second_half), 50)
        self.assert_equal(second_half, all[50:])
        self.assert_equal(len(self.repository.list(limit=50)), 50)

    def test_scan(self):
        for x in range(100):
            self.repository.put(H(x), fchunk(b"SOMEDATA"))
        self.repository.commit(compact=False)
        all, _ = self.repository.scan()
        assert len(all) == 100
        first_half, state = self.repository.scan(limit=50)
        assert len(first_half) == 50
        assert first_half == all[:50]
        second_half, _ = self.repository.scan(state=state)
        assert len(second_half) == 50
        assert second_half == all[50:]
        # check result order == on-disk order (which is hash order)
        for x in range(100):
            assert all[x] == H(x)

    def test_scan_modify(self):
        for x in range(100):
            self.repository.put(H(x), fchunk(b"ORIGINAL"))
        self.repository.commit(compact=False)
        # now we scan, read and modify chunks at the same time
        count = 0
        ids, _ = self.repository.scan()
        for id in ids:
            # scan results are in same order as we put the chunks into the repo (into the segment file)
            assert id == H(count)
            chunk = self.repository.get(id)
            # check that we **only** get data that was committed when we started scanning
            # and that we do not run into the new data we put into the repo.
            assert pdchunk(chunk) == b"ORIGINAL"
            count += 1
            self.repository.put(id, fchunk(b"MODIFIED"))
        assert count == 100
        self.repository.commit()

        # now we have committed all the modified chunks, and **only** must get the modified ones.
        count = 0
        ids, _ = self.repository.scan()
        for id in ids:
            # scan results are in same order as we put the chunks into the repo (into the segment file)
            assert id == H(count)
            chunk = self.repository.get(id)
            assert pdchunk(chunk) == b"MODIFIED"
            count += 1
        assert count == 100

    def test_max_data_size(self):
        max_data = b"x" * (MAX_DATA_SIZE - RepoObj.meta_len_hdr.size)
        self.repository.put(H(0), fchunk(max_data))
        self.assert_equal(pdchunk(self.repository.get(H(0))), max_data)
        self.assert_raises(IntegrityError, lambda: self.repository.put(H(1), fchunk(max_data + b"x")))

    def test_set_flags(self):
        id = H(0)
        self.repository.put(id, fchunk(b""))
        self.assert_equal(self.repository.flags(id), 0x00000000)  # init == all zero
        self.repository.flags(id, mask=0x00000001, value=0x00000001)
        self.assert_equal(self.repository.flags(id), 0x00000001)
        self.repository.flags(id, mask=0x00000002, value=0x00000002)
        self.assert_equal(self.repository.flags(id), 0x00000003)
        self.repository.flags(id, mask=0x00000001, value=0x00000000)
        self.assert_equal(self.repository.flags(id), 0x00000002)
        self.repository.flags(id, mask=0x00000002, value=0x00000000)
        self.assert_equal(self.repository.flags(id), 0x00000000)

    def test_get_flags(self):
        id = H(0)
        self.repository.put(id, fchunk(b""))
        self.assert_equal(self.repository.flags(id), 0x00000000)  # init == all zero
        self.repository.flags(id, mask=0xC0000003, value=0x80000001)
        self.assert_equal(self.repository.flags(id, mask=0x00000001), 0x00000001)
        self.assert_equal(self.repository.flags(id, mask=0x00000002), 0x00000000)
        self.assert_equal(self.repository.flags(id, mask=0x40000008), 0x00000000)
        self.assert_equal(self.repository.flags(id, mask=0x80000000), 0x80000000)

    def test_flags_many(self):
        ids_flagged = [H(0), H(1)]
        ids_default_flags = [H(2), H(3)]
        [self.repository.put(id, fchunk(b"")) for id in ids_flagged + ids_default_flags]
        self.repository.flags_many(ids_flagged, mask=0xFFFFFFFF, value=0xDEADBEEF)
        self.assert_equal(list(self.repository.flags_many(ids_default_flags)), [0x00000000, 0x00000000])
        self.assert_equal(list(self.repository.flags_many(ids_flagged)), [0xDEADBEEF, 0xDEADBEEF])
        self.assert_equal(list(self.repository.flags_many(ids_flagged, mask=0xFFFF0000)), [0xDEAD0000, 0xDEAD0000])
        self.assert_equal(list(self.repository.flags_many(ids_flagged, mask=0x0000FFFF)), [0x0000BEEF, 0x0000BEEF])

    def test_flags_persistence(self):
        self.repository.put(H(0), fchunk(b"default"))
        self.repository.put(H(1), fchunk(b"one one zero"))
        # we do not set flags for H(0), so we can later check their default state.
        self.repository.flags(H(1), mask=0x00000007, value=0x00000006)
        self.repository.commit(compact=False)
        self.repository.close()

        self.repository = self.open()
        with self.repository:
            # we query all flags to check if the initial flags were all zero and
            # only the ones we explicitly set to one are as expected.
            self.assert_equal(self.repository.flags(H(0), mask=0xFFFFFFFF), 0x00000000)
            self.assert_equal(self.repository.flags(H(1), mask=0xFFFFFFFF), 0x00000006)


class LocalRepositoryTestCase(RepositoryTestCaseBase):
    # test case that doesn't work with remote repositories

    def _assert_sparse(self):
        # The superseded 123456... PUT
        assert self.repository.compact[0] == 41 + 8 + len(fchunk(b"123456789"))
        # a COMMIT
        assert self.repository.compact[1] == 9
        # The DELETE issued by the superseding PUT (or issued directly)
        assert self.repository.compact[2] == 41
        self.repository._rebuild_sparse(0)
        assert self.repository.compact[0] == 41 + 8 + len(fchunk(b"123456789"))  # 9 is chunk or commit?

    def test_sparse1(self):
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.put(H(1), fchunk(b"123456789"))
        self.repository.commit(compact=False)
        self.repository.put(H(1), fchunk(b"bar"))
        self._assert_sparse()

    def test_sparse2(self):
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.put(H(1), fchunk(b"123456789"))
        self.repository.commit(compact=False)
        self.repository.delete(H(1))
        self._assert_sparse()

    def test_sparse_delete(self):
        ch0 = fchunk(b"1245")
        self.repository.put(H(0), ch0)
        self.repository.delete(H(0))
        self.repository.io._write_fd.sync()

        # The on-line tracking works on a per-object basis...
        assert self.repository.compact[0] == 41 + 8 + 41 + len(ch0)
        self.repository._rebuild_sparse(0)
        # ...while _rebuild_sparse can mark whole segments as completely sparse (which then includes the segment magic)
        assert self.repository.compact[0] == 41 + 8 + 41 + len(ch0) + len(MAGIC)

        self.repository.commit(compact=True)
        assert 0 not in [segment for segment, _ in self.repository.io.segment_iterator()]

    def test_uncommitted_garbage(self):
        # uncommitted garbage should be no problem, it is cleaned up automatically.
        # we just have to be careful with invalidation of cached FDs in LoggedIO.
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)
        # write some crap to a uncommitted segment file
        last_segment = self.repository.io.get_latest_segment()
        with open(self.repository.io.segment_filename(last_segment + 1), "wb") as f:
            f.write(MAGIC + b"crapcrapcrap")
        self.repository.close()
        # usually, opening the repo and starting a transaction should trigger a cleanup.
        self.repository = self.open()
        with self.repository:
            self.repository.put(H(0), fchunk(b"bar"))  # this may trigger compact_segments()
            self.repository.commit(compact=True)
        # the point here is that nothing blows up with an exception.


class RepositoryCommitTestCase(RepositoryTestCaseBase):
    def test_replay_of_missing_index(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(self.repository.path, name))
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)

    def test_crash_before_compact_segments(self):
        self.add_keys()
        self.repository.compact_segments = None
        try:
            self.repository.commit(compact=True)
        except TypeError:
            pass
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)

    def test_crash_before_write_index(self):
        self.add_keys()
        self.repository.write_index = None
        try:
            self.repository.commit(compact=False)
        except TypeError:
            pass
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)

    def test_replay_lock_upgrade_old(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(Lock, "upgrade", side_effect=LockFailed) as upgrade:
            self.reopen(exclusive=None)  # simulate old client that always does lock upgrades
            with self.repository:
                # the repo is only locked by a shared read lock, but to replay segments,
                # we need an exclusive write lock - check if the lock gets upgraded.
                self.assert_raises(LockFailed, lambda: len(self.repository))
                upgrade.assert_called_once_with()

    def test_replay_lock_upgrade(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith("index."):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(Lock, "upgrade", side_effect=LockFailed) as upgrade:
            self.reopen(exclusive=False)  # current client usually does not do lock upgrade, except for replay
            with self.repository:
                # the repo is only locked by a shared read lock, but to replay segments,
                # we need an exclusive write lock - check if the lock gets upgraded.
                self.assert_raises(LockFailed, lambda: len(self.repository))
                upgrade.assert_called_once_with()

    def test_crash_before_deleting_compacted_segments(self):
        self.add_keys()
        self.repository.io.delete_segment = None
        try:
            self.repository.commit(compact=False)
        except TypeError:
            pass
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)
            self.assert_equal(len(self.repository), 3)

    def test_ignores_commit_tag_in_data(self):
        self.repository.put(H(0), LoggedIO.COMMIT)
        self.reopen()
        with self.repository:
            io = self.repository.io
            assert not io.is_committed_segment(io.get_latest_segment())

    def test_moved_deletes_are_tracked(self):
        self.repository.put(H(1), fchunk(b"1"))
        self.repository.put(H(2), fchunk(b"2"))
        self.repository.commit(compact=False)
        self.repo_dump("p1 p2 c")
        self.repository.delete(H(1))
        self.repository.commit(compact=True)
        self.repo_dump("d1 cc")
        last_segment = self.repository.io.get_latest_segment() - 1
        num_deletes = 0
        for tag, key, offset, size, _ in self.repository.io.iter_objects(last_segment):
            if tag == TAG_DELETE:
                assert key == H(1)
                num_deletes += 1
        assert num_deletes == 1
        assert last_segment in self.repository.compact
        self.repository.put(H(3), fchunk(b"3"))
        self.repository.commit(compact=True)
        self.repo_dump("p3 cc")
        assert last_segment not in self.repository.compact
        assert not self.repository.io.segment_exists(last_segment)
        for segment, _ in self.repository.io.segment_iterator():
            for tag, key, offset, size, _ in self.repository.io.iter_objects(segment):
                assert tag != TAG_DELETE
                assert key != H(1)
        # after compaction, there should be no empty shadowed_segments lists left over.
        # we have no put or del any more for H(1), so we lost knowledge about H(1).
        assert H(1) not in self.repository.shadow_index

    def test_shadowed_entries_are_preserved(self):
        get_latest_segment = self.repository.io.get_latest_segment
        self.repository.put(H(1), fchunk(b"1"))
        # This is the segment with our original PUT of interest
        put_segment = get_latest_segment()
        self.repository.commit(compact=False)

        # We now delete H(1), and force this segment to not be compacted, which can happen
        # if it's not sparse enough (symbolized by H(2) here).
        self.repository.delete(H(1))
        self.repository.put(H(2), fchunk(b"1"))
        delete_segment = get_latest_segment()

        # We pretend these are mostly dense (not sparse) and won't be compacted
        del self.repository.compact[put_segment]
        del self.repository.compact[delete_segment]

        self.repository.commit(compact=True)

        # Now we perform an unrelated operation on the segment containing the DELETE,
        # causing it to be compacted.
        self.repository.delete(H(2))
        self.repository.commit(compact=True)

        assert self.repository.io.segment_exists(put_segment)
        assert not self.repository.io.segment_exists(delete_segment)

        # Basic case, since the index survived this must be ok
        assert H(1) not in self.repository
        # Nuke index, force replay
        os.unlink(os.path.join(self.repository.path, "index.%d" % get_latest_segment()))
        # Must not reappear
        assert H(1) not in self.repository

    def test_shadow_index_rollback(self):
        self.repository.put(H(1), fchunk(b"1"))
        self.repository.delete(H(1))
        assert self.repository.shadow_index[H(1)] == [0]
        self.repository.commit(compact=True)
        self.repo_dump("p1 d1 cc")
        # note how an empty list means that nothing is shadowed for sure
        assert self.repository.shadow_index[H(1)] == []  # because the delete is considered unstable
        self.repository.put(H(1), b"1")
        self.repository.delete(H(1))
        self.repo_dump("p1 d1")
        # 0 put/delete; 1 commit; 2 compacted; 3 commit; 4 put/delete
        assert self.repository.shadow_index[H(1)] == [4]
        self.repository.rollback()
        self.repo_dump("r")
        self.repository.put(H(2), fchunk(b"1"))
        # After the rollback segment 4 shouldn't be considered anymore
        assert self.repository.shadow_index[H(1)] == []  # because the delete is considered unstable


class RepositoryAppendOnlyTestCase(RepositoryTestCaseBase):
    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, "repository"), exclusive=True, create=create, append_only=True)

    def test_destroy_append_only(self):
        # Can't destroy append only repo (via the API)
        with self.assert_raises(ValueError):
            self.repository.destroy()
        assert self.repository.append_only

    def test_append_only(self):
        def segments_in_repository():
            return len(list(self.repository.io.segment_iterator()))

        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)

        self.repository.append_only = False
        assert segments_in_repository() == 2
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=True)
        # normal: compact squashes the data together, only one segment
        assert segments_in_repository() == 2

        self.repository.append_only = True
        assert segments_in_repository() == 2
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)
        # append only: does not compact, only new segments written
        assert segments_in_repository() == 4


class RepositoryFreeSpaceTestCase(RepositoryTestCaseBase):
    def test_additional_free_space(self):
        self.add_keys()
        self.repository.config.set("repository", "additional_free_space", "1000T")
        self.repository.save_key(b"shortcut to save_config")
        self.reopen()

        with self.repository:
            self.repository.put(H(0), fchunk(b"foobar"))
            with pytest.raises(Repository.InsufficientFreeSpaceError):
                self.repository.commit(compact=False)
        assert os.path.exists(self.repository.path)

    def test_create_free_space(self):
        self.repository.additional_free_space = 1e20
        with pytest.raises(Repository.InsufficientFreeSpaceError):
            self.add_keys()
        assert not os.path.exists(self.repository.path)


class QuotaTestCase(RepositoryTestCaseBase):
    def test_tracking(self):
        assert self.repository.storage_quota_use == 0
        ch1 = fchunk(bytes(1234))
        self.repository.put(H(1), ch1)
        assert self.repository.storage_quota_use == len(ch1) + 41 + 8
        ch2 = fchunk(bytes(5678))
        self.repository.put(H(2), ch2)
        assert self.repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)
        self.repository.delete(H(1))
        assert self.repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)  # we have not compacted yet
        self.repository.commit(compact=False)
        assert self.repository.storage_quota_use == len(ch1) + len(ch2) + 2 * (41 + 8)  # we have not compacted yet
        self.reopen()
        with self.repository:
            # Open new transaction; hints and thus quota data is not loaded unless needed.
            ch3 = fchunk(b"")
            self.repository.put(H(3), ch3)
            self.repository.delete(H(3))
            assert self.repository.storage_quota_use == len(ch1) + len(ch2) + len(ch3) + 3 * (
                41 + 8
            )  # we have not compacted yet
            self.repository.commit(compact=True)
            assert self.repository.storage_quota_use == len(ch2) + 41 + 8

    def test_exceed_quota(self):
        assert self.repository.storage_quota_use == 0
        self.repository.storage_quota = 80
        ch1 = fchunk(b"x" * 7)
        self.repository.put(H(1), ch1)
        assert self.repository.storage_quota_use == len(ch1) + 41 + 8
        self.repository.commit(compact=False)
        with pytest.raises(Repository.StorageQuotaExceeded):
            ch2 = fchunk(b"y" * 13)
            self.repository.put(H(2), ch2)
        assert self.repository.storage_quota_use == len(ch1) + len(ch2) + (41 + 8) * 2  # check ch2!?
        with pytest.raises(Repository.StorageQuotaExceeded):
            self.repository.commit(compact=False)
        assert self.repository.storage_quota_use == len(ch1) + len(ch2) + (41 + 8) * 2  # check ch2!?
        self.reopen()
        with self.repository:
            self.repository.storage_quota = 150
            # Open new transaction; hints and thus quota data is not loaded unless needed.
            self.repository.put(H(1), ch1)
            assert (
                self.repository.storage_quota_use == len(ch1) * 2 + (41 + 8) * 2
            )  # we have 2 puts for H(1) here and not yet compacted.
            self.repository.commit(compact=True)
            assert self.repository.storage_quota_use == len(ch1) + 41 + 8  # now we have compacted.


class NonceReservation(RepositoryTestCaseBase):
    def test_get_free_nonce_asserts(self):
        self.reopen(exclusive=False)
        with pytest.raises(AssertionError):
            with self.repository:
                self.repository.get_free_nonce()

    def test_get_free_nonce(self):
        with self.repository:
            assert self.repository.get_free_nonce() is None

            with open(os.path.join(self.repository.path, "nonce"), "w") as fd:
                fd.write("0000000000000000")
            assert self.repository.get_free_nonce() == 0

            with open(os.path.join(self.repository.path, "nonce"), "w") as fd:
                fd.write("5000000000000000")
            assert self.repository.get_free_nonce() == 0x5000000000000000

    def test_commit_nonce_reservation_asserts(self):
        self.reopen(exclusive=False)
        with pytest.raises(AssertionError):
            with self.repository:
                self.repository.commit_nonce_reservation(0x200, 0x100)

    def test_commit_nonce_reservation(self):
        with self.repository:
            with pytest.raises(Exception):
                self.repository.commit_nonce_reservation(0x200, 15)

            self.repository.commit_nonce_reservation(0x200, None)
            with open(os.path.join(self.repository.path, "nonce")) as fd:
                assert fd.read() == "0000000000000200"

            with pytest.raises(Exception):
                self.repository.commit_nonce_reservation(0x200, 15)

            self.repository.commit_nonce_reservation(0x400, 0x200)
            with open(os.path.join(self.repository.path, "nonce")) as fd:
                assert fd.read() == "0000000000000400"


class RepositoryAuxiliaryCorruptionTestCase(RepositoryTestCaseBase):
    def setUp(self):
        super().setUp()
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)
        self.repository.close()

    def do_commit(self):
        with self.repository:
            self.repository.put(H(0), fchunk(b"fox"))
            self.repository.commit(compact=False)

    def test_corrupted_hints(self):
        with open(os.path.join(self.repository.path, "hints.1"), "ab") as fd:
            fd.write(b"123456789")
        self.do_commit()

    def test_deleted_hints(self):
        os.unlink(os.path.join(self.repository.path, "hints.1"))
        self.do_commit()

    def test_deleted_index(self):
        os.unlink(os.path.join(self.repository.path, "index.1"))
        self.do_commit()

    def test_unreadable_hints(self):
        hints = os.path.join(self.repository.path, "hints.1")
        os.unlink(hints)
        os.mkdir(hints)
        with self.assert_raises(OSError):
            self.do_commit()

    def test_index(self):
        with open(os.path.join(self.repository.path, "index.1"), "wb") as fd:
            fd.write(b"123456789")
        self.do_commit()

    def test_index_outside_transaction(self):
        with open(os.path.join(self.repository.path, "index.1"), "wb") as fd:
            fd.write(b"123456789")
        with self.repository:
            assert len(self.repository) == 1

    def _corrupt_index(self):
        # HashIndex is able to detect incorrect headers and file lengths,
        # but on its own it can't tell if the data is correct.
        index_path = os.path.join(self.repository.path, "index.1")
        with open(index_path, "r+b") as fd:
            index_data = fd.read()
            # Flip one bit in a key stored in the index
            corrupted_key = (int.from_bytes(H(0), "little") ^ 1).to_bytes(32, "little")
            corrupted_index_data = index_data.replace(H(0), corrupted_key)
            assert corrupted_index_data != index_data
            assert len(corrupted_index_data) == len(index_data)
            fd.seek(0)
            fd.write(corrupted_index_data)

    def test_index_corrupted(self):
        # HashIndex is able to detect incorrect headers and file lengths,
        # but on its own it can't tell if the data itself is correct.
        self._corrupt_index()
        with self.repository:
            # Data corruption is detected due to mismatching checksums
            # and fixed by rebuilding the index.
            assert len(self.repository) == 1
            assert pdchunk(self.repository.get(H(0))) == b"foo"

    def test_index_corrupted_without_integrity(self):
        self._corrupt_index()
        integrity_path = os.path.join(self.repository.path, "integrity.1")
        os.unlink(integrity_path)
        with self.repository:
            # Since the corrupted key is not noticed, the repository still thinks
            # it contains one key...
            assert len(self.repository) == 1
            with pytest.raises(Repository.ObjectNotFound):
                # ... but the real, uncorrupted key is not found in the corrupted index.
                self.repository.get(H(0))

    def test_unreadable_index(self):
        index = os.path.join(self.repository.path, "index.1")
        os.unlink(index)
        os.mkdir(index)
        with self.assert_raises(OSError):
            self.do_commit()

    def test_unknown_integrity_version(self):
        # For now an unknown integrity data version is ignored and not an error.
        integrity_path = os.path.join(self.repository.path, "integrity.1")
        with open(integrity_path, "r+b") as fd:
            msgpack.pack(
                {
                    # Borg only understands version 2
                    b"version": 4.7
                },
                fd,
            )
            fd.truncate()
        with self.repository:
            # No issues accessing the repository
            assert len(self.repository) == 1
            assert pdchunk(self.repository.get(H(0))) == b"foo"

    def _subtly_corrupted_hints_setup(self):
        with self.repository:
            self.repository.append_only = True
            assert len(self.repository) == 1
            assert pdchunk(self.repository.get(H(0))) == b"foo"
            self.repository.put(H(1), fchunk(b"bar"))
            self.repository.put(H(2), fchunk(b"baz"))
            self.repository.commit(compact=False)
            self.repository.put(H(2), fchunk(b"bazz"))
            self.repository.commit(compact=False)

        hints_path = os.path.join(self.repository.path, "hints.5")
        with open(hints_path, "r+b") as fd:
            hints = msgpack.unpack(fd)
            fd.seek(0)
            # Corrupt segment refcount
            assert hints["segments"][2] == 1
            hints["segments"][2] = 0
            msgpack.pack(hints, fd)
            fd.truncate()

    def test_subtly_corrupted_hints(self):
        self._subtly_corrupted_hints_setup()
        with self.repository:
            self.repository.append_only = False
            self.repository.put(H(3), fchunk(b"1234"))
            # Do a compaction run. Succeeds, since the failed checksum prompted a rebuild of the index+hints.
            self.repository.commit(compact=True)

            assert len(self.repository) == 4
            assert pdchunk(self.repository.get(H(0))) == b"foo"
            assert pdchunk(self.repository.get(H(1))) == b"bar"
            assert pdchunk(self.repository.get(H(2))) == b"bazz"

    def test_subtly_corrupted_hints_without_integrity(self):
        self._subtly_corrupted_hints_setup()
        integrity_path = os.path.join(self.repository.path, "integrity.5")
        os.unlink(integrity_path)
        with self.repository:
            self.repository.append_only = False
            self.repository.put(H(3), fchunk(b"1234"))
            # Do a compaction run. Fails, since the corrupted refcount was not detected and leads to an assertion failure.
            with pytest.raises(AssertionError) as exc_info:
                self.repository.commit(compact=True)
            assert "Corrupted segment reference count" in str(exc_info.value)


class RepositoryCheckTestCase(RepositoryTestCaseBase):
    def list_indices(self):
        return [name for name in os.listdir(os.path.join(self.tmppath, "repository")) if name.startswith("index.")]

    def check(self, repair=False, status=True):
        self.assert_equal(self.repository.check(repair=repair), status)
        # Make sure no tmp files are left behind
        self.assert_equal(
            [name for name in os.listdir(os.path.join(self.tmppath, "repository")) if "tmp" in name],
            [],
            "Found tmp files",
        )

    def get_objects(self, *ids):
        for id_ in ids:
            pdchunk(self.repository.get(H(id_)))

    def add_objects(self, segments):
        for ids in segments:
            for id_ in ids:
                self.repository.put(H(id_), fchunk(b"data"))
            self.repository.commit(compact=False)

    def get_head(self):
        return sorted(int(n) for n in os.listdir(os.path.join(self.tmppath, "repository", "data", "0")) if n.isdigit())[
            -1
        ]

    def open_index(self):
        return NSIndex.read(os.path.join(self.tmppath, "repository", f"index.{self.get_head()}"))

    def corrupt_object(self, id_):
        idx = self.open_index()
        segment, offset, _ = idx[H(id_)]
        with open(os.path.join(self.tmppath, "repository", "data", "0", str(segment)), "r+b") as fd:
            fd.seek(offset)
            fd.write(b"BOOM")

    def delete_segment(self, segment):
        self.repository.io.delete_segment(segment)

    def delete_index(self):
        os.unlink(os.path.join(self.tmppath, "repository", f"index.{self.get_head()}"))

    def rename_index(self, new_name):
        os.rename(
            os.path.join(self.tmppath, "repository", f"index.{self.get_head()}"),
            os.path.join(self.tmppath, "repository", new_name),
        )

    def list_objects(self):
        return {int(key) for key in self.repository.list()}

    def test_repair_corrupted_segment(self):
        self.add_objects([[1, 2, 3], [4, 5], [6]])
        self.assert_equal({1, 2, 3, 4, 5, 6}, self.list_objects())
        self.check(status=True)
        self.corrupt_object(5)
        self.assert_raises(IntegrityError, lambda: self.get_objects(5))
        self.repository.rollback()
        # Make sure a regular check does not repair anything
        self.check(status=False)
        self.check(status=False)
        # Make sure a repair actually repairs the repo
        self.check(repair=True, status=True)
        self.get_objects(4)
        self.check(status=True)
        self.assert_equal({1, 2, 3, 4, 6}, self.list_objects())

    def test_repair_missing_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.assert_equal({1, 2, 3, 4, 5, 6}, self.list_objects())
        self.check(status=True)
        self.delete_segment(2)
        self.repository.rollback()
        self.check(repair=True, status=True)
        self.assert_equal({1, 2, 3}, self.list_objects())

    def test_repair_missing_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.delete_segment(3)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.assert_equal({1, 2, 3}, self.list_objects())

    def test_repair_corrupted_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        with open(os.path.join(self.tmppath, "repository", "data", "0", "3"), "r+b") as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b"X")
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.check(status=True)
        self.get_objects(3)
        self.assert_equal({1, 2, 3}, self.list_objects())

    def test_repair_no_commits(self):
        self.add_objects([[1, 2, 3]])
        with open(os.path.join(self.tmppath, "repository", "data", "0", "1"), "r+b") as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b"X")
        self.assert_raises(Repository.CheckNeeded, lambda: self.get_objects(4))
        self.check(status=False)
        self.check(status=False)
        self.assert_equal(self.list_indices(), ["index.1"])
        self.check(repair=True, status=True)
        self.assert_equal(self.list_indices(), ["index.2"])
        self.check(status=True)
        self.get_objects(3)
        self.assert_equal({1, 2, 3}, self.list_objects())

    def test_repair_missing_index(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.delete_index()
        self.check(status=True)
        self.get_objects(4)
        self.assert_equal({1, 2, 3, 4, 5, 6}, self.list_objects())

    def test_repair_index_too_new(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.assert_equal(self.list_indices(), ["index.3"])
        self.rename_index("index.100")
        self.check(status=True)
        self.assert_equal(self.list_indices(), ["index.3"])
        self.get_objects(4)
        self.assert_equal({1, 2, 3, 4, 5, 6}, self.list_objects())

    def test_crash_before_compact(self):
        self.repository.put(H(0), fchunk(b"data"))
        self.repository.put(H(0), fchunk(b"data2"))
        # Simulate a crash before compact
        with patch.object(Repository, "compact_segments") as compact:
            self.repository.commit(compact=True)
            compact.assert_called_once_with(0.1)
        self.reopen()
        with self.repository:
            self.check(repair=True)
            self.assert_equal(pdchunk(self.repository.get(H(0))), b"data2")


class RepositoryHintsTestCase(RepositoryTestCaseBase):
    def test_hints_persistence(self):
        self.repository.put(H(0), fchunk(b"data"))
        self.repository.delete(H(0))
        self.repository.commit(compact=False)
        shadow_index_expected = self.repository.shadow_index
        compact_expected = self.repository.compact
        segments_expected = self.repository.segments
        # close and re-open the repository (create fresh Repository instance) to
        # check whether hints were persisted to / reloaded from disk
        self.reopen()
        with self.repository:
            # see also do_compact()
            self.repository.put(H(42), fchunk(b"foobar"))  # this will call prepare_txn() and load the hints data
            # check if hints persistence worked:
            self.assert_equal(shadow_index_expected, self.repository.shadow_index)
            self.assert_equal(compact_expected, self.repository.compact)
            del self.repository.segments[2]  # ignore the segment created by put(H(42), ...)
            self.assert_equal(segments_expected, self.repository.segments)

    def test_hints_behaviour(self):
        self.repository.put(H(0), fchunk(b"data"))
        self.assert_equal(self.repository.shadow_index, {})
        assert len(self.repository.compact) == 0
        self.repository.delete(H(0))
        self.repository.commit(compact=False)
        # now there should be an entry for H(0) in shadow_index
        self.assert_in(H(0), self.repository.shadow_index)
        self.assert_equal(len(self.repository.shadow_index[H(0)]), 1)
        self.assert_in(0, self.repository.compact)  # segment 0 can be compacted
        self.repository.put(H(42), fchunk(b"foobar"))  # see also do_compact()
        self.repository.commit(compact=True, threshold=0.0)  # compact completely!
        # nothing to compact any more! no info left about stuff that does not exist any more:
        self.assert_not_in(H(0), self.repository.shadow_index)
        # segment 0 was compacted away, no info about it left:
        self.assert_not_in(0, self.repository.compact)
        self.assert_not_in(0, self.repository.segments)


class RemoteRepositoryTestCase(RepositoryTestCase):
    repository = None  # type: RemoteRepository

    def open(self, create=False):
        return RemoteRepository(
            Location("ssh://__testsuite__" + os.path.join(self.tmppath, "repository")), exclusive=True, create=create
        )

    def _get_mock_args(self):
        class MockArgs:
            remote_path = "borg"
            umask = 0o077
            debug_topics = []
            rsh = None

            def __contains__(self, item):
                # To behave like argparse.Namespace
                return hasattr(self, item)

        return MockArgs()

    def test_invalid_rpc(self):
        self.assert_raises(InvalidRPCMethod, lambda: self.repository.call("__init__", {}))

    def test_rpc_exception_transport(self):
        s1 = "test string"

        try:
            self.repository.call("inject_exception", {"kind": "DoesNotExist"})
        except Repository.DoesNotExist as e:
            assert len(e.args) == 1
            assert e.args[0] == self.repository.location.processed

        try:
            self.repository.call("inject_exception", {"kind": "AlreadyExists"})
        except Repository.AlreadyExists as e:
            assert len(e.args) == 1
            assert e.args[0] == self.repository.location.processed

        try:
            self.repository.call("inject_exception", {"kind": "CheckNeeded"})
        except Repository.CheckNeeded as e:
            assert len(e.args) == 1
            assert e.args[0] == self.repository.location.processed

        try:
            self.repository.call("inject_exception", {"kind": "IntegrityError"})
        except IntegrityError as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            self.repository.call("inject_exception", {"kind": "PathNotAllowed"})
        except PathNotAllowed as e:
            assert len(e.args) == 1
            assert e.args[0] == "foo"

        try:
            self.repository.call("inject_exception", {"kind": "ObjectNotFound"})
        except Repository.ObjectNotFound as e:
            assert len(e.args) == 2
            assert e.args[0] == s1
            assert e.args[1] == self.repository.location.processed

        try:
            self.repository.call("inject_exception", {"kind": "InvalidRPCMethod"})
        except InvalidRPCMethod as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            self.repository.call("inject_exception", {"kind": "divide"})
        except RemoteRepository.RPCError as e:
            assert e.unpacked
            assert e.get_message() == "ZeroDivisionError: integer division or modulo by zero\n"
            assert e.exception_class == "ZeroDivisionError"
            assert len(e.exception_full) > 0

    def test_ssh_cmd(self):
        args = self._get_mock_args()
        self.repository._args = args
        assert self.repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "example.com"]
        assert self.repository.ssh_cmd(Location("ssh://user@example.com/foo")) == ["ssh", "user@example.com"]
        assert self.repository.ssh_cmd(Location("ssh://user@example.com:1234/foo")) == [
            "ssh",
            "-p",
            "1234",
            "user@example.com",
        ]
        os.environ["BORG_RSH"] = "ssh --foo"
        assert self.repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "--foo", "example.com"]

    def test_borg_cmd(self):
        assert self.repository.borg_cmd(None, testing=True) == [sys.executable, "-m", "borg", "serve"]
        args = self._get_mock_args()
        # XXX without next line we get spurious test fails when using pytest-xdist, root cause unknown:
        logging.getLogger().setLevel(logging.INFO)
        # note: test logger is on info log level, so --info gets added automagically
        assert self.repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.remote_path = "borg-0.28.2"
        assert self.repository.borg_cmd(args, testing=False) == ["borg-0.28.2", "serve", "--info"]
        args.debug_topics = ["something_client_side", "repository_compaction"]
        assert self.repository.borg_cmd(args, testing=False) == [
            "borg-0.28.2",
            "serve",
            "--info",
            "--debug-topic=borg.debug.repository_compaction",
        ]
        args = self._get_mock_args()
        args.storage_quota = 0
        assert self.repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.storage_quota = 314159265
        assert self.repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info", "--storage-quota=314159265"]
        args.rsh = "ssh -i foo"
        self.repository._args = args
        assert self.repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "-i", "foo", "example.com"]


class RemoteLegacyFree(RepositoryTestCaseBase):
    # Keep testing this so we can someday safely remove the legacy tuple format.

    def open(self, create=False):
        with patch.object(RemoteRepository, "dictFormat", True):
            return RemoteRepository(
                Location("ssh://__testsuite__" + os.path.join(self.tmppath, "repository")),
                exclusive=True,
                create=create,
            )

    def test_legacy_free(self):
        # put
        self.repository.put(H(0), fchunk(b"foo"))
        self.repository.commit(compact=False)
        self.repository.close()
        # replace
        self.repository = self.open()
        with self.repository:
            self.repository.put(H(0), fchunk(b"bar"))
            self.repository.commit(compact=False)
        # delete
        self.repository = self.open()
        with self.repository:
            self.repository.delete(H(0))
            self.repository.commit(compact=False)


class RemoteRepositoryCheckTestCase(RepositoryCheckTestCase):
    def open(self, create=False):
        return RemoteRepository(
            Location("ssh://__testsuite__" + os.path.join(self.tmppath, "repository")), exclusive=True, create=create
        )

    def test_crash_before_compact(self):
        # skip this test, we can't mock-patch a Repository class in another process!
        pass

    def test_repair_missing_commit_segment(self):
        # skip this test, files in RemoteRepository cannot be deleted
        pass

    def test_repair_missing_segment(self):
        # skip this test, files in RemoteRepository cannot be deleted
        pass


class RemoteLoggerTestCase(BaseTestCase):
    def setUp(self):
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        logging.getLogger().handlers[:] = [self.handler]
        logging.getLogger("borg.repository").handlers[:] = []
        logging.getLogger("borg.repository.foo").handlers[:] = []
        # capture stderr
        sys.stderr.flush()
        self.old_stderr = sys.stderr
        self.stderr = sys.stderr = io.StringIO()

    def tearDown(self):
        sys.stderr = self.old_stderr

    def test_stderr_messages(self):
        handle_remote_line("unstructured stderr message\n")
        self.assert_equal(self.stream.getvalue(), "")
        # stderr messages don't get an implicit newline
        self.assert_equal(self.stderr.getvalue(), "Remote: unstructured stderr message\n")

    def test_stderr_progress_messages(self):
        handle_remote_line("unstructured stderr progress message\r")
        self.assert_equal(self.stream.getvalue(), "")
        # stderr messages don't get an implicit newline
        self.assert_equal(self.stderr.getvalue(), "Remote: unstructured stderr progress message\r")

    def test_pre11_format_messages(self):
        self.handler.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

        handle_remote_line("$LOG INFO Remote: borg < 1.1 format message\n")
        self.assert_equal(self.stream.getvalue(), "Remote: borg < 1.1 format message\n")
        self.assert_equal(self.stderr.getvalue(), "")

    def test_post11_format_messages(self):
        self.handler.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

        handle_remote_line("$LOG INFO borg.repository Remote: borg >= 1.1 format message\n")
        self.assert_equal(self.stream.getvalue(), "Remote: borg >= 1.1 format message\n")
        self.assert_equal(self.stderr.getvalue(), "")

    def test_remote_messages_screened(self):
        # default borg config for root logger
        self.handler.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)

        handle_remote_line("$LOG INFO borg.repository Remote: new format info message\n")
        self.assert_equal(self.stream.getvalue(), "")
        self.assert_equal(self.stderr.getvalue(), "")

    def test_info_to_correct_local_child(self):
        logging.getLogger("borg.repository").setLevel(logging.INFO)
        logging.getLogger("borg.repository.foo").setLevel(logging.INFO)
        # default borg config for root logger
        self.handler.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)

        child_stream = io.StringIO()
        child_handler = logging.StreamHandler(child_stream)
        child_handler.setLevel(logging.INFO)
        logging.getLogger("borg.repository").handlers[:] = [child_handler]
        foo_stream = io.StringIO()
        foo_handler = logging.StreamHandler(foo_stream)
        foo_handler.setLevel(logging.INFO)
        logging.getLogger("borg.repository.foo").handlers[:] = [foo_handler]

        handle_remote_line("$LOG INFO borg.repository Remote: new format child message\n")
        self.assert_equal(foo_stream.getvalue(), "")
        self.assert_equal(child_stream.getvalue(), "Remote: new format child message\n")
        self.assert_equal(self.stream.getvalue(), "")
        self.assert_equal(self.stderr.getvalue(), "")
