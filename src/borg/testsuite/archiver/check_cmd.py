import logging
import shutil
import unittest
from unittest.mock import patch

from ...archive import ChunkBuffer
from ...constants import *  # NOQA
from ...helpers import bin_to_hex
from ...helpers import msgpack
from ...manifest import Manifest
from ...repository import Repository
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverCheckTestCase(ArchiverTestCaseBase):
    def setUp(self):
        super().setUp()
        with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
            self.create_src_archive("archive1")
            self.create_src_archive("archive2")

    def test_check_usage(self):
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--progress", exit_code=0)
        self.assert_in("Starting repository check", output)
        self.assert_in("Starting archive consistency check", output)
        self.assert_in("Checking segments", output)
        # reset logging to new process default to avoid need for fork=True on next check
        logging.getLogger("borg.output.progress").setLevel(logging.NOTSET)
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--repository-only", exit_code=0)
        self.assert_in("Starting repository check", output)
        self.assert_not_in("Starting archive consistency check", output)
        self.assert_not_in("Checking segments", output)
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--archives-only", exit_code=0)
        self.assert_not_in("Starting repository check", output)
        self.assert_in("Starting archive consistency check", output)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "check",
            "-v",
            "--archives-only",
            "--match-archives=archive2",
            exit_code=0,
        )
        self.assert_not_in("archive1", output)
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--first=1", exit_code=0
        )
        self.assert_in("archive1", output)
        self.assert_not_in("archive2", output)
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--last=1", exit_code=0
        )
        self.assert_not_in("archive1", output)
        self.assert_in("archive2", output)

    def test_date_matching(self):
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        earliest_ts = "2022-11-20T23:59:59"
        ts_in_between = "2022-12-18T23:59:59"
        self.create_src_archive("archive1", ts=earliest_ts)
        self.create_src_archive("archive2", ts=ts_in_between)
        self.create_src_archive("archive3")
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--oldest=23e", exit_code=2
        )
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--oldest=1m", exit_code=0
        )
        self.assert_in("archive1", output)
        self.assert_in("archive2", output)
        self.assert_not_in("archive3", output)

        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--newest=1m", exit_code=0
        )
        self.assert_in("archive3", output)
        self.assert_not_in("archive2", output)
        self.assert_not_in("archive1", output)
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--newer=1d", exit_code=0
        )
        self.assert_in("archive3", output)
        self.assert_not_in("archive1", output)
        self.assert_not_in("archive2", output)
        output = self.cmd(
            f"--repo={self.repository_location}", "check", "-v", "--archives-only", "--older=1d", exit_code=0
        )
        self.assert_in("archive1", output)
        self.assert_in("archive2", output)
        self.assert_not_in("archive3", output)

    def test_missing_file_chunk(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            for item in archive.iter_items():
                if item.path.endswith("testsuite/archiver/__init__.py"):
                    valid_chunks = item.chunks
                    killed_chunk = valid_chunks[-1]
                    repository.delete(killed_chunk.id)
                    break
            else:
                self.fail("should not happen")
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        output = self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)
        self.assert_in("New missing file chunk detected", output)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)
        output = self.cmd(
            f"--repo={self.repository_location}", "list", "archive1", "--format={health}#{path}{NL}", exit_code=0
        )
        self.assert_in("broken#", output)
        # check that the file in the old archives has now a different chunk list without the killed chunk
        for archive_name in ("archive1", "archive2"):
            archive, repository = self.open_archive(archive_name)
            with repository:
                for item in archive.iter_items():
                    if item.path.endswith("testsuite/archiver/__init__.py"):
                        self.assert_not_equal(valid_chunks, item.chunks)
                        self.assert_not_in(killed_chunk, item.chunks)
                        break
                else:
                    self.fail("should not happen")
        # do a fresh backup (that will include the killed chunk)
        with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
            self.create_src_archive("archive3")
        # check should be able to heal the file now:
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--repair", exit_code=0)
        self.assert_in("Healed previously missing file chunk", output)
        self.assert_in("testsuite/archiver/__init__.py: Completely healed previously damaged file!", output)
        # check that the file in the old archives has the correct chunks again
        for archive_name in ("archive1", "archive2"):
            archive, repository = self.open_archive(archive_name)
            with repository:
                for item in archive.iter_items():
                    if item.path.endswith("testsuite/archiver/__init__.py"):
                        self.assert_equal(valid_chunks, item.chunks)
                        break
                else:
                    self.fail("should not happen")
        # list is also all-healthy again
        output = self.cmd(
            f"--repo={self.repository_location}", "list", "archive1", "--format={health}#{path}{NL}", exit_code=0
        )
        self.assert_not_in("broken#", output)

    def test_missing_archive_item_chunk(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            repository.delete(archive.metadata.items[0])
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)

    def test_missing_archive_metadata(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            repository.delete(archive.id)
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)

    def test_missing_manifest(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            repository.delete(Manifest.MANIFEST_ID)
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--repair", exit_code=0)
        self.assert_in("archive1", output)
        self.assert_in("archive2", output)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)

    def test_corrupted_manifest(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b"corrupted!"
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--repair", exit_code=0)
        self.assert_in("archive1", output)
        self.assert_in("archive2", output)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)

    def test_manifest_rebuild_corrupted_chunk(self):
        archive, repository = self.open_archive("archive1")
        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b"corrupted!"
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)

            chunk = repository.get(archive.id)
            corrupted_chunk = chunk + b"corrupted!"
            repository.put(archive.id, corrupted_chunk)
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        output = self.cmd(f"--repo={self.repository_location}", "check", "-v", "--repair", exit_code=0)
        self.assert_in("archive2", output)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)

    def test_manifest_rebuild_duplicate_archive(self):
        archive, repository = self.open_archive("archive1")
        repo_objs = archive.repo_objs

        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b"corrupted!"
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)

            archive = msgpack.packb(
                {
                    "command_line": "",
                    "item_ptrs": [],
                    "hostname": "foo",
                    "username": "bar",
                    "name": "archive1",
                    "time": "2016-12-15T18:49:51.849711",
                    "version": 2,
                }
            )
            archive_id = repo_objs.id_hash(archive)
            repository.put(archive_id, repo_objs.format(archive_id, {}, archive))
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_in("archive1", output)
        self.assert_in("archive1.1", output)
        self.assert_in("archive2", output)

    def test_extra_chunks(self):
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)
        with Repository(self.repository_location, exclusive=True) as repository:
            repository.put(b"01234567890123456789012345678901", b"xxxx")
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair", exit_code=0)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)
        self.cmd(f"--repo={self.repository_location}", "extract", "archive1", "--dry-run", exit_code=0)

    def _test_verify_data(self, *init_args):
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", *init_args)
        self.create_src_archive("archive1")
        archive, repository = self.open_archive("archive1")
        with repository:
            for item in archive.iter_items():
                if item.path.endswith("testsuite/archiver/__init__.py"):
                    chunk = item.chunks[-1]
                    data = repository.get(chunk.id)
                    data = data[0:100] + b"x" + data[101:]
                    repository.put(chunk.id, data)
                    break
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=0)
        output = self.cmd(f"--repo={self.repository_location}", "check", "--verify-data", exit_code=1)
        assert bin_to_hex(chunk.id) + ", integrity error" in output
        # repair (heal is tested in another test)
        output = self.cmd(f"--repo={self.repository_location}", "check", "--repair", "--verify-data", exit_code=0)
        assert bin_to_hex(chunk.id) + ", integrity error" in output
        assert "testsuite/archiver/__init__.py: New missing file chunk detected" in output

    def test_verify_data(self):
        self._test_verify_data(RK_ENCRYPTION)

    def test_verify_data_unencrypted(self):
        self._test_verify_data("--encryption", "none")

    def test_empty_repository(self):
        with Repository(self.repository_location, exclusive=True) as repository:
            for id_ in repository.list():
                repository.delete(id_)
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "check", exit_code=1)


class RemoteArchiverCheckTestCase(RemoteArchiverTestCaseBase, ArchiverCheckTestCase):
    """run the same tests, but with a remote repository"""

    @unittest.skip("only works locally")
    def test_empty_repository(self):
        pass

    @unittest.skip("only works locally")
    def test_extra_chunks(self):
        pass


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverCheckTestCase):
    """runs the same tests, but via the borg binary"""
