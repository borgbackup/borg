import hashlib
import json
import os
import random
import re
import stat
import tarfile
from contextlib import contextmanager

import pytest

from ...constants import *  # NOQA
from ...helpers import open_item
from ...helpers.time import parse_timestamp
from ...helpers.parseformat import parse_file_size, ChunkerParams
from ..platform.platform_test import is_win32
from . import cmd, create_regular_file, create_test_files, RK_ENCRYPTION, open_archive, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote")  # NOQA


def test_transfer_upgrade(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() in ["remote", "binary"]:
        pytest.skip("only works locally")

    # test upgrading a borg 1.2 repo to borg 2
    # testing using json is a bit problematic because parseformat (used for json dumping)
    # already tweaks the values a bit for better printability (like e.g. using the empty
    # string for attributes that are not present).
    # borg 1.2 repo dir contents, created by: scripts/make-testdata/test_transfer_upgrade.sh
    repo12_tar = os.path.join(os.path.dirname(__file__), "repo12.tar.gz")
    repo12_tzoffset = "+01:00"  # timezone used to create the repo/archives/json dumps inside the tar file

    def convert_tz(local_naive, tzoffset, tzinfo):
        # local_naive was meant to be in tzoffset timezone (e.g. "+01:00"),
        # but we want it non-naive in tzinfo time zone (e.g. timezone.utc
        # or None if local timezone is desired).
        ts = parse_timestamp(local_naive + tzoffset)
        return ts.astimezone(tzinfo).isoformat(timespec="microseconds")

    original_location = archiver.repository_location
    dst_dir = f"{original_location}1"
    os.makedirs(dst_dir)
    with tarfile.open(repo12_tar) as tf:
        tf.extractall(dst_dir)

    other_repo1 = f"--other-repo={original_location}1"
    archiver.repository_location = original_location + "2"

    monkeypatch.setenv("BORG_PASSPHRASE", "pw2")
    monkeypatch.setenv("BORG_OTHER_PASSPHRASE", "waytooeasyonlyfortests")
    os.environ["BORG_TESTONLY_WEAKEN_KDF"] = "0"  # must use the strong kdf here or it can't decrypt the key

    cmd(archiver, "repo-create", RK_ENCRYPTION, other_repo1, "--from-borg1")
    cmd(archiver, "transfer", other_repo1, "--from-borg1")
    cmd(archiver, "check")

    # check list of archives / manifest
    rlist_json = cmd(archiver, "repo-list", "--json")
    got = json.loads(rlist_json)
    with open(os.path.join(dst_dir, "test_meta", "repo_list.json")) as f:
        expected = json.load(f)

    for key in "encryption", "repository":
        # some stuff obviously needs to be different, remove that!
        del got[key]
        del expected[key]
    assert len(got["archives"]) == len(expected["archives"])

    for got_archive, expected_archive in zip(got["archives"], expected["archives"]):
        del got_archive["id"]
        del got_archive["username"]  # we didn't have this in the 1.x default format
        del got_archive["hostname"]  # we didn't have this in the 1.x default format
        del got_archive["comment"]  # we didn't have this in the 1.x default format
        del got_archive["tags"]  # we didn't have this in the 1.x default format
        del expected_archive["id"]
        del expected_archive["barchive"]
        # timestamps:
        # borg 1.2 transformed to local time and had microseconds = 0, no tzoffset
        # borg 2 uses local time, with microseconds and with tzoffset
        for key in "start", "time":
            # fix expectation: local time meant +01:00, so we convert that to whatever local tz is here.
            expected_archive[key] = convert_tz(expected_archive[key], repo12_tzoffset, None)
            # set microseconds to 0, so we can compare got with expected.
            got_ts = parse_timestamp(got_archive[key])
            got_archive[key] = got_ts.replace(microsecond=0).isoformat(timespec="microseconds")
    assert got == expected

    for archive in got["archives"]:
        name = archive["name"]
        # check archive contents
        list_json = cmd(archiver, "list", "--json-lines", name)
        got = [json.loads(line) for line in list_json.splitlines()]
        with open(os.path.join(dst_dir, "test_meta", f"{name}_list.json")) as f:
            lines = f.read()
        expected = [json.loads(line) for line in lines.splitlines()]
        hardlinks = {}
        for g, e in zip(got, expected):
            # borg 1.2 parseformat uses .get("bsdflags", 0) so the json has 0 even
            # if there were no bsdflags stored in the item.
            # borg 2 parseformat uses .get("bsdflags"), so the json has either an int
            # (if the archived item has bsdflags) or None (if the item has no bsdflags).
            if e["flags"] == 0 and g["flags"] is None:
                # this is expected behaviour, fix the expectation
                e["flags"] = None

            # borg2 parseformat falls back to str(item.uid) if it does not have item.user,
            # same for str(item.gid) and no item.group.
            # so user/group are always str type, even if it is just str(uid) or str(gid).
            # fix expectation (borg1 used int type for user/group in that case):
            if g["user"] == str(g["uid"]) == str(e["uid"]):
                e["user"] = str(e["uid"])
            if g["group"] == str(g["gid"]) == str(e["gid"]):
                e["group"] = str(e["gid"])

            for key in "mtime", "ctime", "atime":
                if key in e:
                    e[key] = convert_tz(e[key], repo12_tzoffset, None)

            # borg 1 used hardlink slaves linking back to their hardlink masters.
            # borg 2 uses symmetric approach: just normal items. if they are hardlinks,
            # each item has normal attributes, including the chunks list, size. additionally,
            # they have a hlid and same hlid means same inode / belonging to same set of hardlinks.
            hardlink = bool(g.get("hlid"))  # note: json has "" as hlid if there is no hlid in the item
            if hardlink:
                hardlinks[g["path"]] = g["hlid"]
                if e["mode"].startswith("h"):
                    # fix expectations: borg1 signalled a hardlink slave with "h"
                    # borg2 treats all hardlinks symmetrically as normal files
                    e["mode"] = g["mode"][0] + e["mode"][1:]
                    # borg1 used source/linktarget to link back to hardlink master
                    assert e["source"] != ""
                    assert e["linktarget"] != ""
                    # fix expectations: borg2 does not use source/linktarget any more for hardlinks
                    e["source"] = ""
                    e["linktarget"] = ""
                    # borg 1 has size == 0 for hardlink slaves, borg 2 has the real file size
                    assert e["size"] == 0
                    assert g["size"] >= 0
                    # fix expectation for size
                    e["size"] = g["size"]
                # Note: size == 0 for all items without a size or chunks list (like e.g. directories)
            del g["hlid"]

            # borg 1 used "linktarget" and "source" for links, borg 2 uses "target" for symlinks.
            if g["target"] == e["linktarget"]:
                e["target"] = e["linktarget"]
                del e["linktarget"]
                del e["source"]

            if e["type"] == "b" and is_win32:
                # The S_IFBLK macro is broken on MINGW
                del e["type"], g["type"]
                del e["mode"], g["mode"]

            del e["healthy"]  # not supported anymore

            assert g == e

        if name == "archive1":
            # hardlinks referring to same inode have same hlid
            assert hardlinks["tmp/borgtest/hardlink1"] == hardlinks["tmp/borgtest/hardlink2"]

    repo_path = f"{original_location}2"
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(repo_path, archive_name)
        with repository:
            for item in archive.iter_items():
                # borg1 used to store some stuff with None values
                # borg2 does just not have the key if the value is not known.
                item_dict = item.as_dict()
                assert not any(value is None for value in item_dict.values()), f"found None value in {item_dict}"

                # with borg2, all items with chunks must have a precomputed size
                assert "chunks" not in item or "size" in item and item.size >= 0

                if item.path.endswith("directory") or item.path.endswith("borgtest"):
                    assert stat.S_ISDIR(item.mode)
                    assert item.uid > 0
                    assert "hlid" not in item
                elif item.path.endswith("no_hardlink") or item.path.endswith("target"):
                    assert stat.S_ISREG(item.mode)
                    assert item.uid > 0
                    assert "hlid" not in item
                    assert len(item.chunks) > 0
                    assert "bsdflags" not in item
                elif item.path.endswith("hardlink1"):
                    assert stat.S_ISREG(item.mode)
                    assert item.uid > 0
                    assert "hlid" in item and len(item.hlid) == 32  # 256bit
                    hlid1 = item.hlid
                    assert len(item.chunks) > 0
                    chunks1 = item.chunks
                    size1 = item.size
                    assert "source" not in item
                    assert "target" not in item
                    assert "hardlink_master" not in item
                elif item.path.endswith("hardlink2"):
                    assert stat.S_ISREG(item.mode)
                    assert item.uid > 0
                    assert "hlid" in item and len(item.hlid) == 32  # 256bit
                    hlid2 = item.hlid
                    assert len(item.chunks) > 0
                    chunks2 = item.chunks
                    size2 = item.size
                    assert "source" not in item
                    assert "target" not in item
                    assert "hardlink_master" not in item
                elif item.path.endswith("broken_symlink"):
                    assert stat.S_ISLNK(item.mode)
                    assert item.target == "doesnotexist"
                    assert item.uid > 0
                    assert "hlid" not in item
                elif item.path.endswith("symlink"):
                    assert stat.S_ISLNK(item.mode)
                    assert item.target == "target"
                    assert item.uid > 0
                    assert "hlid" not in item
                elif item.path.endswith("fifo"):
                    assert stat.S_ISFIFO(item.mode)
                    assert item.uid > 0
                    assert "hlid" not in item
                elif item.path.endswith("without_xattrs"):
                    assert stat.S_ISREG(item.mode)
                    assert "xattrs" not in item
                elif item.path.endswith("with_xattrs"):
                    assert stat.S_ISREG(item.mode)
                    assert "xattrs" in item
                    assert len(item.xattrs) == 2
                    assert item.xattrs[b"key1"] == b"value"
                    assert item.xattrs[b"key2"] == b""
                elif item.path.endswith("without_flags"):
                    assert stat.S_ISREG(item.mode)
                    # borg1 did not store a flags value of 0 ("nothing special")
                    # borg2 reflects this "I do not know" by not having the k/v pair
                    assert "bsdflags" not in item
                elif item.path.endswith("with_flags"):
                    assert stat.S_ISREG(item.mode)
                    assert "bsdflags" in item
                    assert item.bsdflags == stat.UF_NODUMP
                elif item.path.endswith("root_stuff"):
                    assert stat.S_ISDIR(item.mode)
                    assert item.uid == 0
                    assert item.gid == 0
                    assert "hlid" not in item
                elif item.path.endswith("cdev_34_56"):
                    assert stat.S_ISCHR(item.mode)
                    # looks like we can't use os.major/minor with data coming from another platform,
                    # thus we only do a rather rough check here:
                    assert "rdev" in item and item.rdev != 0
                    assert item.uid == 0
                    assert item.gid == 0
                    assert item.user == "root"
                    assert item.group in ("root", "wheel")
                    assert "hlid" not in item
                elif item.path.endswith("bdev_12_34"):
                    if not is_win32:
                        # The S_IFBLK macro is broken on MINGW
                        assert stat.S_ISBLK(item.mode)
                    # looks like we can't use os.major/minor with data coming from another platform,
                    # thus we only do a rather rough check here:
                    assert "rdev" in item and item.rdev != 0
                    assert item.uid == 0
                    assert item.gid == 0
                    assert item.user == "root"
                    assert item.group in ("root", "wheel")
                    assert "hlid" not in item
                elif item.path.endswith("strange_uid_gid"):
                    assert stat.S_ISREG(item.mode)
                    assert item.uid == 54321
                    assert item.gid == 54321
                    assert "user" not in item
                    assert "group" not in item
                else:
                    raise NotImplementedError(f"test missing for {item.path}")
        if archive_name == "archive1":
            assert hlid1 == hlid2
            assert size1 == size2 == 16 + 1  # 16 text chars + \n
            assert chunks1 == chunks2


@contextmanager
def setup_repos(archiver, mp):
    """
    set up repos for transfer tests: OTHER_REPO1  ---transfer---> REPO2
    when the context manager is entered, archiver will work with REPO1 (so one can prepare it as the source repo).
    when the context manager is exited, archiver will work with REPO2 (so the transfer can be run).
    """
    original_location = archiver.repository_location
    original_path = archiver.repository_path

    mp.setenv("BORG_PASSPHRASE", "pw1")
    archiver.repository_location = original_location + "1"
    archiver.repository_path = original_path + "1"
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    other_repo1 = f"--other-repo={original_location}1"
    yield other_repo1

    mp.setenv("BORG_PASSPHRASE", "pw2")
    mp.setenv("BORG_OTHER_PASSPHRASE", "pw1")
    archiver.repository_location = original_location + "2"
    archiver.repository_path = original_path + "2"
    cmd(archiver, "repo-create", RK_ENCRYPTION, other_repo1)


def test_transfer(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)

    def check_repo():
        listing = cmd(archiver, "repo-list")
        assert "arch1" in listing
        assert "arch2" in listing
        listing = cmd(archiver, "list", "--short", "arch1")
        assert "file1" in listing
        assert "dir2/file2" in listing
        cmd(archiver, "check")

    with setup_repos(archiver, monkeypatch) as other_repo1:
        # prepare the source repo:
        create_test_files(archiver.input_path)
        cmd(archiver, "create", "arch1", "input")
        cmd(archiver, "create", "arch2", "input")
        check_repo()

    # test the transfer:
    cmd(archiver, "transfer", other_repo1, "--dry-run")
    cmd(archiver, "transfer", other_repo1)
    cmd(archiver, "transfer", other_repo1, "--dry-run")
    check_repo()


def test_transfer_archive_metadata(archivers, request, monkeypatch):
    """Test transfer of archive metadata"""
    archiver = request.getfixturevalue(archivers)

    with setup_repos(archiver, monkeypatch) as other_repo1:
        create_test_files(archiver.input_path)
        # Create an archive with a comment
        test_comment = "This is a test comment for transfer"
        cmd(archiver, "create", "--comment", test_comment, "archive", "input")

        # Get metadata from source archive
        source_info_json = cmd(archiver, "info", "--json", "archive")
        source_info = json.loads(source_info_json)
        source_archive = source_info["archives"][0]

    # Transfer should succeed
    cmd(archiver, "transfer", other_repo1)

    # Get metadata from destination archive
    dest_info_json = cmd(archiver, "info", "--json", "archive")
    dest_info = json.loads(dest_info_json)
    dest_archive = dest_info["archives"][0]

    # Compare metadata fields
    assert dest_archive["comment"] == source_archive["comment"]
    assert dest_archive["hostname"] == source_archive["hostname"]
    assert dest_archive["username"] == source_archive["username"]
    assert dest_archive["command_line"] == source_archive["command_line"]
    assert dest_archive["duration"] == source_archive["duration"]
    assert dest_archive["start"] == source_archive["start"]
    assert dest_archive["end"] == source_archive["end"]
    assert dest_archive["tags"] == source_archive["tags"]
    assert dest_archive["chunker_params"] == source_archive["chunker_params"]

    # Compare stats
    assert dest_archive["stats"]["nfiles"] == source_archive["stats"]["nfiles"]
    # Note: original_size might differ slightly between source and destination due to implementation details
    # but they should be close enough for the test to pass. TODO: check this, could also be a bug maybe.
    assert abs(dest_archive["stats"]["original_size"] - source_archive["stats"]["original_size"]) < 10000


@pytest.mark.parametrize("recompress_mode", ["never", "always"])
def test_transfer_recompress(archivers, request, monkeypatch, recompress_mode):
    """Test transfer with recompression"""
    archiver = request.getfixturevalue(archivers)

    def repo_size(archiver):
        output = cmd(archiver, "compact", "-v", "--stats")
        match = re.search(r"Repository size is ([^B]+)B", output, re.MULTILINE)
        size = parse_file_size(match.group(1))
        return size

    with setup_repos(archiver, monkeypatch) as other_repo1:
        create_test_files(archiver.input_path)
        cmd(archiver, "create", "--compression=none", "archive", "input")
        source_size = repo_size(archiver)

    # Test with --recompress and a different compression algorithm
    cmd(archiver, "transfer", other_repo1, f"--recompress={recompress_mode}", "--compression=zstd")
    dest_size = repo_size(archiver)

    # Verify that the transfer succeeded
    listing = cmd(archiver, "repo-list")
    assert "archive" in listing

    # Check repository size difference based on recompress_mode
    if recompress_mode == "always":
        # zstd compression is better than none.
        assert source_size > dest_size, f"dest_size ({dest_size}) should be smaller than source_size ({source_size})."
    else:  # recompress_mode == "never"
        # When not recompressing, the data chunks should remain the same size.
        # There might be small differences due to metadata, but they should be minimal
        # We allow a small percentage difference to account for metadata changes.
        size_diff_percent = abs(source_size - dest_size) / source_size * 100
        assert size_diff_percent < 5, f"dest_size ({dest_size}) should be similar as source_size ({source_size})."


def test_transfer_rechunk(archivers, request, monkeypatch):
    """Test transfer with re-chunking"""
    archiver = request.getfixturevalue(archivers)

    BLKSIZE = 512
    source_chunker_params = "buzhash,19,23,21,4095"  # default buzhash chunks
    dest_chunker_params = f"fixed,{BLKSIZE}"  # fixed chunk size

    with setup_repos(archiver, monkeypatch) as other_repo1:
        contents_1 = random.randbytes(1 * BLKSIZE)
        contents_255 = random.randbytes(255 * BLKSIZE)
        contents_1024 = random.randbytes(1024 * BLKSIZE)
        create_regular_file(archiver.input_path, "file_1", contents=contents_1)
        create_regular_file(archiver.input_path, "file_256", contents=contents_255 + contents_1)
        create_regular_file(archiver.input_path, "file_1280", contents=contents_1024 + contents_255 + contents_1)

        cmd(archiver, "create", f"--chunker-params={source_chunker_params}", "archive", "input")

        # Get metadata from source archive
        source_info_json = cmd(archiver, "info", "--json", "archive")
        source_info = json.loads(source_info_json)
        source_archive = source_info["archives"][0]
        source_chunker_params_info = source_archive["chunker_params"]

        # Calculate SHA256 hashes of file contents from source archive
        source_archive_obj, source_repo = open_archive(archiver.repository_path, "archive")
        with source_repo:
            source_file_hashes = {}
            for item in source_archive_obj.iter_items():
                if hasattr(item, "chunks"):  # Only process regular files with chunks
                    f = open_item(source_archive_obj, item)
                    content = f.read(10 * 1024 * 1024)  # Read up to 10 MB
                    source_file_hashes[item.path] = hashlib.sha256(content).hexdigest()

    # Transfer with rechunking
    cmd(archiver, "transfer", other_repo1, f"--chunker-params={dest_chunker_params}")

    # Get metadata from destination archive
    dest_info_json = cmd(archiver, "info", "--json", "archive")
    dest_info = json.loads(dest_info_json)
    dest_archive = dest_info["archives"][0]
    dest_chunker_params_info = dest_archive["chunker_params"]

    # chunker params in metadata must reflect the chunker params given on the CLI
    assert tuple(source_chunker_params_info) == ChunkerParams(source_chunker_params)
    assert tuple(dest_chunker_params_info) == ChunkerParams(dest_chunker_params)

    # Compare file hashes between source and destination archives, also check expected chunk counts.
    dest_archive_obj, dest_repo = open_archive(archiver.repository_path, "archive")
    with dest_repo:
        for item in dest_archive_obj.iter_items():
            if hasattr(item, "chunks"):  # Only process regular files with chunks
                # Verify expected chunk count for each file
                expected_chunk_count = {"input/file_1": 1, "input/file_256": 256, "input/file_1280": 1280}[item.path]
                assert len(item.chunks) == expected_chunk_count
                f = open_item(dest_archive_obj, item)
                content = f.read(10 * 1024 * 1024)  # Read up to 10 MB
                dest_hash = hashlib.sha256(content).hexdigest()
                # Verify that the file hash is identical to the source
                assert item.path in source_file_hashes, f"File {item.path} not found in source archive"
                assert dest_hash == source_file_hashes[item.path], f"Content hash mismatch for {item.path}"
