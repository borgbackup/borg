import json
import os
import stat
import tarfile

import pytest

from ...constants import *  # NOQA
from ...helpers.time import parse_timestamp
from ..platform import is_win32
from . import cmd, create_test_files, RK_ENCRYPTION, open_archive, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_transfer(archivers, request):
    archiver = request.getfixturevalue(archivers)
    original_location, input_path = archiver.repository_location, archiver.input_path

    def check_repo():
        listing = cmd(archiver, "rlist", "--short")
        assert "arch1" in listing
        assert "arch2" in listing
        listing = cmd(archiver, "list", "--short", "arch1")
        assert "file1" in listing
        assert "dir2/file2" in listing
        cmd(archiver, "check")

    create_test_files(input_path)
    archiver.repository_location = original_location + "1"

    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "arch1", "input")
    cmd(archiver, "create", "arch2", "input")
    check_repo()

    archiver.repository_location = original_location + "2"
    other_repo1 = f"--other-repo={original_location}1"
    cmd(archiver, "rcreate", RK_ENCRYPTION, other_repo1)
    cmd(archiver, "transfer", other_repo1, "--dry-run")
    cmd(archiver, "transfer", other_repo1)
    cmd(archiver, "transfer", other_repo1, "--dry-run")
    check_repo()


def test_transfer_upgrade(archivers, request):
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

    assert os.environ.get("BORG_PASSPHRASE") == "waytooeasyonlyfortests"
    os.environ["BORG_TESTONLY_WEAKEN_KDF"] = "0"  # must use the strong kdf here or it can't decrypt the key

    cmd(archiver, "rcreate", RK_ENCRYPTION, other_repo1)
    cmd(archiver, "transfer", other_repo1, "--upgrader=From12To20")
    cmd(archiver, "check")

    # check list of archives / manifest
    rlist_json = cmd(archiver, "rlist", "--json")
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
                # Note: healthy == True indicates the *absence* of the additional chunks_healthy list
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
