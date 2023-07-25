"""
test_disk_full is very slow and not recommended to be included in daily testing.
for this test, an empty, writable 16MB filesystem mounted on DF_MOUNT is required.
for speed and other reasons, it is recommended that the underlying block device is
in RAM, not a magnetic or flash disk.

assuming /tmp is a tmpfs (in memory filesystem), one can use this:
dd if=/dev/zero of=/tmp/borg-disk bs=16M count=1
mkfs.ext4 /tmp/borg-disk
mkdir /tmp/borg-mount
sudo mount /tmp/borg-disk /tmp/borg-mount

if the directory does not exist, the test will be skipped.
"""
import errno
import os
import random
import shutil

import pytest

from ...constants import *  # NOQA
from . import cmd_fixture

DF_MOUNT = "/tmp/borg-mount"


@pytest.mark.skipif(not os.path.exists(DF_MOUNT), reason="needs a 16MB fs mounted on %s" % DF_MOUNT)
def test_disk_full(cmd_fixture, monkeypatch):
    def make_files(dir, count, size, rnd=True):
        shutil.rmtree(dir, ignore_errors=True)
        os.mkdir(dir)
        if rnd:
            count = random.randint(1, count)
            if size > 1:
                size = random.randint(1, size)
        for i in range(count):
            fn = os.path.join(dir, "file%03d" % i)
            with open(fn, "wb") as f:
                data = os.urandom(size)
                f.write(data)

    monkeypatch.setenv("BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "YES")
    mount = DF_MOUNT
    assert os.path.exists(mount)
    repo = os.path.join(mount, "repo")
    input = os.path.join(mount, "input")
    reserve = os.path.join(mount, "reserve")
    for j in range(100):
        shutil.rmtree(repo, ignore_errors=True)
        shutil.rmtree(input, ignore_errors=True)
        # keep some space and some inodes in reserve that we can free up later:
        make_files(reserve, 80, 100000, rnd=False)
        rc, out = cmd_fixture(f"--repo={repo}", "rcreate")
        if rc != EXIT_SUCCESS:
            print("rcreate", rc, out)
        assert rc == EXIT_SUCCESS
        try:
            success, i = True, 0
            while success:
                i += 1
                try:
                    make_files(input, 20, 200000)
                except OSError as err:
                    if err.errno == errno.ENOSPC:
                        # already out of space
                        break
                    raise
                try:
                    rc, out = cmd_fixture("--repo=%s" % repo, "create", "test%03d" % i, input)
                    success = rc == EXIT_SUCCESS
                    if not success:
                        print("create", rc, out)
                finally:
                    # make sure repo is not locked
                    shutil.rmtree(os.path.join(repo, "lock.exclusive"), ignore_errors=True)
                    os.remove(os.path.join(repo, "lock.roster"))
        finally:
            # now some error happened, likely we are out of disk space.
            # free some space such that we can expect borg to be able to work normally:
            shutil.rmtree(reserve, ignore_errors=True)
        rc, out = cmd_fixture(f"--repo={repo}", "rlist")
        if rc != EXIT_SUCCESS:
            print("rlist", rc, out)
        rc, out = cmd_fixture(f"--repo={repo}", "check", "--repair")
        if rc != EXIT_SUCCESS:
            print("check", rc, out)
        assert rc == EXIT_SUCCESS
