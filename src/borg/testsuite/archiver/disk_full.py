"""
test_disk_full is very slow and not recommended to be included in daily testing.
for this test, an empty, writable 700MB filesystem mounted on DF_MOUNT is required.
for speed and other reasons, it is recommended that the underlying block device is
in RAM, not a magnetic or flash disk.

assuming /dev/shm is a tmpfs (in memory filesystem), one can use this:

dd if=/dev/zero of=/dev/shm/borg-disk bs=1M count=700
mkfs.ext4 /dev/shm/borg-disk
mkdir /tmp/borg-mount
sudo mount /dev/shm/borg-disk /tmp/borg-mount
sudo chown myuser /tmp/borg-mount/

if the directory does not exist, the test will be skipped.
"""

import errno
import os
import random
import shutil

import pytest

from ...constants import *  # NOQA
from . import cmd_fixture  # NOQA

DF_MOUNT = "/tmp/borg-mount"


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


@pytest.mark.skipif(not os.path.exists(DF_MOUNT), reason="needs a 700MB fs mounted on %s" % DF_MOUNT)
@pytest.mark.parametrize("test_pass", range(10))
def test_disk_full(test_pass, cmd_fixture, monkeypatch):
    monkeypatch.setenv("BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "YES")
    monkeypatch.setenv("BORG_DELETE_I_KNOW_WHAT_I_AM_DOING", "YES")
    repo = os.path.join(DF_MOUNT, "repo")
    input = os.path.join(DF_MOUNT, "input")
    shutil.rmtree(repo, ignore_errors=True)
    shutil.rmtree(input, ignore_errors=True)
    rc, out = cmd_fixture(f"--repo={repo}", "repo-create", "--encryption=none")
    if rc != EXIT_SUCCESS:
        print("repo-create", rc, out)
    assert rc == EXIT_SUCCESS
    try:
        try:
            success, i = True, 0
            while success:
                i += 1
                try:
                    # have some randomness here to produce different out of space conditions:
                    make_files(input, 40, 1000000, rnd=True)
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
                    shutil.rmtree(os.path.join(repo, "lock.roster"), ignore_errors=True)
        finally:
            # now some error happened, likely we are out of disk space.
            # free some space such that we can expect borg to be able to work normally:
            shutil.rmtree(input, ignore_errors=True)
        rc, out = cmd_fixture(f"--repo={repo}", "repo-list")
        if rc != EXIT_SUCCESS:
            print("repo-list", rc, out)
        rc, out = cmd_fixture(f"--repo={repo}", "check", "--repair")
        if rc != EXIT_SUCCESS:
            print("check", rc, out)
        assert rc == EXIT_SUCCESS
    finally:
        # try to free the space allocated for the repo
        cmd_fixture(f"--repo={repo}", "repo-delete")
