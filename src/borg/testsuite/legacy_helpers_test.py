"""Tests for borg.legacy.helpers (borg1_hardlinkable, borg1_hardlink_master, borg1_hardlink_slave)."""

import stat

from ..item import Item
from ..legacy.helpers import borg1_hardlink_master, borg1_hardlink_slave, borg1_hardlinkable


def _item(**kwargs):
    base = {"path": "dir/file", "mode": stat.S_IFREG | 0o644, "mtime": 0}
    base.update(kwargs)
    return Item(internal_dict=base)


# ── borg1_hardlinkable ────────────────────────────────────────────────────────


def test_hardlinkable_regular_file():
    assert borg1_hardlinkable(stat.S_IFREG | 0o644)


def test_hardlinkable_block_device():
    assert borg1_hardlinkable(stat.S_IFBLK | 0o660)


def test_hardlinkable_char_device():
    assert borg1_hardlinkable(stat.S_IFCHR | 0o660)


def test_hardlinkable_fifo():
    assert borg1_hardlinkable(stat.S_IFIFO | 0o644)


def test_hardlinkable_symlink_is_false():
    assert not borg1_hardlinkable(stat.S_IFLNK | 0o777)


def test_hardlinkable_directory_is_false():
    assert not borg1_hardlinkable(stat.S_IFDIR | 0o755)


def test_hardlinkable_socket_is_false():
    assert not borg1_hardlinkable(stat.S_IFSOCK | 0o600)


# ── borg1_hardlink_master ─────────────────────────────────────────────────────


def test_hardlink_master_true_when_all_conditions_met():
    item = _item(hardlink_master=True)
    assert borg1_hardlink_master(item)


def test_hardlink_master_false_when_flag_missing():
    item = _item()
    assert not borg1_hardlink_master(item)


def test_hardlink_master_false_when_flag_is_false():
    item = _item(hardlink_master=False)
    assert not borg1_hardlink_master(item)


# ── borg1_hardlink_slave ──────────────────────────────────────────────────────


def test_hardlink_slave_true_when_source_and_hardlinkable():
    item = _item(source="dir/original")
    assert borg1_hardlink_slave(item)


def test_hardlink_slave_true_for_non_regular_hardlinkable_type():
    # borg1_hardlinkable covers FIFO/block/char as well as regular files
    item = _item(source="dir/original", mode=stat.S_IFIFO | 0o644)
    assert borg1_hardlink_slave(item)


def test_hardlink_slave_false_when_no_source():
    item = _item()
    assert not borg1_hardlink_slave(item)
