"""Tests for borg.legacy.upgrade (UpgraderFrom12To20)."""

import stat
import zlib
from argparse import Namespace
from struct import Struct
from unittest.mock import MagicMock

from ..compress import ZLIB, ObfuscateSize
from ..constants import CH_BUZHASH, REQUIRED_ITEM_KEYS
from ..item import Item
from ..legacy.upgrade import UpgraderFrom12To20

CHUNK_ID = b"\xab" * 32
CHUNK_SIZE = 512


# ── helpers ───────────────────────────────────────────────────────────────────


def _upgrader(*, rechunk=None):
    """Return (upgrader, mock_cache, mock_archive) ready for upgrade calls."""
    cache = MagicMock()
    args = Namespace(chunker_params=rechunk)
    u = UpgraderFrom12To20(cache=cache, args=args)
    archive = MagicMock()
    u.new_archive(archive=archive)
    return u, cache, archive


def _item(**kwargs):
    """Build an Item via internal_dict to allow borg1-only keys (hardlink_master, source, etc.)."""
    base = {"path": "dir/file", "mode": stat.S_IFREG | 0o644, "mtime": 0}
    base.update(kwargs)
    return Item(internal_dict=base)


def _run_upgrade_archive_metadata(attrs, *, rechunk=None):
    u, _, _ = _upgrader(rechunk=rechunk)
    return u.upgrade_archive_metadata(metadata=Namespace(**attrs))


# ── upgrade_item ──────────────────────────────────────────────────────────────


def test_regular_file_passes_through():
    u, _, _ = _upgrader()
    item = _item()
    result = u.upgrade_item(item=item)
    assert result.path == "dir/file"
    assert result.mode == stat.S_IFREG | 0o644
    assert all(k in result for k in REQUIRED_ITEM_KEYS)


def test_whitelist_strips_legacy_keys():
    # 'acl' = attic <= 0.13 bug; 'chunks_healthy' and 'hardlink_master' are borg1-only
    u, _, _ = _upgrader()
    item = _item(acl=b"bad", chunks_healthy=[], hardlink_master=False)
    result = u.upgrade_item(item=item)
    d = result.as_dict()
    assert "acl" not in d
    assert "chunks_healthy" not in d
    assert "hardlink_master" not in d


def test_user_group_none_removed():
    u, _, _ = _upgrader()
    item = _item(user=None, group=None)
    result = u.upgrade_item(item=item)
    d = result.as_dict()
    assert "user" not in d
    assert "group" not in d


def test_symlink_source_renamed_to_target():
    u, _, _ = _upgrader()
    item = _item(path="dir/link", mode=stat.S_IFLNK | 0o777, source="/etc/hosts")
    result = u.upgrade_item(item=item)
    d = result.as_dict()
    assert d["target"] == "/etc/hosts"
    assert "source" not in d


def test_hardlink_master_gets_hlid_and_strips_hardlink_master_key():
    u, _, _ = _upgrader()
    item = _item(hardlink_master=True, chunks=[[CHUNK_ID, CHUNK_SIZE]])
    result = u.upgrade_item(item=item)
    d = result.as_dict()
    assert "hlid" in d
    assert "hardlink_master" not in d
    assert d["chunks"] == [[CHUNK_ID, CHUNK_SIZE]]


def test_hardlink_slave_resolves_hlid_and_reuses_chunks():
    u, cache, archive = _upgrader()
    master = _item(hardlink_master=True, chunks=[[CHUNK_ID, CHUNK_SIZE]])
    u.upgrade_item(item=master)

    slave = _item(path="dir/link2", source="dir/file")
    result = u.upgrade_item(item=slave)

    d = result.as_dict()
    assert "hlid" in d
    assert "source" not in d
    assert d["chunks"] == [[CHUNK_ID, CHUNK_SIZE]]
    cache.reuse_chunk.assert_called_once_with(CHUNK_ID, CHUNK_SIZE, archive.stats)


def test_master_and_slave_share_the_same_hlid():
    u, _, _ = _upgrader()
    master = _item(hardlink_master=True, chunks=[[CHUNK_ID, CHUNK_SIZE]])
    master_result = u.upgrade_item(item=master)

    slave = _item(path="dir/link2", source="dir/file")
    slave_result = u.upgrade_item(item=slave)

    assert master_result.hlid == slave_result.hlid


def test_required_item_keys_always_present():
    u, _, _ = _upgrader()
    item = _item()
    result = u.upgrade_item(item=item)
    assert all(k in result for k in REQUIRED_ITEM_KEYS)


# ── upgrade_archive_metadata ──────────────────────────────────────────────────


def test_cmdline_list_becomes_command_line_string():
    result = _run_upgrade_archive_metadata({"cmdline": ["borg", "create", "::arch", "/home"]})
    assert result["command_line"] == "borg create ::arch /home"
    assert "cmdline" not in result


def test_recreate_cmdline_becomes_recreate_command_line_string():
    result = _run_upgrade_archive_metadata({"recreate_cmdline": ["borg", "recreate", "--recompress"]})
    assert result["recreate_command_line"] == "borg recreate --recompress"
    assert "recreate_cmdline" not in result


def test_time_gets_utc_offset_appended():
    result = _run_upgrade_archive_metadata({"time": "2021-01-01T12:00:00.000000"})
    assert result["time"] == "2021-01-01T12:00:00.000000+00:00"


def test_old_4tuple_chunker_params_gets_buzhash_prefix():
    old = (10, 23, 16, 4095)
    result = _run_upgrade_archive_metadata({"chunker_params": old})
    assert result["chunker_params"] == (CH_BUZHASH,) + old


def test_new_5tuple_chunker_params_unchanged():
    new = (CH_BUZHASH, 10, 23, 16, 4095)
    result = _run_upgrade_archive_metadata({"chunker_params": new})
    assert result["chunker_params"] == new


def test_rechunking_overrides_stored_chunker_params():
    override = (CH_BUZHASH, 12, 25, 18, 4095)
    result = _run_upgrade_archive_metadata({"chunker_params": (10, 23, 16, 4095)}, rechunk=override)
    assert result["chunker_params"] == override


def test_recreate_fields_dropped():
    result = _run_upgrade_archive_metadata(
        {
            "recreate_source_id": b"\x01" * 32,
            "recreate_args": ["--some-arg"],
            "recreate_partial_chunks": [[b"\x02" * 32, 100]],
        }
    )
    assert "recreate_source_id" not in result
    assert "recreate_args" not in result
    assert "recreate_partial_chunks" not in result


def test_tags_always_set_to_empty_list():
    result = _run_upgrade_archive_metadata({})
    assert result["tags"] == []


def test_missing_optional_attrs_not_in_result():
    result = _run_upgrade_archive_metadata({})
    assert "command_line" not in result
    assert "time" not in result
    assert "chunker_params" not in result


# ── upgrade_compressed_chunk ──────────────────────────────────────────────────


def test_zlib_legacy_detected_and_ctype_promoted():
    # Raw zlib bytes (no ctype/clevel prefix) — ZLIB_legacy.detect() matches them
    raw = zlib.compress(b"hello world")
    u, _, _ = _upgrader()
    meta, out = u.upgrade_compressed_chunk({}, raw)
    assert meta["ctype"] == ZLIB.ID
    assert meta["clevel"] == 0xFF
    assert meta["csize"] == len(raw)
    assert out == raw  # data is unchanged; only metadata is upgraded


def test_non_zlib_two_prefix_bytes_stripped():
    # Any compressor with explicit ctype/clevel bytes (e.g. LZ4 ID=0x01)
    payload = b"lz4_compressed_payload"
    data = bytes([0x01, 0xFF]) + payload
    u, _, _ = _upgrader()
    meta, out = u.upgrade_compressed_chunk({}, data)
    assert meta["ctype"] == 0x01
    assert meta["clevel"] == 0xFF
    assert out == payload
    assert meta["csize"] == len(payload)


def test_obfuscate_old_big_endian_csize_is_upgraded():
    # Borg 1.x ObfuscateSize used big-endian csize; borg 2 uses little-endian.
    # The upgrader must re-parse the header and preserve the inner payload + padding.
    inner = zlib.compress(b"secret data")
    csize = len(inner)
    big_endian_csize = Struct(">I").pack(csize)
    padding = bytes(16)
    data = bytes([ObfuscateSize.ID, 0xFF]) + big_endian_csize + inner + padding

    u, _, _ = _upgrader()
    meta, out = u.upgrade_compressed_chunk({}, data)

    assert meta["psize"] == csize
    assert meta["ctype"] == ZLIB.ID  # inner was ZLIB_legacy → promoted
    assert meta["clevel"] == 0xFF
    assert len(out) == csize + len(padding)
    assert meta["csize"] == len(out)
    assert out[csize:] == padding  # trailing zeros preserved
