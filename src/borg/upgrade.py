from struct import Struct

from .constants import REQUIRED_ITEM_KEYS
from .compress import ZLIB, ZLIB_legacy, ObfuscateSize
from .helpers import HardLinkManager
from .item import Item
from .logger import create_logger

logger = create_logger(__name__)


class UpgraderNoOp:
    def __init__(self, *, cache):
        pass

    def new_archive(self, *, archive):
        pass

    def upgrade_item(self, *, item):
        return item

    def upgrade_compressed_chunk(self, *, chunk):
        return chunk

    def upgrade_archive_metadata(self, *, metadata):
        new_metadata = {}
        # keep all metadata except archive version and stats.
        for attr in (
            "cmdline",
            "hostname",
            "username",
            "time",
            "time_end",
            "comment",
            "chunker_params",
            "recreate_cmdline",
        ):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        return new_metadata


class UpgraderFrom12To20:
    def __init__(self, *, cache):
        self.cache = cache

    def new_archive(self, *, archive):
        self.archive = archive
        self.hlm = HardLinkManager(id_type=bytes, info_type=tuple)  # hlid -> (chunks, chunks_healthy)

    def upgrade_item(self, *, item):
        """upgrade item as needed, get rid of legacy crap"""
        ITEM_KEY_WHITELIST = {
            "path",
            "source",
            "rdev",
            "chunks",
            "chunks_healthy",
            "hlid",
            "mode",
            "user",
            "group",
            "uid",
            "gid",
            "mtime",
            "atime",
            "ctime",
            "birthtime",
            "size",
            "xattrs",
            "bsdflags",
            "acl_nfs4",
            "acl_access",
            "acl_default",
            "acl_extended",
            "part",
        }

        if self.hlm.borg1_hardlink_master(item):
            item._dict["hlid"] = hlid = self.hlm.hardlink_id_from_path(item._dict["path"])
            self.hlm.remember(id=hlid, info=(item._dict.get("chunks"), item._dict.get("chunks_healthy")))
        elif self.hlm.borg1_hardlink_slave(item):
            item._dict["hlid"] = hlid = self.hlm.hardlink_id_from_path(item._dict["source"])
            chunks, chunks_healthy = self.hlm.retrieve(id=hlid, default=(None, None))
            if chunks is not None:
                item._dict["chunks"] = chunks
                for chunk_id, _ in chunks:
                    self.cache.chunk_incref(chunk_id, self.archive.stats)
            if chunks_healthy is not None:
                item._dict["chunks_healthy"] = chunks
            item._dict.pop("source")  # not used for hardlinks any more, replaced by hlid
        # make sure we only have desired stuff in the new item. specifically, make sure to get rid of:
        # - 'acl' remnants of bug in attic <= 0.13
        # - 'hardlink_master' (superseded by hlid)
        new_item_dict = {key: value for key, value in item.as_dict().items() if key in ITEM_KEY_WHITELIST}
        new_item = Item(internal_dict=new_item_dict)
        new_item.get_size(memorize=True)  # if not already present: compute+remember size for items with chunks
        assert all(key in new_item for key in REQUIRED_ITEM_KEYS)
        return new_item

    def upgrade_compressed_chunk(self, *, chunk):
        def upgrade_zlib_and_level(chunk):
            if ZLIB_legacy.detect(chunk):
                ctype = ZLIB.ID
                chunk = ctype + level + bytes(chunk)  # get rid of the legacy: prepend separate type/level bytes
            else:
                ctype = bytes(chunk[0:1])
                chunk = ctype + level + bytes(chunk[2:])  # keep type same, but set level
            return chunk

        ctype = chunk[0:1]
        level = b"\xFF"  # FF means unknown compression level

        if ctype == ObfuscateSize.ID:
            # in older borg, we used unusual byte order
            old_header_fmt = Struct(">I")
            new_header_fmt = ObfuscateSize.header_fmt
            length = ObfuscateSize.header_len
            size_bytes = chunk[2 : 2 + length]
            size = old_header_fmt.unpack(size_bytes)
            size_bytes = new_header_fmt.pack(size)
            compressed = chunk[2 + length :]
            compressed = upgrade_zlib_and_level(compressed)
            chunk = ctype + level + size_bytes + compressed
        else:
            chunk = upgrade_zlib_and_level(chunk)
        return chunk

    def upgrade_archive_metadata(self, *, metadata):
        new_metadata = {}
        # keep all metadata except archive version and stats. also do not keep
        # recreate_source_id, recreate_args, recreate_partial_chunks which were used only in 1.1.0b1 .. b2.
        for attr in (
            "cmdline",
            "hostname",
            "username",
            "time",
            "time_end",
            "comment",
            "chunker_params",
            "recreate_cmdline",
        ):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        return new_metadata
