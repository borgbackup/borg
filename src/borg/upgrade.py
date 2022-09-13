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

    def upgrade_compressed_chunk(self, meta, data):
        return meta, data

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

    def upgrade_compressed_chunk(self, meta, data):
        # meta/data was parsed via RepoObj1.parse, which returns data **including** the ctype/clevel bytes prefixed
        def upgrade_zlib_and_level(meta, data):
            if ZLIB_legacy.detect(data):
                ctype = ZLIB.ID
                data = bytes(data)  # ZLIB_legacy has no ctype/clevel prefix
            else:
                ctype = data[0]
                data = bytes(data[2:])  # strip ctype/clevel bytes
            meta["ctype"] = ctype
            meta["clevel"] = level
            meta["csize"] = len(data)  # we may have stripped some prefixed ctype/clevel bytes
            return meta, data

        ctype = data[0]
        level = 0xFF  # means unknown compression level

        if ctype == ObfuscateSize.ID:
            # in older borg, we used unusual byte order
            borg1_header_fmt = Struct(">I")
            hlen = borg1_header_fmt.size
            csize_bytes = data[2 : 2 + hlen]
            csize = borg1_header_fmt.unpack(csize_bytes)
            compressed = data[2 + hlen : 2 + hlen + csize]
            meta, compressed = upgrade_zlib_and_level(meta, compressed)
            meta["psize"] = csize
            osize = len(data) - 2 - hlen - csize  # amount of 0x00 bytes appended for obfuscation
            data = compressed + bytes(osize)
            meta["csize"] = len(data)
        else:
            meta, data = upgrade_zlib_and_level(meta, data)
        return meta, data

    def upgrade_archive_metadata(self, *, metadata):
        new_metadata = {}
        # keep all metadata except archive version and stats. also do not keep
        # recreate_source_id, recreate_args, recreate_partial_chunks which were used only in 1.1.0b1 .. b2.
        for attr in ("cmdline", "hostname", "username", "comment", "chunker_params", "recreate_cmdline"):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        # old borg used UTC timestamps, but did not have the explicit tz offset in them.
        for attr in ("time", "time_end"):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr) + "+00:00"
        return new_metadata
