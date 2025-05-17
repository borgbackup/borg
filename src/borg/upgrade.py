from struct import Struct

from .constants import REQUIRED_ITEM_KEYS, CH_BUZHASH
from .compress import ZLIB, ZLIB_legacy, ObfuscateSize
from .helpers import HardLinkManager, join_cmd
from .item import Item
from .logger import create_logger

logger = create_logger(__name__)


class UpgraderNoOp:
    def __init__(self, *, cache, args):
        self.args = args

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
            "command_line",
            "hostname",
            "username",
            "time",
            "time_end",
            "comment",
            "chunker_params",
            "recreate_command_line",
        ):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        rechunking = self.args.chunker_params is not None
        if rechunking:
            # if we are rechunking while transferring, we take the new chunker_params.
            new_metadata["chunker_params"] = self.args.chunker_params
        return new_metadata


class UpgraderFrom12To20:
    borg1_header_fmt = Struct(">I")

    def __init__(self, *, cache, args):
        self.cache = cache
        self.args = args

    def new_archive(self, *, archive):
        self.archive = archive
        self.hlm = HardLinkManager(id_type=bytes, info_type=list)  # hlid -> chunks_correct

    def upgrade_item(self, *, item):
        """upgrade item as needed, get rid of legacy crap"""
        ITEM_KEY_WHITELIST = {
            "path",
            "rdev",
            "chunks",
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
        }

        if self.hlm.borg1_hardlink_master(item):
            item.hlid = hlid = self.hlm.hardlink_id_from_path(item.path)
            self.hlm.remember(id=hlid, info=item.get("chunks"))
        elif self.hlm.borg1_hardlink_slave(item):
            item.hlid = hlid = self.hlm.hardlink_id_from_path(item.source)
            chunks = self.hlm.retrieve(id=hlid)
            if chunks is not None:
                item.chunks = chunks
                for chunk_id, chunk_size in chunks:
                    self.cache.reuse_chunk(chunk_id, chunk_size, self.archive.stats)
            del item.source  # not used for hardlinks any more, replaced by hlid
        # make sure we only have desired stuff in the new item. specifically, make sure to get rid of:
        # - 'acl' remnants of bug in attic <= 0.13
        # - 'hardlink_master' (superseded by hlid)
        item_dict = item.as_dict()
        new_item_dict = {key: value for key, value in item_dict.items() if key in ITEM_KEY_WHITELIST}
        # symlink targets were .source for borg1, but borg2 uses .target:
        if "source" in item_dict:
            new_item_dict["target"] = item_dict["source"]
        assert "source" not in new_item_dict
        # remove some pointless entries older borg put in there:
        for key in "user", "group":
            if key in new_item_dict and new_item_dict[key] is None:
                del new_item_dict[key]
        assert not any(value is None for value in new_item_dict.values()), f"found None value in {new_item_dict}"
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
            hlen = self.borg1_header_fmt.size
            csize_bytes = data[2 : 2 + hlen]
            csize = self.borg1_header_fmt.unpack(csize_bytes)[0]
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
        for attr in ("hostname", "username", "comment", "chunker_params"):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        rechunking = self.args.chunker_params is not None
        if rechunking:
            # if we are rechunking while transferring, we take the new chunker_params.
            new_metadata["chunker_params"] = self.args.chunker_params
        else:
            if chunker_params := new_metadata.get("chunker_params"):
                if len(chunker_params) == 4 and isinstance(chunker_params[0], int):
                    # this is a borg < 1.2 chunker_params tuple, no chunker algo specified, but we only had buzhash:
                    new_metadata["chunker_params"] = (CH_BUZHASH,) + chunker_params
        # old borg used UTC timestamps, but did not have the explicit tz offset in them.
        for attr in ("time", "time_end"):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr) + "+00:00"
        # borg 1: cmdline, recreate_cmdline: a copy of sys.argv
        # borg 2: command_line, recreate_command_line: a single string
        if hasattr(metadata, "cmdline"):
            new_metadata["command_line"] = join_cmd(getattr(metadata, "cmdline"))
        if hasattr(metadata, "recreate_cmdline"):
            new_metadata["recreate_command_line"] = join_cmd(getattr(metadata, "recreate_cmdline"))
        new_metadata["tags"] = []
        return new_metadata
