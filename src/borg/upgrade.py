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
            "start",
            "end",
            "comment",
            "chunker_params",
            "recreate_command_line",
        ):
            if hasattr(metadata, attr):
                new_metadata[attr] = getattr(metadata, attr)
        new_metadata["cwd"] = getattr(metadata, "cwd", None)  # None signals save() to leave cwd unset
        rechunking = self.args.chunker_params is not None
        if rechunking:
            # if we are rechunking while transferring, we take the new chunker_params.
            new_metadata["chunker_params"] = self.args.chunker_params
        return new_metadata
