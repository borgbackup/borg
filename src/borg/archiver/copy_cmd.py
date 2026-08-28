from ._common import with_repository, with_archive
from ..constants import *  # NOQA
from ..helpers import archivename_validator, bin_to_hex
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class CopyMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.CHECK,))
    @with_archive
    def do_copy(self, args, repository, manifest, cache, archive):
        """Copy an archive to a new archive name."""
        old_id = archive.id
        archive.copy(args.newname)
        manifest.write()
        logger.info(f"id: {bin_to_hex(old_id):.8} -> {bin_to_hex(archive.id):.8}, name: {archive.name}.")

    def build_parser_copy(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        copy_epilog = process_epilog(
            """
        This command copies an existing archive to a new archive with a different name,
        keeping the existing archive.

        Afterwards, the repository has two archives with the same contents, but with
        different names and different archive IDs. The copy is an independent archive:
        deleting either of the two archives keeps the other one intact, because
        ``borg compact`` only frees chunks that no remaining archive references.

        Copying is cheap and fast: no file content is read or written, only a new archive
        metadata object is created. Like any deduplicated archives, the two archives share
        their data, so a copy needs almost no additional repository space.

        Because archive names do not need to be unique, NEWNAME may also be the name of
        some *other* already existing archive - the copy then just becomes another archive
        of that archive series.

        NEWNAME must be different from the name of the archive that is copied, though: the
        copy would get identical metadata and thus the same archive ID as its source, so no
        second archive could be created.

        OLDNAME must match precisely one archive: give an archive name (if it is unique) or
        an archive ID, like ``aid:d34db33f``.

        Note: to copy archives into a *different* repository, use ``borg transfer``.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_copy.__doc__, epilog=copy_epilog)
        subparsers.add_subcommand("copy", subparser, help="copy an archive to a new archive name")
        subparser.add_argument(
            "name", metavar="OLDNAME", type=archivename_validator, help="specify the existing archive name or ID"
        )
        subparser.add_argument(
            "newname", metavar="NEWNAME", type=archivename_validator, help="specify the new archive name"
        )
