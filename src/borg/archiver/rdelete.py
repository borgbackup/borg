import argparse

from .common import with_repository
from ..cache import Cache, SecurityManager
from ..constants import *  # NOQA
from ..helpers import EXIT_ERROR
from ..helpers import NoManifestError
from ..helpers import format_archive
from ..helpers import bin_to_hex
from ..helpers import Manifest
from ..helpers import yes

from ..logger import create_logger

logger = create_logger()


class RDeleteMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_rdelete(self, args, repository):
        """Delete a repository"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        keep_security_info = args.keep_security_info

        if not args.cache_only:
            if args.forced == 0:  # without --force, we let the user see the archives list and confirm.
                id = bin_to_hex(repository.id)
                location = repository._location.canonical_path()
                msg = []
                try:
                    manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
                    n_archives = len(manifest.archives)
                    msg.append(
                        f"You requested to completely DELETE the following repository "
                        f"*including* {n_archives} archives it contains:"
                    )
                except NoManifestError:
                    n_archives = None
                    msg.append(
                        "You requested to completely DELETE the following repository "
                        "*including* all archives it may contain:"
                    )

                msg.append(DASHES)
                msg.append(f"Repository ID: {id}")
                msg.append(f"Location: {location}")

                if self.output_list:
                    msg.append("")
                    msg.append("Archives:")

                    if n_archives is not None:
                        if n_archives > 0:
                            for archive_info in manifest.archives.list(sort_by=["ts"]):
                                msg.append(format_archive(archive_info))
                        else:
                            msg.append("This repository seems to not have any archives.")
                    else:
                        msg.append(
                            "This repository seems to have no manifest, so we can't "
                            "tell anything about its contents."
                        )

                msg.append(DASHES)
                msg.append("Type 'YES' if you understand this and want to continue: ")
                msg = "\n".join(msg)
                if not yes(
                    msg,
                    false_msg="Aborting.",
                    invalid_msg="Invalid answer, aborting.",
                    truish=("YES",),
                    retry=False,
                    env_var_override="BORG_DELETE_I_KNOW_WHAT_I_AM_DOING",
                ):
                    self.exit_code = EXIT_ERROR
                    return self.exit_code
            if not dry_run:
                repository.destroy()
                logger.info("Repository deleted.")
                if not keep_security_info:
                    SecurityManager.destroy(repository)
            else:
                logger.info("Would delete repository.")
                logger.info("Would %s security info." % ("keep" if keep_security_info else "delete"))
        if not dry_run:
            Cache.destroy(repository)
            logger.info("Cache deleted.")
        else:
            logger.info("Would delete cache.")
        return self.exit_code

    def build_parser_rdelete(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

        rdelete_epilog = process_epilog(
            """
        This command deletes the complete repository.

        When you delete a complete repository, the security info and local cache for it
        (if any) are also deleted. Alternatively, you can delete just the local cache
        with the ``--cache-only`` option, or keep the security info with the
        ``--keep-security-info`` option.

        Always first use ``--dry-run --list`` to see what would be deleted.
        """
        )
        subparser = subparsers.add_parser(
            "rdelete",
            parents=[common_parser],
            add_help=False,
            description=self.do_rdelete.__doc__,
            epilog=rdelete_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="delete repository",
        )
        subparser.set_defaults(func=self.do_rdelete)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository")
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives"
        )
        subparser.add_argument(
            "--force",
            dest="forced",
            action="count",
            default=0,
            help="force deletion of corrupted archives, " "use ``--force --force`` in case ``--force`` does not work.",
        )
        subparser.add_argument(
            "--cache-only",
            dest="cache_only",
            action="store_true",
            help="delete only the local cache for the given repository",
        )
        subparser.add_argument(
            "--keep-security-info",
            dest="keep_security_info",
            action="store_true",
            help="keep the local security info when deleting a repository",
        )
