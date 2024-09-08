import argparse

from ._common import with_repository
from ..cache import Cache, SecurityManager
from ..constants import *  # NOQA
from ..helpers import CancelledByUser
from ..helpers import format_archive
from ..helpers import bin_to_hex
from ..helpers import yes
from ..manifest import Manifest, NoManifestError

from ..logger import create_logger

logger = create_logger()


class RepoDeleteMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_repo_delete(self, args, repository):
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
                    manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
                    n_archives = manifest.archives.count()
                    msg.append(
                        f"You requested to DELETE the following repository completely "
                        f"*including* {n_archives} archives it contains:"
                    )
                except NoManifestError:
                    n_archives = None
                    msg.append(
                        "You requested to DELETE the following repository completely "
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
                            msg.append("This repository seems not to have any archives.")
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
                    raise CancelledByUser()
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

    def build_parser_repo_delete(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_delete_epilog = process_epilog(
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
            "repo-delete",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_delete.__doc__,
            epilog=repo_delete_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="delete repository",
        )
        subparser.set_defaults(func=self.do_repo_delete)
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
