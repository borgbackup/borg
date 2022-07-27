import argparse
from .common import with_repository
from ..archive import ArchiveChecker
from ..constants import *  # NOQA
from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from ..helpers import yes

from ..logger import create_logger

logger = create_logger()


class CheckMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_check(self, args, repository):
        """Check repository consistency"""
        if args.repair:
            msg = (
                "This is a potentially dangerous function.\n"
                "check --repair might lead to data loss (for kinds of corruption it is not\n"
                "capable of dealing with). BE VERY CAREFUL!\n"
                "\n"
                "Type 'YES' if you understand this and want to continue: "
            )
            if not yes(
                msg,
                false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                truish=("YES",),
                retry=False,
                env_var_override="BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
            ):
                return EXIT_ERROR
        if args.repo_only and any((args.verify_data, args.first, args.last, args.glob_archives)):
            self.print_error(
                "--repository-only contradicts --first, --last, -a / --glob-archives " " and --verify-data arguments."
            )
            return EXIT_ERROR
        if args.repair and args.max_duration:
            self.print_error("--repair does not allow --max-duration argument.")
            return EXIT_ERROR
        if args.max_duration and not args.repo_only:
            # when doing a partial repo check, we can only check crc32 checksums in segment files,
            # we can't build a fresh repo index in memory to verify the on-disk index against it.
            # thus, we should not do an archives check based on a unknown-quality on-disk repo index.
            # also, there is no max_duration support in the archives check code anyway.
            self.print_error("--repository-only is required for --max-duration support.")
            return EXIT_ERROR
        if not args.archives_only:
            if not repository.check(repair=args.repair, save_space=args.save_space, max_duration=args.max_duration):
                return EXIT_WARNING
        if not args.repo_only and not ArchiveChecker().check(
            repository,
            repair=args.repair,
            first=args.first,
            last=args.last,
            sort_by=args.sort_by or "ts",
            glob=args.glob_archives,
            verify_data=args.verify_data,
            save_space=args.save_space,
        ):
            return EXIT_WARNING
        return EXIT_SUCCESS

    def build_parser_check(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog
        from .common import define_archive_filters_group

        check_epilog = process_epilog(
            """
        The check command verifies the consistency of a repository and the corresponding archives.

        check --repair is a potentially dangerous function and might lead to data loss
        (for kinds of corruption it is not capable of dealing with). BE VERY CAREFUL!

        Pursuant to the previous warning it is also highly recommended to test the
        reliability of the hardware running this software with stress testing software
        such as memory testers. Unreliable hardware can also lead to data loss especially
        when this command is run in repair mode.

        First, the underlying repository data files are checked:

        - For all segments, the segment magic header is checked.
        - For all objects stored in the segments, all metadata (e.g. CRC and size) and
          all data is read. The read data is checked by size and CRC. Bit rot and other
          types of accidental damage can be detected this way.
        - In repair mode, if an integrity error is detected in a segment, try to recover
          as many objects from the segment as possible.
        - In repair mode, make sure that the index is consistent with the data stored in
          the segments.
        - If checking a remote repo via ``ssh:``, the repo check is executed on the server
          without causing significant network traffic.
        - The repository check can be skipped using the ``--archives-only`` option.
        - A repository check can be time consuming. Partial checks are possible with the
          ``--max-duration`` option.

        Second, the consistency and correctness of the archive metadata is verified:

        - Is the repo manifest present? If not, it is rebuilt from archive metadata
          chunks (this requires reading and decrypting of all metadata and data).
        - Check if archive metadata chunk is present; if not, remove archive from manifest.
        - For all files (items) in the archive, for all chunks referenced by these
          files, check if chunk is present. In repair mode, if a chunk is not present,
          replace it with a same-size replacement chunk of zeroes. If a previously lost
          chunk reappears (e.g. via a later backup), in repair mode the all-zero replacement
          chunk will be replaced by the correct chunk. This requires reading of archive and
          file metadata, but not data.
        - In repair mode, when all the archives were checked, orphaned chunks are deleted
          from the repo. One cause of orphaned chunks are input file related errors (like
          read errors) in the archive creation process.
        - In verify-data mode, a complete cryptographic verification of the archive data
          integrity is performed. This conflicts with ``--repository-only`` as this mode
          only makes sense if the archive checks are enabled. The full details of this mode
          are documented below.
        - If checking a remote repo via ``ssh:``, the archive check is executed on the
          client machine because it requires decryption, and this is always done client-side
          as key access is needed.
        - The archive checks can be time consuming; they can be skipped using the
          ``--repository-only`` option.

        The ``--max-duration`` option can be used to split a long-running repository check
        into multiple partial checks. After the given number of seconds the check is
        interrupted. The next partial check will continue where the previous one stopped,
        until the complete repository has been checked. Example: Assuming a complete check took 7
        hours, then running a daily check with --max-duration=3600 (1 hour) resulted in one
        completed check per week.

        Attention: A partial --repository-only check can only do way less checking than a full
        --repository-only check: only the non-cryptographic checksum checks on segment file
        entries are done, while a full --repository-only check would also do a repo index check.
        A partial check cannot be combined with the ``--repair`` option. Partial checks
        may therefore be useful only with very large repositories where a full check would take
        too long.
        Doing a full repository check aborts a partial check; the next partial check will restart
        from the beginning.

        The ``--verify-data`` option will perform a full integrity verification (as opposed to
        checking the CRC32 of the segment) of data, which means reading the data from the
        repository, decrypting and decompressing it. This is a cryptographic verification,
        which will detect (accidental) corruption. For encrypted repositories it is
        tamper-resistant as well, unless the attacker has access to the keys. It is also very
        slow.
        """
        )
        subparser = subparsers.add_parser(
            "check",
            parents=[common_parser],
            add_help=False,
            description=self.do_check.__doc__,
            epilog=check_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="verify repository",
        )
        subparser.set_defaults(func=self.do_check)
        subparser.add_argument(
            "--repository-only", dest="repo_only", action="store_true", help="only perform repository checks"
        )
        subparser.add_argument(
            "--archives-only", dest="archives_only", action="store_true", help="only perform archives checks"
        )
        subparser.add_argument(
            "--verify-data",
            dest="verify_data",
            action="store_true",
            help="perform cryptographic archive data integrity verification " "(conflicts with ``--repository-only``)",
        )
        subparser.add_argument(
            "--repair", dest="repair", action="store_true", help="attempt to repair any inconsistencies found"
        )
        subparser.add_argument(
            "--save-space", dest="save_space", action="store_true", help="work slower, but using less space"
        )
        subparser.add_argument(
            "--max-duration",
            metavar="SECONDS",
            dest="max_duration",
            type=int,
            default=0,
            help="do only a partial repo check for max. SECONDS seconds (Default: unlimited)",
        )
        define_archive_filters_group(subparser)
