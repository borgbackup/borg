import argparse
from ._common import with_repository, Highlander
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
        if args.repo_only and any((args.verify_data, args.first, args.last, args.match_archives)):
            self.print_error(
                "--repository-only contradicts --first, --last, -a / --match-archives and --verify-data arguments."
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
            if not repository.check(repair=args.repair, max_duration=args.max_duration):
                return EXIT_WARNING
        if not args.repo_only and not ArchiveChecker().check(
            repository,
            verify_data=args.verify_data,
            repair=args.repair,
            match=args.match_archives,
            sort_by=args.sort_by or "ts",
            first=args.first,
            last=args.last,
            older=args.older,
            newer=args.newer,
            oldest=args.oldest,
            newest=args.newest,
        ):
            return EXIT_WARNING
        return EXIT_SUCCESS

    def build_parser_check(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_archive_filters_group

        check_epilog = process_epilog(
            """
        The check command verifies the consistency of a repository and its archives.
        It consists of two major steps:

        1. Checking the consistency of the repository itself. This includes checking
           the segment magic headers, and both the metadata and data of all objects in
           the segments. The read data is checked by size and CRC. Bit rot and other
           types of accidental damage can be detected this way. Running the repository
           check can be split into multiple partial checks using ``--max-duration``.
           When checking a remote repository, please note that the checks run on the
           server and do not cause significant network traffic.

        2. Checking consistency and correctness of the archive metadata and optionally
           archive data (requires ``--verify-data`). This includes ensuring that the
           repository manifest exists, the archive metadata chunk is present, and that
           all chunks referencing files (items) in the archive exist. This requires
           reading archive and file metadata, but not data. To verify the cryptographic
           archive data integrity pass ``--verify-data`, but keep in mind that this
           requires reading all data and is hence very time consuming. When checking
           archives of a remote repository, archive checks run on the client machine
           because they require decrypting data and therefore the encryption key.

        Both steps can also be run independently. Pass ``--repository-only`` to run the
        repository checks only, or pass ``--archives-only`` to run the archive checks
        only.

        The ``--max-duration`` option can be used to split a long-running repository
        check into multiple partial checks. After the given number of seconds the check
        is interrupted. The next partial check will continue where the previous one
        stopped, until the full repository has been checked. Assuming a complete check
        would take 7 hours, then running a daily check with ``--max-duration=3600``
        (1 hour) would result in one full repository check per week. Doing a full
        repository check aborts any previous partial check; the next partial check will
        restart from the beginning. You can use ``--max-duration`` with neither
        ``--repair``, nor ``--archives-only``.

        **Warning:** Please note that partial repository checks (i.e. running it with
        ``--max-duration``) can only perform non-cryptographic checksum checks on the
        segment files. A full repository check (i.e. without ``--max-duration``) can
        also do a repository index check. Even though this is often no issue, partial
        checks may therefore be useful only with very large repositories where a full
        check would take too long.

        The ``--verify-data`` option will perform a full integrity verification (as
        opposed to checking the CRC32 of the segment) of data, which means reading the
        data from the repository, decrypting and decompressing it. It is a complete
        cryptographic verification and hence very time consuming, but will detect any
        accidental and malicious corruption. Tamper-resistance is only gauranteed for
        encrypted repositories against attackers without access to the keys. You can
        not use ``--verify-data`` with ``--repository-only``.

        About repair mode
        +++++++++++++++++

        The check command is a readonly task by default. If any corruption is found,
        Borg will report the issue and proceed with checking. To actually repair the
        issues found, pass ``--repair``.

        .. note::

            ``--repair`` is a **POTENTIALLY DANGEROUS FEATURE** and might lead to data
            loss! This does not just include data that was previously lost anyway, but
            might include more data for kinds of corruption it is not capable of
            dealing with. **BE VERY CAREFUL!**

        Pursuant to the previous warning it is also highly recommended to test the
        reliability of the hardware running Borg with stress testing software. This
        especially includes storage and memory testers. Unreliable hardware might lead
        to additional data loss.

        It is highly recommended to create a backup of your repository before running
        in repair mode (i.e. running it with ``--repair``).

        Repair mode will attempt to fix any corruptions found. Fixing corruptions does
        not mean recovering lost data: Borg can not magically restore data lost due to
        e.g. a hardware failure. Repairing a repository means sacrificing some data
        for the sake of the repository as a whole and the remaining data. Hence it is,
        by definition, a lossy task.

        In practice, repair mode hooks into both the repository and archive checks:

        1. When checking the repository's consistency, repair mode will try to recover
           as many objects from segments with integrity errors as possible, and ensure
           that the index is consistent with the data stored in the segments.

        2. When checking the consistency and correctness of archives, repair mode might
           remove whole archives from the manifest if their archive metadata chunk is
           corrupt or lost. On a chunk level (i.e. the contents of files), repair mode
           will replace corrupt or lost chunks with a same-size replacement chunk of
           zeroes. If a previously zeroed chunk reappears, repair mode will restore
           this lost chunk using the new chunk. Lastly, repair mode will also delete
           orphaned chunks (e.g. caused by read errors while creating the archive).

        Most steps taken by repair mode have an onetime effect on the repository, like
        removing a lost archive from the repository. However, replacing a corrupt or
        lost chunk with a same-size all-zero replacement will have an ongoing effect on
        the repository: When attempting to extract a file referencing an all-zero
        chunk, the ``extract`` command will distinctly warn about it. The ``mount``
        command will reject reading such a "zero-patched" file unless a special mount
        option is given.

        This ongoing effect of all-zero replacement chunks has a big advantage: If a
        previously lost chunk reappears (e.g. via a later backup), repair mode might
        "heal" some of these "zero-patched" files and restore some of the previously
        lost data. However, this "healing process" can only happen in repair mode.
        Thus it is advised to run ``--repair`` a second time after creating some new
        backups.

        Technical description
        +++++++++++++++++++++

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
          are documented above.
        - If checking a remote repo via ``ssh:``, the archive check is executed on the
          client machine because it requires decryption, and this is always done client-side
          as key access is needed.
        - The archive checks can be time consuming; they can be skipped using the
          ``--repository-only`` option.
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
            "--max-duration",
            metavar="SECONDS",
            dest="max_duration",
            type=int,
            default=0,
            action=Highlander,
            help="do only a partial repo check for max. SECONDS seconds (Default: unlimited)",
        )
        define_archive_filters_group(subparser)
