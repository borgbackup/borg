import argparse
from ._common import with_repository, Highlander
from ..archive import ArchiveChecker
from ..constants import *  # NOQA
from ..helpers import set_ec, EXIT_WARNING, CancelledByUser, CommandError, IntegrityError
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
                raise CancelledByUser()
        if args.repo_only and any((args.verify_data, args.first, args.last, args.match_archives)):
            raise CommandError(
                "--repository-only contradicts --first, --last, -a / --match-archives and --verify-data arguments."
            )
        if args.repo_only and args.find_lost_archives:
            raise CommandError("--repository-only contradicts the --find-lost-archives option.")
        if args.repair and args.max_duration:
            raise CommandError("--repair does not allow --max-duration argument.")
        if args.max_duration and not args.repo_only:
            # when doing a partial repo check, we can only check xxh64 hashes in repository files.
            # archives check requires that a full repo check was done before and has built/cached a ChunkIndex.
            # also, there is no max_duration support in the archives check code anyway.
            raise CommandError("--repository-only is required for --max-duration support.")
        if not args.repo_only:
            # if we need the key later for the archives check, ask NOW for the passphrase! #1931
            archive_checker = ArchiveChecker()
            try:
                archive_checker.key = archive_checker.make_key(repository, manifest_only=True)
            except IntegrityError:
                pass  # will try to make key later again
        if not args.archives_only:
            if not repository.check(repair=args.repair, max_duration=args.max_duration):
                set_ec(EXIT_WARNING)
        if not args.repo_only and not archive_checker.check(
            repository,
            verify_data=args.verify_data,
            repair=args.repair,
            find_lost_archives=args.find_lost_archives,
            match=args.match_archives,
            sort_by=args.sort_by or "ts",
            first=args.first,
            last=args.last,
            older=args.older,
            newer=args.newer,
            oldest=args.oldest,
            newest=args.newest,
        ):
            set_ec(EXIT_WARNING)
            return

    def build_parser_check(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_archive_filters_group

        check_epilog = process_epilog(
            """
        The check command verifies the consistency of a repository and its archives.
        It consists of two major steps:

        1. Checking the consistency of the repository itself. This includes checking
           the file magic headers, and both the metadata and data of all objects in
           the repository. The read data is checked by size and hash. Bit rot and other
           types of accidental damage can be detected this way. Running the repository
           check can be split into multiple partial checks using ``--max-duration``.
           When checking a ssh:// remote repository, please note that the checks run on
           the server and do not cause significant network traffic.

        2. Checking consistency and correctness of the archive metadata and optionally
           archive data (requires ``--verify-data``). This includes ensuring that the
           repository manifest exists, the archive metadata chunk is present, and that
           all chunks referencing files (items) in the archive exist. This requires
           reading archive and file metadata, but not data. To scan for archives whose
           entries were lost from the archive directory, pass ``--find-lost-archives``.
           It requires reading all data and is hence very time consuming.
           To additionally cryptographically verify the file (content) data integrity,
           pass ``--verify-data``, which is even more time consuming.

           When checking archives of a remote repository, archive checks run on the client
           machine because they require decrypting data and therefore the encryption key.

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
        restart from the beginning. With partial repository checks you can run neither
        archive checks, nor enable repair mode. Consequently, if you want to use
        ``--max-duration`` you must also pass ``--repository-only``, and must not pass
        ``--archives-only``, nor ``--repair``.

        **Warning:** Please note that partial repository checks (i.e. running it with
        ``--max-duration``) can only perform non-cryptographic checksum checks on the
        repository files. Enabling partial repository checks excepts archive checks
        for the same reason. Therefore partial checks may be useful with very large
        repositories only where a full check would take too long.

        The ``--verify-data`` option will perform a full integrity verification (as
        opposed to checking just the xxh64) of data, which means reading the
        data from the repository, decrypting and decompressing it. It is a complete
        cryptographic verification and hence very time consuming, but will detect any
        accidental and malicious corruption. Tamper-resistance is only guaranteed for
        encrypted repositories against attackers without access to the keys. You can
        not use ``--verify-data`` with ``--repository-only``.

        The ``--find-lost-archives`` option will also scan the whole repository, but
        tells Borg to search for lost archive metadata. If Borg encounters any archive
        metadata that doesn't match with an archive directory entry (including
        soft-deleted archives), it means that an entry was lost.
        Unless ``borg compact`` is called, these archives can be fully restored with
        ``--repair``. Please note that ``--find-lost-archives`` must read a lot of
        data from the repository and is thus very time consuming. You can not use
        ``--find-lost-archives`` with ``--repository-only``.

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
        by definition, a potentially lossy task.

        In practice, repair mode hooks into both the repository and archive checks:

        1. When checking the repository's consistency, repair mode removes corrupted
           objects from the repository after it did a 2nd try to read them correctly.

        2. When checking the consistency and correctness of archives, repair mode might
           remove whole archives from the manifest if their archive metadata chunk is
           corrupt or lost. Borg will also report files that reference missing chunks.

        If ``--repair --find-lost-archives`` is given, previously lost entries will
        be recreated in the archive directory. This is only possible before
        ``borg compact`` would remove the archives' data completely.
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
            "--find-lost-archives", dest="find_lost_archives", action="store_true", help="attempt to find lost archives"
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
