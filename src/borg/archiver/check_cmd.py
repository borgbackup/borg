import os

from ._common import with_repository, Highlander
from ..archive import ArchiveChecker
from ..constants import *  # NOQA
from ..helpers import set_ec, EXIT_WARNING, CancelledByUser, CommandError, Error, IntegrityError
from ..helpers import relative_time_marker_validator, yes, ArchiveFormatter, sig_int
from ..helpers.argparsing import ArgumentParser
from ..helpers.time import archive_ts_now, calculate_relative_offset

from ..logger import create_logger

logger = create_logger()


class CheckMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_check(self, args, repository):
        """Checks repository consistency."""
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
        if args.repo_only and any(
            (args.verify_data, args.first, args.last, args.match_archives, args.format is not None)
        ):
            raise CommandError(
                "--repository-only contradicts --first, --last, -a / --match-archives, "
                "--verify-data and --format arguments."
            )
        if args.repo_only and args.find_lost_archives:
            raise CommandError("--repository-only contradicts the --find-lost-archives option.")
        # resolve the marker (e.g. 4w, 12m) to seconds; calendar units (m, y) count from now, as for
        # --older/--newer. max_age stays 0 when --max-age is not given, which disables reuse.
        if args.max_age is not None:
            now = archive_ts_now()
            max_age = int((now - calculate_relative_offset(args.max_age, now, earlier=True)).total_seconds())
        else:
            max_age = 0
        if args.repair and args.max_duration:
            raise CommandError("--repair does not allow --max-duration argument.")
        if args.repair and args.max_age is not None:
            # repair verifies every pack; reusing recorded results during repair needs repository
            # repair (refs #8572).
            raise CommandError("--repair does not allow the --max-age option.")
        if args.archives_only and args.max_age is not None:
            # --max-age only affects the repository check; --archives-only skips it.
            raise CommandError("--archives-only does not allow the --max-age option.")
        if args.max_duration and not args.repo_only:
            # --max-duration limits only the repository check; the archives check has no max_duration
            # support.
            raise CommandError("--repository-only is required for --max-duration support.")
        if not args.repo_only:
            # if we need the key later for the archives check, ask NOW for the passphrase! #1931
            archive_checker = ArchiveChecker()
            try:
                archive_checker.key = archive_checker.make_key(repository, manifest_only=True)
            except IntegrityError:
                pass  # will try to make key later again
            if args.format is not None:
                format = args.format
            else:
                format = os.environ.get("BORG_CHECK_FORMAT", "{archive} {time} {id}")
            # check the format here, the archives check formats the first archive only after
            # the repository check has finished, which can take hours.
            ArchiveFormatter.validate_format(format)
        if not args.archives_only:
            if not repository.check(
                repair=args.repair, max_duration=args.max_duration, max_age=max_age, repo_only=args.repo_only
            ):
                set_ec(EXIT_WARNING)
            if sig_int:  # repository check interrupted; skip the archive check
                raise Error("Got Ctrl-C / SIGINT.")
        if not args.repo_only and not archive_checker.check(
            repository,
            verify_data=args.verify_data,
            repair=args.repair,
            find_lost_archives=args.find_lost_archives,
            match=args.match_archives,
            sort_by=args.sort_by or "timestamp",
            first=args.first,
            last=args.last,
            older=args.older,
            newer=args.newer,
            oldest=args.oldest,
            newest=args.newest,
            format=format,
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

        1. Checking the consistency of the repository itself. The objects in the ``index/``
           and ``packs/`` namespaces are named by the sha256 hash of their content, so such
           an object is intact if and only if the hash of its content still equals its name.
           The check verifies the (small) index objects first and, only if they are intact,
           all packs. It also cross-checks the chunk index against the packs present in the
           repository to detect referenced but missing packs. Bit rot and other types of
           accidental damage can be detected this way, but as sha256 content-addressing is
           not a MAC, this step does not detect tampering. Running the repository check can
           be split into multiple partial checks using ``--max-duration``.
           For rest:// repositories, the server computes the hashes, so the pack contents do
           not have to travel over the network. For other remote backends, borg usually has
           to read (download) the objects to hash them.

        2. Checking consistency and correctness of the archive metadata and optionally
           archive data (requires ``--verify-data``). This includes ensuring that the
           repository manifest exists, the archive metadata chunk is present, and that
           all chunks referencing files (items) in the archive exist. This requires
           reading archive and file metadata, but not data. To scan for archives whose
           entries were lost from the archive directory, pass ``--find-lost-archives``.
           It has to look at the metadata of every object in the repository (only for the
           archive metadata objects it finds that way, it also reads the object data), so
           it is very time-consuming for big repositories.
           To additionally cryptographically verify the file (content) data integrity,
           pass ``--verify-data``, which is even more time-consuming.

           When checking archives of a remote repository, archive checks run on the client
           machine because they require decrypting data and therefore the encryption key.

        Both steps can also be run independently. Pass ``--repository-only`` to run the
        repository checks only, or pass ``--archives-only`` to run the archive checks
        only.

        The ``--max-age`` option makes the check reuse the results of previous
        repository checks: packs whose intact result is younger than the given
        timespan (e.g. ``--max-age=4w`` or ``--max-age=12m``) are skipped, spreading
        the verification cost over repeated checks. The timespan uses the same markers
        as ``--older``/``--newer``: ``d``, ``w``, ``H``, ``M``, ``S`` are exact spans,
        while ``m`` and ``y`` are calendar units counted from now (so ``12m`` equals
        ``1y``). Check results are recorded in any case; ``--max-age`` only controls
        their reuse. Packs recorded corrupt are always re-verified. ``--max-age``
        affects only the repository check and cannot be combined with
        ``--archives-only`` or ``--repair``.

        The ``--max-duration`` option splits a long-running repository check into
        several partial checks. After the given number of seconds, the check is
        interrupted. A partial check verifies the least-recently-checked packs first,
        so repeated runs cover the whole repository. Add ``--max-age`` to also skip
        packs whose result is still younger than the given age: once every pack has a
        recent result, further runs re-check each pack at most once per ``--max-age``,
        and no faster than the per-run budget allows.
        Assuming a complete check would take 7 hours, running a daily check with
        ``--max-duration=3600 --max-age=1w`` (1 hour) results in one full repository
        verification per week. Partial repository checks run neither archive checks
        nor repair mode, so ``--max-duration`` requires ``--repository-only`` and
        cannot be combined with ``--archives-only`` or ``--repair``.

        **Note:** A partial repository check verifies the repository files in exactly the
        same way as a full repository check does - the difference is only how many of them
        one run gets to. What a partial run does not do are the archive checks: because
        ``--max-duration`` requires ``--repository-only``, neither the archive metadata
        checks nor the cryptographic data verification of ``--verify-data`` run. Partial
        checks are therefore mostly useful for very large repositories where a full check
        would take too long.

        The ``--verify-data`` option will perform a full integrity verification of data,
        which means reading the data from the repository, decrypting and decompressing it.
        It is a complete cryptographic verification and hence very time-consuming, but
        will detect any accidental and malicious corruption. Tamper-resistance is only
        guaranteed for encrypted repositories against attackers without access to the keys.
        You cannot use ``--verify-data`` with ``--repository-only``.

        ``--verify-data`` also always verifies that each chunk's content matches its chunk id,
        which normal reads do not do by default (see ``BORG_ASSERT_ID``). Running it periodically
        is therefore recommended.

        The ``--find-lost-archives`` option will also scan the whole repository, but
        tells Borg to search for lost archive metadata. If Borg encounters any archive
        metadata that does not match an archive directory entry (including
        soft-deleted archives), it means that an entry was lost.
        Unless ``borg compact`` is called, these archives can be fully restored with
        ``--repair``. Please note that ``--find-lost-archives`` must look at every
        object in the repository and is thus very time-consuming. You cannot use
        ``--find-lost-archives`` with ``--repository-only``.

        You can influence how the archive part of the ``Analyzing archive ...`` output is
        formatted by giving a custom format using ``--format`` (see the ``borg repo-list``
        description for more details about the format string).

        If the ``borg check`` process receives a SIGINT signal (Ctrl-C), it stops at the
        next safe boundary, leaving the repository and its chunk index in a consistent state.
        The repository check stops after the current pack; ``--verify-data`` and
        ``--find-lost-archives`` stop after the current chunk; a ``--repair`` archive check
        stops between whole archives. Results recorded before the interrupt are kept, so a later
        check does not re-verify those packs until they are due again. With ``--repair``, an
        interrupted archive check may leave some archives already repaired and others not yet
        processed, so run ``borg check --repair`` again to finish.

        During a ``--repair`` run, the archive check first rebuilds the chunk index from the
        packs, and, if the key must be recovered, scans chunks for it. These phases do not yet
        respond to SIGINT, so on a large repository a Ctrl-C during them may appear to have no
        effect until they finish.

        About repair mode
        +++++++++++++++++

        The check command is a read-only task by default. If any corruption is found,
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
        not mean recovering lost data: Borg cannot magically restore data lost due to
        e.g. a hardware failure. Repairing a repository means sacrificing some data
        for the sake of the repository as a whole and the remaining data. Hence it is,
        by definition, a potentially lossy task.

        In practice, repair mode hooks into both the repository and archive checks:

        1. When checking the repository's consistency, repair mode rebuilds the repository
           index from the packs if the index is corrupt, provided every pack is intact. If
           any pack is corrupt, the repository check leaves the index and the packs untouched
           and reports the corruption; salvaging a corrupt pack's still-intact objects is not
           implemented yet (refs #8572).

        2. When checking the consistency and correctness of archives, repair mode might
           remove whole archives from the manifest if their archive metadata chunk is
           corrupt or lost. Borg will also report files that reference missing chunks.

        If ``--repair --find-lost-archives`` is given, previously lost entries will
        be recreated in the archive directory. This is only possible before
        ``borg compact`` would remove the archives' data completely.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_check.__doc__, epilog=check_epilog)
        subparsers.add_subcommand("check", subparser, help="verify the repository")
        subparser.add_argument(
            "--repository-only", dest="repo_only", action="store_true", help="only perform repository checks"
        )
        subparser.add_argument(
            "--archives-only", dest="archives_only", action="store_true", help="only perform archive checks"
        )
        subparser.add_argument(
            "--verify-data",
            dest="verify_data",
            action="store_true",
            help="perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)",
        )
        subparser.add_argument(
            "--repair", dest="repair", action="store_true", help="attempt to repair any inconsistencies found"
        )
        subparser.add_argument(
            "--find-lost-archives", dest="find_lost_archives", action="store_true", help="attempt to find lost archives"
        )
        subparser.add_argument(
            "--max-age",
            metavar="TIMESPAN",
            dest="max_age",
            type=relative_time_marker_validator,
            default=None,
            action=Highlander,
            help="reuse intact-pack check results younger than TIMESPAN, e.g. 4w or 12m",
        )
        subparser.add_argument(
            "--max-duration",
            metavar="SECONDS",
            dest="max_duration",
            type=int,
            default=0,
            action=Highlander,
            help="perform only a partial repository check for at most SECONDS seconds (default: unlimited)",
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help="specify format for the archive part " '(default: "{archive} {time} {id}")',
        )
        define_archive_filters_group(subparser)
