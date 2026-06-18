import os
from datetime import datetime, timezone

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import set_ec, Error, json_print
from ..helpers.time import parse_timestamp
from ..crypto.low_level import IntegrityError
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest
from .. import monitoring
from ..crypto import monitoring as mon_crypto

from ..logger import create_logger

logger = create_logger()

# Default freshness window: alert if the newest report is older than this (slightly over
# a day, to tolerate a late daily backup). Override with --max-age.
DEFAULT_MAX_AGE = 25 * 3600


class MonitorMixIn:
    @with_repository(manifest=False)
    def do_monitor(self, args, repository):
        """Read or export trusted monitoring state of a repository.

        Without arguments this reads the monitoring reports that backup-side commands
        published into the repository, verifies and decrypts them using the key from the
        BORG_MONITORING_KEY environment variable, and reports - per archive series (and per
        maintenance command) - the latest status and freshness. Because each series is
        reported independently, a later successful backup of one series does not mask an
        earlier failed backup of another. Restrict the output with --name (one archive
        series) or --command (e.g. create or prune). Neither the repository passphrase nor
        the borg key is needed for reading.

        Reports accumulate over time; --keep=N deletes all but the N newest after reading.

        With --key (which does need the borg key), it derives and prints the
        BORG_MONITORING_KEY value for this repository, to be configured on the monitoring
        host. The printed value only allows verifying and decrypting reports, not creating
        them.
        """
        if args.key:
            return self._monitor_export_key(repository)
        return self._monitor_read(args, repository)

    def _monitor_export_key(self, repository):
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        if not mon_crypto.is_signed_repo(manifest.key):
            raise Error(
                "This repository is unencrypted; monitoring reports are not signed, so there is no monitoring key."
            )
        print(mon_crypto.export_monitor_key(manifest.key))

    def _monitor_read(self, args, repository):
        key_str = os.environ.get("BORG_MONITORING_KEY")
        try:
            monitor_key = mon_crypto.parse_monitor_key(key_str) if key_str else None
        except ValueError as e:
            raise Error(f"Invalid BORG_MONITORING_KEY: {e}")

        try:
            reports = list(monitoring.iter_reports(repository, monitor_key))
        except IntegrityError as e:
            raise Error(f"Monitoring report verification/decryption failed (wrong key or tampered): {e}")
        except ValueError as e:
            raise Error(str(e))

        # Cleanup is best-effort and must not change the read result, so do it after reading.
        monitoring.prune_reports(repository, args.keep)

        now = datetime.now(timezone.utc)

        # Reports are oldest-first, so the last one written per "unit" (archive series for
        # create, else the command) wins - giving each unit its latest status independently,
        # so a later successful series cannot mask an earlier failed one.
        latest = {}
        for report, trusted in reports:
            if args.command and report.get("command") != args.command:
                continue
            if args.name and report.get("archive") != args.name:
                continue
            unit = report.get("archive") or report.get("command")
            latest[unit] = (report, trusted)

        entries = []
        for unit in sorted(latest):
            report, trusted = latest[unit]
            age = (now - parse_timestamp(report["time"])).total_seconds()
            stale = age > args.max_age
            entries.append((unit, report, trusted, age, stale))

        self._monitor_output(args, entries)

        if not entries:
            set_ec(EXIT_ERROR)  # nothing matched -> dead man's switch fires
            return
        # Exit code drives external alerting: worst unit wins (stale/error -> error,
        # warning/untrusted -> warning).
        for _, report, trusted, _, stale in entries:
            if stale or report.get("status") == "error":
                set_ec(EXIT_ERROR)
            elif report.get("status") == "warning" or not trusted:
                set_ec(EXIT_WARNING)

    def _monitor_output(self, args, entries):
        if args.json:
            out = {
                "max_age_seconds": args.max_age,
                "entries": [
                    {"unit": unit, "trusted": trusted, "stale": stale, "age_seconds": age, "report": report}
                    for unit, report, trusted, age, stale in entries
                ],
            }
            json_print(out)
            return
        if not entries:
            scope = ""
            if args.name:
                scope = f" for archive '{args.name}'"
            elif args.command:
                scope = f" for command '{args.command}'"
            print(f"No monitoring report found{scope}.")
            return
        for unit, report, trusted, age, stale in entries:
            print(f"{unit}:")
            print(f"    command:    {report.get('command')}")
            print(f"    status:     {report.get('status')} (rc {report.get('rc')})")
            print(f"    archive:    {report.get('archive', '-')}")
            print(f"    time:       {report.get('time')}")
            print(f"    age:        {int(age)}s (max {args.max_age}s){'  STALE' if stale else ''}")
            print(f"    trusted:    {trusted}{'' if trusted else '  (unsigned - repo is unencrypted)'}")

    def build_parser_monitor(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        monitor_epilog = process_epilog(
            """
        Read trusted monitoring state of a repository.

        Borg client commands publish a signed-and-encrypted state report into the
        repository after each run. Only borg monitor can read these reports using
        the monitoring key.

        Setup (once, on a host that has the borg key)::

            borg monitor --key  # this outputs the monitoring key

        Then, on the monitoring host::

            BORG_MONITORING_KEY=<that key> borg monitor

        This verifies and decrypts the reports and prints, per archive series (and per
        maintenance command), the latest status and its age. It exits with a non-zero code
        (warning or error) if any series is missing, stale (older than --max-age), unsigned,
        or did not indicate success - so it can drive alerting like a dead man's switch.
        Reports accumulate over time; --keep=N (default 500) deletes all but the N newest
        after reading.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_monitor.__doc__, epilog=monitor_epilog)
        subparsers.add_subcommand("monitor", subparser, help="read/export repository monitoring state")
        subparser.add_argument(
            "--key",
            dest="key",
            action="store_true",
            help="derive and print BORG_MONITORING_KEY for this repository (needs the borg key)",
        )
        subparser.add_argument(
            "--name",
            dest="name",
            default=None,
            metavar="SERIES",
            help="only report on the given archive series (e.g. the name used with borg create)",
        )
        subparser.add_argument(
            "--command",
            dest="command",
            default=None,
            metavar="COMMAND",
            help="only report on the given command, e.g. create or prune (default: all commands)",
        )
        subparser.add_argument(
            "--max-age",
            dest="max_age",
            type=int,
            default=DEFAULT_MAX_AGE,
            metavar="SECONDS",
            help=f"freshness window in seconds; older reports count as stale (default: {DEFAULT_MAX_AGE})",
        )
        subparser.add_argument(
            "--keep",
            dest="keep",
            type=int,
            default=monitoring.DEFAULT_KEEP,
            metavar="N",
            help="after reading, delete all but the N newest report objects "
            f"(0 = do not clean up; default: {monitoring.DEFAULT_KEEP})",
        )
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
