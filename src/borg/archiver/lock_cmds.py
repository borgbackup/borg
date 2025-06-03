import argparse
import subprocess

from ._common import with_repository
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import prepare_subprocess_env, set_ec, CommandError, ThreadRunner

from ..logger import create_logger

logger = create_logger()


class LocksMixIn:
    @with_repository(manifest=False, exclusive=True)
    def do_with_lock(self, args, repository):
        """run a user specified command with the repository lock held"""
        # the repository lock needs to get refreshed regularly, or it will be killed as stale.
        # refreshing the lock is not part of the repository API, so we do it indirectly via repository.info.
        lock_refreshing_thread = ThreadRunner(sleep_interval=60, target=repository.info)
        lock_refreshing_thread.start()
        env = prepare_subprocess_env(system=True)
        try:
            # we exit with the return code we get from the subprocess
            rc = subprocess.call([args.command] + args.args, env=env)  # nosec B603
            set_ec(rc)
        except (FileNotFoundError, OSError, ValueError) as e:
            raise CommandError(f"Error while trying to run '{args.command}': {e}")
        finally:
            lock_refreshing_thread.terminate()

    @with_repository(lock=False, manifest=False)
    def do_break_lock(self, args, repository):
        """Break the repository lock (e.g. in case it was left by a dead borg."""
        repository.break_lock()
        Cache.break_lock(repository)

    def build_parser_locks(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        break_lock_epilog = process_epilog(
            """
        This command breaks the repository and cache locks.
        Please use carefully and only while no borg process (on any machine) is
        trying to access the Cache or the Repository.
        """
        )
        subparser = subparsers.add_parser(
            "break-lock",
            parents=[common_parser],
            add_help=False,
            description=self.do_break_lock.__doc__,
            epilog=break_lock_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="break repository and cache locks",
        )
        subparser.set_defaults(func=self.do_break_lock)

        with_lock_epilog = process_epilog(
            """
        This command runs a user-specified command while locking the repository. For example:

        ::

            $ BORG_REPO=/mnt/borgrepo borg with-lock rsync -av /mnt/borgrepo /somewhere/else/borgrepo

        It will first try to acquire the lock (make sure that no other operation is
        running in the repo), then execute the given command as a subprocess and wait
        for its termination, release the lock and return the user command's return
        code as borg's return code.

        .. note::

            If you copy a repository with the lock held, the lock will be present in
            the copy. Thus, before using borg on the copy from a different host,
            you need to use "borg break-lock" on the copied repository, because
            Borg is cautious and does not automatically remove stale locks made by a different host.
        """
        )
        subparser = subparsers.add_parser(
            "with-lock",
            parents=[common_parser],
            add_help=False,
            description=self.do_with_lock.__doc__,
            epilog=with_lock_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="run user command with lock held",
        )
        subparser.set_defaults(func=self.do_with_lock)
        subparser.add_argument("command", metavar="COMMAND", help="command to run")
        subparser.add_argument("args", metavar="ARGS", nargs=argparse.REMAINDER, help="command arguments")
