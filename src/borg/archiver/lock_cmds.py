import argparse

from ._argparse import ArgumentParser
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
        """Runs a user-specified command with the repository lock held."""
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
            raise CommandError(f"Failed to execute command: {e}")
        finally:
            lock_refreshing_thread.terminate()

    @with_repository(lock=False, manifest=False)
    def do_break_lock(self, args, repository):
        """Breaks the repository lock (for example, if it was left by a dead Borg process)."""
        repository.break_lock()
        Cache.break_lock(repository)

    def build_parser_locks(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        break_lock_epilog = process_epilog(
            """
        This command breaks the repository and cache locks.
        Use with care and only when no Borg process (on any machine) is
        trying to access the cache or the repository.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_break_lock.__doc__,
            epilog=break_lock_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        subparsers.add_subcommand("break-lock", subparser, help="break the repository and cache locks")

        with_lock_epilog = process_epilog(
            """
        This command runs a user-specified command while locking the repository. For example:

        ::

            $ BORG_REPO=/mnt/borgrepo borg with-lock rsync -av /mnt/borgrepo /somewhere/else/borgrepo

        It first tries to acquire the lock (make sure that no other operation is
        running in the repository), then executes the given command as a subprocess and waits
        for its termination, releases the lock, and returns the user command's return
        code as Borg's return code.

        .. note::

            If you copy a repository with the lock held, the lock will be present in
            the copy. Before using Borg on the copy from a different host,
            you need to run ``borg break-lock`` on the copied repository, because
            Borg is cautious and does not automatically remove stale locks made by a different host.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_with_lock.__doc__,
            epilog=with_lock_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        subparsers.add_subcommand("with-lock", subparser, help="run a user command with the lock held")
        subparser.add_argument("command", metavar="COMMAND", help="command to run")
        subparser.add_argument("args", metavar="ARGS", nargs=argparse.REMAINDER, help="command arguments")
