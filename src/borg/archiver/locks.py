import argparse
import subprocess

from .common import with_repository
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import prepare_subprocess_env

from ..logger import create_logger

logger = create_logger()


class LocksMixIn:
    @with_repository(manifest=False, exclusive=True)
    def do_with_lock(self, args, repository):
        """run a user specified command with the repository lock held"""
        # for a new server, this will immediately take an exclusive lock.
        # to support old servers, that do not have "exclusive" arg in open()
        # RPC API, we also do it the old way:
        # re-write manifest to start a repository transaction - this causes a
        # lock upgrade to exclusive for remote (and also for local) repositories.
        # by using manifest=False in the decorator, we avoid having to require
        # the encryption key (and can operate just with encrypted data).
        data = repository.get(Manifest.MANIFEST_ID)
        repository.put(Manifest.MANIFEST_ID, data)
        # usually, a 0 byte (open for writing) segment file would be visible in the filesystem here.
        # we write and close this file, to rather have a valid segment file on disk, before invoking the subprocess.
        # we can only do this for local repositories (with .io), though:
        if hasattr(repository, "io"):
            repository.io.close_segment()
        env = prepare_subprocess_env(system=True)
        try:
            # we exit with the return code we get from the subprocess
            return subprocess.call([args.command] + args.args, env=env)
        finally:
            # we need to commit the "no change" operation we did to the manifest
            # because it created a new segment file in the repository. if we would
            # roll back, the same file would be later used otherwise (for other content).
            # that would be bad if somebody uses rsync with ignore-existing (or
            # any other mechanism relying on existing segment data not changing).
            # see issue #1867.
            repository.commit(compact=False)

    @with_repository(lock=False, manifest=False)
    def do_break_lock(self, args, repository):
        """Break the repository lock (e.g. in case it was left by a dead borg."""
        repository.break_lock()
        Cache.break_lock(repository)
        return self.exit_code

    def build_parser_locks(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

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
        This command runs a user-specified command while the repository lock is held.

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
