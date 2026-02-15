import argparse

from ._argparse import ArgumentParser

from ..constants import *  # NOQA
from ..remote import RepositoryServer

from ..logger import create_logger

logger = create_logger()


class ServeMixIn:
    def do_serve(self, args):
        """Starts in server mode. This command is usually not used manually."""
        RepositoryServer(
            restrict_to_paths=args.restrict_to_paths,
            restrict_to_repositories=args.restrict_to_repositories,
            use_socket=args.use_socket,
            permissions=args.permissions,
        ).serve()

    def build_parser_serve(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        serve_epilog = process_epilog(
            """
        This command starts a repository server process.

        `borg serve` currently supports:

        - Being automatically started via SSH when the borg client uses an ssh://...
          remote repository. In this mode, `borg serve` will run until that SSH connection
          is terminated.

        - Being started by some other means (not by the borg client) as a long-running socket
          server to be used for borg clients using a socket://... repository (see the `--socket`
          option if you do not want to use the default path for the socket and PID file).

        Please note that `borg serve` does not support providing a specific repository via the
        `--repo` option or the `BORG_REPO` environment variable. It is always the borg client that
        specifies the repository to use when communicating with `borg serve`.

        The --permissions option enforces repository permissions:

        - `all`: All permissions are granted. (Default; the permissions system is not used.)
        - `no-delete`: Allow reading and writing; disallow deleting and overwriting data.
          New archives can be created; existing archives cannot be deleted. New chunks can
          be added; existing chunks cannot be deleted or overwritten.
        - `write-only`: Allow writing; disallow reading data.
          New archives can be created; existing archives cannot be read.
          New chunks can be added; existing chunks cannot be read, deleted, or overwritten.
        - `read-only`: Allow reading; disallow writing or deleting data.
          Existing archives can be read, but no archives can be created or deleted.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_serve.__doc__,
            epilog=serve_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        subparsers.add_subcommand("serve", subparser, help="start the repository server process")
        subparser.add_argument(
            "--restrict-to-path",
            metavar="PATH",
            dest="restrict_to_paths",
            action="append",
            help="Restrict repository access to PATH. "
            "Can be specified multiple times to allow the client access to several directories. "
            "Access to all subdirectories is granted implicitly; PATH does not need to point directly to a repository.",
        )
        subparser.add_argument(
            "--restrict-to-repository",
            metavar="PATH",
            dest="restrict_to_repositories",
            action="append",
            help="Restrict repository access. Only the repository located at PATH "
            "(no subdirectories are considered) is accessible. "
            "Can be specified multiple times to allow the client access to several repositories. "
            "Unlike ``--restrict-to-path``, subdirectories are not accessible; "
            "PATH must point directly to a repository location. "
            "PATH may be an empty directory or the last element of PATH may not exist, in which case "
            "the client may initialize a repository there.",
        )
        subparser.add_argument(
            "--permissions",
            dest="permissions",
            choices=["all", "no-delete", "write-only", "read-only"],
            help="Set repository permission mode. Overrides BORG_REPO_PERMISSIONS environment variable.",
        )
