import os

from ..constants import *  # NOQA
from ..helpers import Error, PathNotAllowed
from ..legacy.remote import RepositoryServer

from ..logger import create_logger
from ..helpers.argparsing import ArgumentParser

logger = create_logger()


class ServeMixIn:
    def do_serve(self, args):
        """Starts in server mode. This command is usually not used manually."""
        if args.rest:
            self.do_serve_rest(args)
        else:
            # note: legacy (borg 1.x) repositories have no permission system, so args.permissions
            # is intentionally not forwarded here (it only applies to "borg serve --rest").
            RepositoryServer(
                restrict_to_paths=args.restrict_to_paths, restrict_to_repositories=args.restrict_to_repositories
            ).serve()

    def do_serve_rest(self, args):
        """Serve a current (non-legacy) rest:// repository on stdio (borgstore REST server)."""
        from borgstore.server.rest import serve as rest_serve
        from ..repository import borg_permissions

        if not args.backend:
            raise Error("borg serve --rest requires --backend FILE:<path>.")
        # enforce --restrict-to-path / --restrict-to-repository against the requested FILE: path
        self.check_rest_restrictions(args.backend, args.restrict_to_paths, args.restrict_to_repositories)
        permissions = (
            args.permissions if args.permissions is not None else os.environ.get("BORG_REPO_PERMISSIONS", "all")
        )
        rest_serve(None, None, args.backend, permissions=borg_permissions(permissions), stdio=True)

    @staticmethod
    def check_rest_restrictions(backend, restrict_to_paths, restrict_to_repositories):
        if not (restrict_to_paths or restrict_to_repositories):
            return
        if not backend.startswith("FILE:"):
            raise PathNotAllowed("only FILE: backends can be restricted")
        path = os.path.realpath(os.path.expanduser(backend[len("FILE:") :]))
        path_with_sep = os.path.join(path, "")  # ensure trailing slash for prefix checks
        if restrict_to_paths:
            for p in restrict_to_paths:
                if path_with_sep.startswith(os.path.join(os.path.realpath(p), "")):
                    break
            else:
                raise PathNotAllowed(path)
        if restrict_to_repositories:
            for p in restrict_to_repositories:
                if os.path.join(os.path.realpath(p), "") == path_with_sep:
                    break
            else:
                raise PathNotAllowed(path)

    def build_parser_serve(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        serve_epilog = process_epilog(
            """
        This command starts a repository server process. It is usually started automatically via
        SSH by a borg client and runs until that SSH connection is terminated.

        It operates in one of two modes:

        - default (no option): serve a **legacy** (borg 1.x / v1) repository using the legacy
          RPC protocol. This is used e.g. for ``borg transfer --from-borg1`` and is command-line
          compatible with borg 1.x ``borg serve``.

        - ``--rest``: serve a **current** (non-legacy) repository as the server-side component of
          a ``rest://`` repository, talking HTTP over stdio. The repository to serve is given via
          ``--backend FILE:<path>``. A borg client using a ``rest://`` repository starts this
          automatically (over SSH if a host is given).

        Please note that, in legacy mode, `borg serve` does not support providing a specific
        repository via the `--repo` option or the `BORG_REPO` environment variable - it is the
        borg client that specifies the repository to use.

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
        subparser = ArgumentParser(parents=[common_parser], description=self.do_serve.__doc__, epilog=serve_epilog)
        subparsers.add_subcommand("serve", subparser, help="start the repository server process")
        subparser.add_argument(
            "--rest",
            dest="rest",
            action="store_true",
            help="serve a current (non-legacy) repository as a rest:// server (HTTP over stdio). "
            "Requires --backend. Without this option, a legacy (borg 1.x) repository is served.",
        )
        subparser.add_argument(
            "--backend",
            metavar="BACKEND_URL",
            dest="backend",
            help="(with --rest) backend URL of the repository to serve, e.g. FILE:/path/to/repo.",
        )
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
