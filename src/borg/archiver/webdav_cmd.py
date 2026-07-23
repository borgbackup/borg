import threading
import time

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import sig_int
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class WebDAVMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_webdav(self, args, repository, manifest):
        """Serve archive contents via a read-only WebDAV / HTTP server on localhost."""
        from ..webdav import make_server
        from ..storelocking import LockRefresher

        server = make_server(manifest, args, port=args.port)
        host, port = server.server_address[:2]
        print(f"Serving selected archives read-only on http://{host}:{port}/ - press Ctrl-C to stop.")
        # keep the repository lock of an idle server alive, so it is not killed as stale (see #9872).
        lock_refreshing_thread = LockRefresher(manifest.repository.info, sleep_interval=60, lock=server.repo_lock)
        lock_refreshing_thread.start()
        # the first SIGINT only sets the sig_int flag (see SigIntManager), so serve in a
        # thread and poll the flag here, to shut down cleanly on the first Ctrl-C already.
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            while not sig_int:
                time.sleep(0.1)
            print("Shutting down...")
        finally:
            lock_refreshing_thread.terminate()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=10)

    def build_parser_webdav(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        webdav_epilog = process_epilog(
            """
        This command serves the contents of the selected archives via a read-only
        WebDAV / HTTP server, so the archive contents can be:

        - browsed and downloaded with a web browser,
        - mounted as a read-only network file system, using the WebDAV client
          built into most operating systems and file managers.

        Mounting examples:

        - Windows Explorer: "Map network drive" -> ``http://localhost:8000/``
          (or on the command line: ``net use Z: http://localhost:8000/``).
        - macOS Finder: "Go > Connect to Server" (Cmd-K) -> ``http://localhost:8000``.
        - GNOME Files / KDE Dolphin: open ``dav://localhost:8000/``.
        - Linux kernel mount: ``mount -t davfs http://localhost:8000/ /mnt/point``
          (needs the davfs2 package).

        The server listens on localhost (127.0.0.1) only and offers no
        authentication and no encryption - anything that can connect to
        localhost TCP ports on the machine can read the served archive contents.

        The top level lists the selected archives (use the archive filter options
        to select fewer archives); below that, the archive contents can be
        browsed like a directory tree. The directory tree of an archive is built
        in memory when it is first entered, so expect some delay for big archives.

        Notes:

        - Downloads do not preserve any POSIX metadata (owner, group, mode,
          timestamps, xattrs, ACLs). Use ``borg extract`` or ``borg export-tar``
          for full-fidelity restores.
        - Symbolic links and special files (devices, fifos, sockets) are shown
          in the web browser listings, but are neither followed nor downloadable,
          and they are not visible in WebDAV-mounted directories (WebDAV has no
          concept of them).
        - Damaged files (with chunks missing in the repository) cause the
          download connection to be aborted - the server never silently serves
          corrupted file content.
        - The Windows WebDAV client limits file downloads to about 47 MiB by
          default (``FileSizeLimitInBytes`` registry value) - use a web browser
          or another WebDAV client to download bigger files.

        Recently used file content chunks are kept decrypted in an in-memory cache,
        so that the many small, sequential range requests a mounted file system
        does for a big file do not re-fetch and re-decrypt the same chunk over and
        over. As for ``borg mount``, the ``BORG_MOUNT_DATA_CACHE_ENTRIES`` environment
        variable sets the number of cached chunks (default: number of CPUs);
        additional memory usage can be up to the chunk size times this number.

        The command runs in the foreground until it is interrupted with Ctrl-C.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_webdav.__doc__, epilog=webdav_epilog)
        subparsers.add_subcommand("webdav", subparser, help="serve archive contents via WebDAV / HTTP")
        subparser.add_argument(
            "--port",
            metavar="PORT",
            dest="port",
            type=int,
            default=8000,
            action=Highlander,
            help="TCP port to listen on (on localhost); default: %(default)s",
        )
        define_archive_filters_group(subparser)
