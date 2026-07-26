import os
import threading
import time

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import sig_int, daemonizing, signal_handler
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

        # bind the socket now (in the foreground), so a bind error (e.g. port in use) is
        # reported here instead of in a detached background process. The listening socket
        # survives the daemonizing fork below.
        server = make_server(manifest, args, port=args.port)
        host, port = server.server_address[:2]
        url = f"http://{host}:{port}/"

        # daemonizing needs os.fork(), which does not exist on Windows - stay in the
        # foreground there (borg webdav is meant to be usable on Windows, unlike borg mount).
        daemonize = not args.foreground and hasattr(os, "fork")
        if not args.foreground and not daemonize:
            logger.info("Daemonizing is not supported on this platform, staying in the foreground.")

        if daemonize:
            print(f"Serving selected archives read-only on {url} in the background.")
            with daemonizing(show_rc=getattr(args, "show_rc", False)) as (old_id, new_id):
                # we forked, so the process holding the repository lock changed: migrate it.
                manifest.repository.migrate_lock(old_id, new_id)
        else:
            print(f"Serving selected archives read-only on {url} - press Ctrl-C to stop.")

        # From here on we run in the background (grandchild) process if daemonized, or in the
        # same process otherwise. Threads must be started here, after the possible fork above,
        # because threads do not survive fork().
        # keep the repository lock of an idle server alive, so it is not killed as stale (see #9872).
        lock_refreshing_thread = LockRefresher(manifest.repository.info, sleep_interval=60, lock=server.repo_lock)
        lock_refreshing_thread.start()
        # the first SIGINT only sets the sig_int flag (see SigIntManager), so serve in a
        # thread and poll the flag here, to shut down cleanly on the first Ctrl-C already.
        # SIGTERM (the usual way to stop a daemon) also stops us, so the repo lock is released.
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        terminated = threading.Event()
        try:
            with signal_handler("SIGTERM", lambda sig_no, stack: terminated.set()):
                while not sig_int and not terminated.is_set():
                    time.sleep(0.1)
            logger.info("webdav: shutting down.")
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

        Any directory can be downloaded as a tar archive by appending ``?tar`` to its
        URL (the web browser listings show a download icon next to the heading for this).
        Unlike a plain file
        download, the tar preserves POSIX metadata (owner, group, mode, sub-second
        timestamps, symlinks, special files, xattrs, ACLs), so it is the metadata-
        lossless way to restore a whole directory tree over this server. It is a PAX
        format tarball, streamed uncompressed.

        Notes:

        - Plain (non-tar) file downloads do not preserve any POSIX metadata (owner,
          group, mode, timestamps, xattrs, ACLs). Use the ``?tar`` download above, or
          ``borg extract`` / ``borg export-tar``, for full-fidelity restores.
        - Symbolic links and special files (devices, fifos, sockets) are shown
          in the web browser listings, but are neither followed nor downloadable
          individually, and they are not visible in WebDAV-mounted directories
          (WebDAV has no concept of them). They are, however, included in ``?tar``
          downloads.
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

        Unless the ``--foreground`` option is given, the command daemonizes and runs
        in the background until it is stopped by sending it a signal (e.g. ``kill``
        sends SIGTERM), which shuts the server down and releases the repository lock.
        In the foreground, ^C / SIGINT stops it. Daemonizing is not available on
        Windows, so the command always stays in the foreground there.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_webdav.__doc__, epilog=webdav_epilog)
        subparsers.add_subcommand("webdav", subparser, help="serve archive contents via WebDAV / HTTP")
        subparser.add_argument(
            "-f", "--foreground", dest="foreground", action="store_true", help="stay in foreground, do not daemonize"
        )
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
