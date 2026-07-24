.. include:: webdav.rst.inc

Examples
~~~~~~~~

::

    # Serve all archives of the repository on http://127.0.0.1:8000/,
    # then browse and download files with a web browser.
    $ borg webdav

    # Serve only one archive on a different port.
    $ borg webdav --port 8123 --match-archives my-archive


Client notes and known issues
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

WebDAV's rough edges are almost all on the client side, and a *read-only* server
(like this one) hits a specific subset of them. A plain web browser avoids most of
these - the notes below matter mainly when *mounting* the server as a file system.

**Windows Explorer** (the "WebClient" / mini-redirector)

- Downloads are limited to about 47 MiB by default (the ``FileSizeLimitInBytes``
  registry value). Bigger files fail when copied from a mapped drive - use a web
  browser (including for the ``?tar`` directory download) or another WebDAV client.
- The ``WebClient`` service must be running for ``net use`` / "Map network drive"
  to work; if it is stopped, mounting silently fails.
- Windows refuses HTTP Basic authentication over plain HTTP by default (only over
  HTTPS). This does not matter now (the server has no authentication), but it is a
  wall for any future networked, authenticated setup.
- Explorer is chatty (a PROPFIND per navigation, many short connections), so
  browsing large directories over a mount can feel slow.

**macOS Finder** (``mount_webdav`` / WebDAVFS)

- Finder tries to write ``.DS_Store``, ``._*`` (AppleDouble) and ``.Trash`` files
  into every folder it opens. On this read-only server those writes are rejected
  (the file system is read-only); Finder tolerates it but may occasionally show a
  spurious "operation could not be completed" dialog. This is harmless.
- WebDAVFS caches directory listings; a stale view usually clears on unmount and
  remount.

**Linux davfs2**

- davfs2 uses WebDAV locking by default and will try to LOCK files it opens, which
  a read-only server rejects. Set ``use_locks 0`` in ``davfs2.conf`` (or the
  per-mount config) to avoid the failed lock attempts. davfs2 also caches whole
  files in a local cache directory.
- The GNOME (gvfs) and KDE (KIO) DAV backends work without such tweaks, but are
  also PROPFIND-heavy on large directories.

**Protocol-level (any client)**

- ``PROPFIND`` with ``Depth: infinity`` (a recursive enumeration that can be very
  expensive) is refused with ``403``, as permitted by RFC 4918. Well-behaved
  clients use ``Depth: 0`` or ``1``.
- Collections must be addressed with a trailing slash; a request for ``/dir`` is
  redirected to ``/dir/``.
- Symbolic links and special files (devices, fifos, sockets) have no
  representation in WebDAV, so they are not visible in a mounted file system. They
  are shown in the web browser listings and are included in ``?tar`` downloads.
- WebDAV transfers file contents plus modification time and size, but no owner,
  group, mode, xattrs or ACLs. Use the ``?tar`` directory download (or
  ``borg extract`` / ``borg export-tar``) when you need a full-fidelity restore.
