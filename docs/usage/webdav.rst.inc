.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_webdav:

borg webdav
-----------
.. code-block:: none

    borg [common options] webdav [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--port PORT``                              | TCP port to listen on (on localhost); default: 8000                                                                         |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                           |
    |                                                                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider the first N archives after other filters are applied                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider the last N archives after other filters are applied                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --port PORT     TCP port to listen on (on localhost); default: 8000


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. See "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider the first N archives after other filters are applied
        --last N                                 consider the last N archives after other filters are applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g., 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.


Description
~~~~~~~~~~~

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

The command runs in the foreground until it is interrupted with Ctrl-C.