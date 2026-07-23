.. include:: webdav.rst.inc

Examples
~~~~~~~~

::

    # Serve all archives of the repository on http://127.0.0.1:8000/,
    # then browse and download files with a web browser.
    $ borg webdav

    # Serve only one archive on a different port.
    $ borg webdav --port 8123 --match-archives my-archive
