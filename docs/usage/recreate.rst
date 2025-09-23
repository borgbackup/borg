.. include:: recreate.rst.inc

Examples
~~~~~~~~
::

    # Create a backup with fast, low compression
    $ borg create archive /some/files --compression lz4
    # Then recompress it — this might take longer, but the backup has already completed,
    # so there are no inconsistencies from a long-running backup job.
    $ borg recreate -a archive --recompress --compression zlib,9

    # Remove unwanted files from all archives in a repository.
    # Note the relative path for the --exclude option — archives only contain relative paths.
    $ borg recreate --exclude home/icke/Pictures/drunk_photos

    # Change the archive comment
    $ borg create --comment "This is a comment" archivename ~
    $ borg info -a archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a comment
    ...
    $ borg recreate --comment "This is a better comment" -a archivename
    $ borg info -a archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a better comment
    ...

