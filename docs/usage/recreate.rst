.. include:: recreate.rst.inc

Examples
~~~~~~~~
::

    # Make old (Attic / Borg 0.xx) archives deduplicate with Borg 1.x archives.
    # Archives created with Borg 1.1+ and the default chunker params are skipped
    # (archive ID stays the same).
    $ borg recreate /mnt/backup --chunker-params default --progress

    # Create a backup with little but fast compression
    $ borg create /mnt/backup::archive /some/files --compression lz4
    # Then compress it - this might take longer, but the backup has already completed,
    # so no inconsistencies from a long-running backup job.
    $ borg recreate /mnt/backup::archive --recompress --compression zlib,9

    # Remove unwanted files from all archives in a repository.
    # Note the relative path for the --exclude option - archives only contain relative paths.
    $ borg recreate /mnt/backup --exclude home/icke/Pictures/drunk_photos

    # Change archive comment
    $ borg create --comment "This is a comment" /mnt/backup::archivename ~
    $ borg info /mnt/backup::archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a comment
    ...
    $ borg recreate --comment "This is a better comment" /mnt/backup::archivename
    $ borg info /mnt/backup::archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a better comment
    ...
