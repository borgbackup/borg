.. include:: recreate.rst.inc

Examples
~~~~~~~~
::

    # Create a backup with fast, low compression
    $ borg create archive files --compression lz4
    # Then recompress the data already stored in the repository — this might take longer,
    # but the backup has already completed, so there are no inconsistencies from a
    # long-running backup job. Note that recompressing existing repository data is the
    # job of "borg repo-compress", not of "borg recreate".
    $ borg repo-compress --compression zlib,9 --stats
    Recompression stats:
    Packs: 2 total, 2 rewritten.
    Objects: 5 total, 2 recompressed, 0 already had the desired compression, 3 kept as-is (recompression brings no gain).
    Repository size: 301.59 kB before, 301.53 kB after, shrunk by 60 B.

    # Remove unwanted files from all archives in a repository.
    # Note the relative path for the --exclude option — archives only contain relative paths.
    $ borg recreate --exclude home/icke/Pictures/drunk_photos

    # Change the archive comment. Note that recreate writes a new archive,
    # so the archive fingerprint changes.
    $ borg create --comment "This is a comment" archivename files
    $ borg info -a archivename
    Archive name: archivename
    Archive fingerprint: 6cfecdd4e963bbe150c08169407de0353a4c5f2f90221646a9ebb0ce9be2529a
    Comment: This is a comment
    ...
    $ borg recreate --comment "This is a better comment" -a archivename
    $ borg info -a archivename
    Archive name: archivename
    Archive fingerprint: 259b5302a8de9c889fb4915fe5df128f6c22776966db2dc3c7d3c8e741bf45b6
    Comment: This is a better comment
    ...

