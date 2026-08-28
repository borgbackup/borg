.. include:: export-tar.rst.inc

.. include:: import-tar.rst.inc

Examples
~~~~~~~~
::

    # Export as an uncompressed tar archive
    $ borg export-tar Monday Monday.tar

    # Import an uncompressed tar archive
    $ borg import-tar Monday Monday.tar

    # Exclude some file types and compress using gzip
    $ borg export-tar Monday Monday.tar.gz --exclude '*.so'

    # Use a higher compression level with gzip
    $ borg export-tar --tar-filter="gzip -9" Monday Monday.tar.gz

    # Copy an archive from repoA to repoB
    $ borg -r repoA export-tar --tar-format=BORG archive - | borg -r repoB import-tar archive -

    # Export a tar, but instead of storing it on disk, upload it to a remote site using curl
    $ borg export-tar Monday - | curl --data-binary @- https://somewhere/to/POST

    # Remote extraction via 'tarpipe'
    $ borg export-tar Monday - | ssh somewhere "cd extracted; tar x"

    # Export sparse files (e.g. disk images) as sparse tar members (GNU sparse format 1.0)
    $ borg export-tar --sparse disk-images disk-images.tar

Archives transfer script
~~~~~~~~~~~~~~~~~~~~~~~~

Outputs a script that copies all archives from repo1 to repo2
(``bash``, because it uses process substitution). Remove the ``echo`` to
actually run the commands instead of just printing them:

::

    while read -r N I T
    do
      echo "borg -r repo1 export-tar --tar-format=BORG aid:$I - | borg -r repo2 import-tar --timestamp=$T $N -"
    done < <(borg -r repo1 repo-list --format='{name} {id} {time:%Y-%m-%dT%H:%M:%S}{NL}')

Kept:

- archive name, archive timestamp
- archive contents (all items with metadata and data)

Lost:

- some archive metadata (like the original command line, execution time, etc.)

Please note:

- all data goes over that pipe, again and again for every archive
- the pipe is dumb, there is no data or transfer time reduction there due to deduplication
- maybe add compression
- pipe over ssh for remote transfer
- maybe add ``--sparse`` to the export-tar command, so runs of all-zero chunks
  travel as a compact sparse map instead of literal zeros
