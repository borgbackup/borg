.. include:: export-tar.rst.inc

.. include:: import-tar.rst.inc

Examples
~~~~~~~~
::

    # export as uncompressed tar
    $ borg export-tar /path/to/repo::Monday Monday.tar

    # import an uncompressed tar
    $ borg import-tar /path/to/repo::Monday Monday.tar

    # exclude some file types, compress using gzip
    $ borg export-tar /path/to/repo::Monday Monday.tar.gz --exclude '*.so'

    # use higher compression level with gzip
    $ borg export-tar --tar-filter="gzip -9" repo::Monday Monday.tar.gz

    # copy an archive from repoA to repoB
    $ borg export-tar --tar-format=BORG repoA::archive - | borg import-tar repoB::archive -

    # export a tar, but instead of storing it on disk, upload it to remote site using curl
    $ borg export-tar /path/to/repo::Monday - | curl --data-binary @- https://somewhere/to/POST

    # remote extraction via "tarpipe"
    $ borg export-tar /path/to/repo::Monday - | ssh somewhere "cd extracted; tar x"

Archives transfer script
~~~~~~~~~~~~~~~~~~~~~~~~

Outputs a script that copies all archives from repo1 to repo2:

::

    for A T in `borg list --format='{archive} {time:%Y-%m-%dT%H:%M:%S}{LF}' repo1`
    do
      echo "borg export-tar --tar-format=BORG repo1::$A - | borg import-tar --timestamp=$T repo2::$A -"
    done

Kept:

- archive name, archive timestamp
- archive contents (all items with metadata and data)

Lost:

- some archive metadata (like the original commandline, execution time, etc.)

Please note:

- all data goes over that pipe, again and again for every archive
- the pipe is dumb, there is no data or transfer time reduction there due to deduplication
- maybe add compression
- pipe over ssh for remote transfer
- no special sparse file support
