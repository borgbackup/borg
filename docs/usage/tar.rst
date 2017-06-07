.. include:: export-tar.rst.inc

Examples
~~~~~~~~
::

    # export as uncompressed tar
    $ borg export-tar /path/to/repo::Monday Monday.tar

    # exclude some types, compress using gzip
    $ borg export-tar /path/to/repo::Monday Monday.tar.gz --exclude '*.so'

    # use higher compression level with gzip
    $ borg export-tar testrepo::linux --tar-filter="gzip -9" Monday.tar.gz

    # export a gzipped tar, but instead of storing it on disk,
    # upload it to a remote site using curl.
    $ borg export-tar ... --tar-filter="gzip" - | curl --data-binary @- https://somewhere/to/POST
