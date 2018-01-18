.. include:: export-tar.rst.inc

Examples
~~~~~~~~
::

    # export as uncompressed tar
    $ borg export-tar /path/to/repo::Monday Monday.tar

    # exclude some types, compress using gzip
    $ borg export-tar /path/to/repo::Monday Monday.tar.gz --exclude '*.so'

    # use higher compression level with gzip
    $ borg export-tar --tar-filter="gzip -9" testrepo::linux Monday.tar.gz

    # export a tar, but instead of storing it on disk,
    # upload it to a remote site using curl.
    $ borg export-tar /path/to/repo::Monday - | curl --data-binary @- https://somewhere/to/POST

    # remote extraction via "tarpipe"
    $ borg export-tar /path/to/repo::Monday - | ssh somewhere "cd extracted; tar x"
