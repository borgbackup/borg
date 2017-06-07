.. include:: info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /path/to/repo::root-2016-02-15
    Name: root-2016-02-15
    Fingerprint: 57c827621f21b000a8d363c1e163cc55983822b3afff3a96df595077a660be50
    Hostname: myhostname
    Username: root
    Time (start): Mon, 2016-02-15 19:36:29
    Time (end):   Mon, 2016-02-15 19:39:26
    Command line: /usr/local/bin/borg create --list -C zlib,6 /path/to/repo::root-2016-02-15 / --one-file-system
    Number of files: 38100

                           Original size      Compressed size    Deduplicated size
    This archive:                1.33 GB            613.25 MB            571.64 MB
    All archives:                1.63 GB            853.66 MB            584.12 MB

                           Unique chunks         Total chunks
    Chunk index:                   36858                48844

