.. include:: info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /path/to/repo::2017-06-29T11:00-srv
    Archive name: 2017-06-29T11:00-srv
    Archive fingerprint: b2f1beac2bd553b34e06358afa45a3c1689320d39163890c5bbbd49125f00fe5
    Comment:
    Hostname: myhostname
    Username: root
    Time (start): Thu, 2017-06-29 11:03:07
    Time (end): Thu, 2017-06-29 11:03:13
    Duration: 5.66 seconds
    Number of files: 17037
    Command line: /usr/sbin/borg create /path/to/repo::2017-06-29T11:00-srv /srv
    Utilization of max. archive size: 0%
    ------------------------------------------------------------------------------
                           Original size      Compressed size    Deduplicated size
    This archive:               12.53 GB             12.49 GB              1.62 kB
    All archives:              121.82 TB            112.41 TB            215.42 GB

                           Unique chunks         Total chunks
    Chunk index:                 1015213            626934122

    $ borg info /path/to/repo --last 1
    Archive name: 2017-06-29T11:00-srv
    Archive fingerprint: b2f1beac2bd553b34e06358afa45a3c1689320d39163890c5bbbd49125f00fe5
    Comment:
    Hostname: myhostname
    Username: root
    Time (start): Thu, 2017-06-29 11:03:07
    Time (end): Thu, 2017-06-29 11:03:13
    Duration: 5.66 seconds
    Number of files: 17037
    Command line: /usr/sbin/borg create /path/to/repo::2017-06-29T11:00-srv /srv
    Utilization of max. archive size: 0%
    ------------------------------------------------------------------------------
                           Original size      Compressed size    Deduplicated size
    This archive:               12.53 GB             12.49 GB              1.62 kB
    All archives:              121.82 TB            112.41 TB            215.42 GB

                           Unique chunks         Total chunks
    Chunk index:                 1015213            626934122

    $ borg info /path/to/repo
    Repository ID: d857ce5788c51272c61535062e89eac4e8ef5a884ffbe976e0af9d8765dedfa5
    Location: /path/to/repo
    Encrypted: Yes (repokey)
    Cache: /root/.cache/borg/d857ce5788c51272c61535062e89eac4e8ef5a884ffbe976e0af9d8765dedfa5
    Security dir: /root/.config/borg/security/d857ce5788c51272c61535062e89eac4e8ef5a884ffbe976e0af9d8765dedfa5
    ------------------------------------------------------------------------------
                           Original size      Compressed size    Deduplicated size
    All archives:              121.82 TB            112.41 TB            215.42 GB

                           Unique chunks         Total chunks
    Chunk index:                 1015213            626934122
