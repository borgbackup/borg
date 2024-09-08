.. include:: repo-compress.rst.inc

Examples
~~~~~~~~

::

    # recompress repo contents
    $ borg repo-compress --progress --compression=zstd,3

    # recompress and obfuscate repo contents
    $ borg repo-compress --progress --compression=obfuscate,1,zstd,3
