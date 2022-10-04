.. include:: rcompress.rst.inc

Examples
~~~~~~~~

::

    # recompress repo contents
    $ borg rcompress --progress --compression=zstd,3

    # recompress and obfuscate repo contents
    $ borg rcompress --progress --compression=obfuscate,1,zstd,3
