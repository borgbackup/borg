.. include:: repo-compress.rst.inc

Examples
~~~~~~~~

::

    # Recompress repository contents
    $ borg repo-compress --progress --compression=zstd,3

    # Recompress and obfuscate repository contents
    $ borg repo-compress --progress --compression=obfuscate,1,zstd,3
