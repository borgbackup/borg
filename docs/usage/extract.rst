.. include:: extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract /path/to/repo::my-files

    # Extract entire archive and list files while processing
    $ borg extract --list /path/to/repo::my-files

    # Verify whether an archive could be successfully extracted, but do not write files to disk
    $ borg extract --dry-run /path/to/repo::my-files

    # Extract the "src" directory
    $ borg extract /path/to/repo::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract /path/to/repo::my-files home/USERNAME/src --exclude '*.o'

    # Restore a raw device (must not be active/in use/mounted at that time)
    $ borg extract --stdout /path/to/repo::my-sdx | dd of=/dev/sdx bs=10M


.. Note::

    Currently, extract always writes into the current working directory ("."),
    so make sure you ``cd`` to the right place before calling ``borg extract``.
