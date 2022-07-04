.. include:: extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract my-files

    # Extract entire archive and list files while processing
    $ borg extract --list my-files

    # Verify whether an archive could be successfully extracted, but do not write files to disk
    $ borg extract --dry-run my-files

    # Extract the "src" directory
    $ borg extract my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract my-files home/USERNAME/src --exclude '*.o'

    # Restore a raw device (must not be active/in use/mounted at that time)
    $ borg extract --stdout my-sdx | dd of=/dev/sdx bs=10M

