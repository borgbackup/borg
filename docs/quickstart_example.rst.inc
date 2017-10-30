1. Before a backup can be made a repository has to be initialized::

    $ borg init --encryption=repokey /path/to/repo

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *Monday*::

    $ borg create /path/to/repo::Monday ~/src ~/Documents

3. The next day create a new archive called *Tuesday*::

    $ borg create --stats /path/to/repo::Tuesday ~/src ~/Documents

   This backup will be a lot quicker and a lot smaller since only new never
   before seen data is stored. The ``--stats`` option causes Borg to
   output statistics about the newly created archive such as the amount of unique
   data (not shared with other archives)::

    ------------------------------------------------------------------------------
    Archive name: Tuesday
    Archive fingerprint: bd31004d58f51ea06ff735d2e5ac49376901b21d58035f8fb05dbf866566e3c2
    Time (start): Tue, 2016-02-16 18:15:11
    Time (end):   Tue, 2016-02-16 18:15:11

    Duration: 0.19 seconds
    Number of files: 127
    ------------------------------------------------------------------------------
                          Original size      Compressed size    Deduplicated size
    This archive:                4.16 MB              4.17 MB             26.78 kB
    All archives:                8.33 MB              8.34 MB              4.19 MB

                          Unique chunks         Total chunks
    Chunk index:                     132                  261
    ------------------------------------------------------------------------------

4. List all archives in the repository::

    $ borg list /path/to/repo
    Monday                               Mon, 2016-02-15 19:14:44
    Tuesday                              Tue, 2016-02-16 19:15:11

5. List the contents of the *Monday* archive::

    $ borg list /path/to/repo::Monday
    drwxr-xr-x user   group          0 Mon, 2016-02-15 18:22:30 home/user/Documents
    -rw-r--r-- user   group       7961 Mon, 2016-02-15 18:22:30 home/user/Documents/Important.doc
    ...

6. Restore the *Monday* archive by extracting the files relative to the current directory::

    $ borg extract /path/to/repo::Monday

7. Recover disk space by manually deleting the *Monday* archive::

    $ borg delete /path/to/repo::Monday

.. Note::
    Borg is quiet by default (it works on WARNING log level).
    You can use options like ``--progress`` or ``--list`` to get specific
    reports during command execution.  You can also add the ``-v`` (or
    ``--verbose`` or ``--info``) option to adjust the log level to INFO to
    get other informational messages.
