1. Before a backup can be made, a repository has to be initialized::

    $ borg -r /path/to/repo repo-create --encryption=aes256-ocb

2. Back up the ``~/src`` and ``~/Documents`` directories into an archive called
   *docs*::

    $ borg -r /path/to/repo create docs ~/src ~/Documents

3. The next day, create a new archive using the same archive name::

    $ borg -r /path/to/repo create --stats docs ~/src ~/Documents

   This backup will be much quicker and much smaller, since only new,
   never-before-seen data is stored. The ``--stats`` option causes Borg to
   output statistics about the newly created archive such as the deduplicated
   size (the amount of unique data not shared with other archives)::

    Repository: /path/to/repo
    Archive name: docs
    Archive fingerprint: 74efb3f0c9c05f8b7c822ba859919b480578a3457fd4965c2cee64fbdb631262
    Time (nominal): Fri, 2026-08-28 12:24:24 +0200
    Time (start):   Fri, 2026-08-28 12:24:24 +0200
    Time (end):     Fri, 2026-08-28 12:24:24 +0200
    Duration: 0.008 seconds
    Number of files: 100
    Original size: 1.99 MB
    Deduplicated size: 703 B
    Time spent in hashing: 0.000 seconds
    Time spent in chunking: 0.000 seconds
    Added files: 1
    Unchanged files: 99
    Modified files: 0
    Error files: 0
    Files changed while reading: 0
    ...

   (some more lines with statistics about the repository store accesses follow)

4. List all archives in the repository (the first column is the beginning of the
   archive ID)::

    $ borg -r /path/to/repo repo-list
    3affe017  Fri, 2026-08-28 12:24:10 +0200  docs                         user        machine
    74efb3f0  Fri, 2026-08-28 12:24:24 +0200  docs                         user        machine

5. List the contents of the first archive::

    $ borg -r /path/to/repo list aid:3affe017
    drwxr-xr-x user   group         0 Fri, 2026-08-28 12:22:30 +0200 home/user/Documents
    -rw-r--r-- user   group      7961 Fri, 2026-08-28 12:22:30 +0200 home/user/Documents/Important.doc
    ...

6. Restore the first archive by extracting the files relative to the current directory::

    $ borg -r /path/to/repo extract aid:3affe017

7. Delete the first archive (please note that this does **not** free repository disk space)::

    $ borg -r /path/to/repo delete aid:3affe017

   If you use an archive NAME (and not an archive ID), Borg will abort if the name matches multiple
   archives (as with the two *docs* archives here); use ``aid:<archive-id>`` to delete one specific
   archive, or ``-a PATTERN`` to delete multiple archives. Always use ``--dry-run`` and ``--list`` first!

8. Recover disk space by removing objects that are not referenced by any
   archive any more::

    $ borg -r /path/to/repo compact -v

.. Note::
    Borg is quiet by default (it defaults to WARNING log level).
    You can use options like ``--progress`` or ``--list`` to get specific
    reports during command execution.  You can also add the ``-v`` (or
    ``--verbose`` or ``--info``) option to adjust the log level to INFO to
    get other informational messages.
