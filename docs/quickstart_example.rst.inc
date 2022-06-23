1. Before a backup can be made a repository has to be initialized::

    $ borg -r /path/to/repo rcreate --encryption=repokey-aes-ocb

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *Monday*::

    $ borg -r /path/to/repo create Monday ~/src ~/Documents

3. The next day create a new archive called *Tuesday*::

    $ borg -r /path/to/repo create --stats Tuesday ~/src ~/Documents

   This backup will be a lot quicker and a lot smaller since only new never
   before seen data is stored. The ``--stats`` option causes Borg to
   output statistics about the newly created archive such as the deduplicated
   size (the amount of unique data not shared with other archives)::

    Repository: /path/to/repo
    Archive name: Tuesday
    Archive fingerprint: bcd1b53f9b4991b7afc2b339f851b7ffe3c6d030688936fe4552eccc1877718d
    Time (start): Sat, 2022-06-25 20:21:43
    Time (end):   Sat, 2022-06-25 20:21:43
    Duration: 0.07 seconds
    Utilization of max. archive size: 0%
    Number of files: 699
    Original size: 31.14 MB
    Deduplicated size: 502 B

4. List all archives in the repository::

    $ borg -r /path/to/repo rlist
    Monday                               Sat, 2022-06-25 20:21:14 [b80e24d2...b179f298]
    Tuesday                              Sat, 2022-06-25 20:21:43 [bcd1b53f...1877718d]

5. List the contents of the *Monday* archive::

    $ borg -r /path/to/repo list Monday
    drwxr-xr-x user   group          0 Mon, 2016-02-15 18:22:30 home/user/Documents
    -rw-r--r-- user   group       7961 Mon, 2016-02-15 18:22:30 home/user/Documents/Important.doc
    ...

6. Restore the *Monday* archive by extracting the files relative to the current directory::

    $ borg -r /path/to/repo extract Monday

7. Delete the *Monday* archive (please note that this does **not** free repo disk space)::

    $ borg -r /path/to/repo delete -a Monday

   Please note the ``-a`` option here (short for ``--glob-archives``) which enables you
   to give a globbing pattern to delete multiple archives, like ``-a 'oldcrap-*'``.
   You can also combine this with ``--first``, ``--last`` and ``--sort-by``.
   Be careful, always first use with ``--dry-run`` and ``--list``!

8. Recover disk space by compacting the segment files in the repo::

    $ borg -r /path/to/repo compact

.. Note::
    Borg is quiet by default (it works on WARNING log level).
    You can use options like ``--progress`` or ``--list`` to get specific
    reports during command execution.  You can also add the ``-v`` (or
    ``--verbose`` or ``--info``) option to adjust the log level to INFO to
    get other informational messages.
