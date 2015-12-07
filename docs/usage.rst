.. include:: global.rst.inc
.. _detailed_usage:

Usage
=====

|project_name| consists of a number of commands. Each command accepts
a number of arguments and options. The following sections will describe each
command in detail.

General
-------

Type of log output
~~~~~~~~~~~~~~~~~~

You can set the log level of the builtin logging configuration using the
--log-level option.

Supported levels: ``debug``, ``info``, ``warning``, ``error``, ``critical``.

All log messages created with at least the given level will be output.

Return codes
~~~~~~~~~~~~

|project_name| can exit with the following return codes (rc):

::

    0 = success (logged as INFO)
    1 = warning (operation reached its normal end, but there were warnings -
        you should check the log, logged as WARNING)
    2 = error (like a fatal error, a local or remote exception, the operation
        did not reach its normal end, logged as ERROR)
    128+N = killed by signal N (e.g. 137 == kill -9)

The return code is also logged at the indicated level as the last log entry.


Environment Variables
~~~~~~~~~~~~~~~~~~~~~

|project_name| uses some environment variables for automation:

General:
    BORG_REPO
        When set, use the value to give the default repository location. If a command needs an archive
        parameter, you can abbreviate as `::archive`. If a command needs a repository parameter, you
        can either leave it away or abbreviate as `::`, if a positional parameter is required.
    BORG_PASSPHRASE
        When set, use the value to answer the passphrase question for encrypted repositories.
    BORG_LOGGING_CONF
        When set, use the given filename as INI_-style logging configuration.
    BORG_RSH
        When set, use this command instead of ``ssh``.
    TMPDIR
        where temporary files are stored (might need a lot of temporary space for some operations)

Some "yes" sayers (if set, they automatically confirm that you really want to do X even if there is that warning):
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK
        For "Warning: Attempting to access a previously unknown unencrypted repository"
    BORG_RELOCATED_REPO_ACCESS_IS_OK
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING
        For "Warning: 'check --repair' is an experimental feature that might result in data loss."

Directories:
    BORG_KEYS_DIR
        Default to '~/.borg/keys'. This directory contains keys for encrypted repositories.
    BORG_CACHE_DIR
        Default to '~/.cache/borg'. This directory contains the local cache and might need a lot
        of space for dealing with big repositories).

Building:
    BORG_OPENSSL_PREFIX
        Adds given OpenSSL header file directory to the default locations (setup.py).
    BORG_LZ4_PREFIX
        Adds given LZ4 header file directory to the default locations (setup.py).


Please note:

- be very careful when using the "yes" sayers, the warnings with prompt exist for your / your data's security/safety
- also be very careful when putting your passphrase into a script, make sure it has appropriate file permissions
  (e.g. mode 600, root:root).


.. _INI: https://docs.python.org/3.2/library/logging.config.html#configuration-file-format

Resource Usage
~~~~~~~~~~~~~~

|project_name| might use a lot of resources depending on the size of the data set it is dealing with.

CPU:
    It won't go beyond 100% of 1 core as the code is currently single-threaded.
    Especially higher zlib and lzma compression levels use significant amounts
    of CPU cycles.

Memory (RAM):
    The chunks index and the files index are read into memory for performance
    reasons.
    Compression, esp. lzma compression with high levels might need substantial
    amounts of memory.

Temporary files:
    Reading data and metadata from a FUSE mounted repository will consume about
    the same space as the deduplicated chunks used to represent them in the
    repository.

Cache files:
    Contains the chunks index and files index (plus a compressed collection of
    single-archive chunk indexes).

Chunks index:
    Proportional to the amount of data chunks in your repo. Lots of small chunks
    in your repo imply a big chunks index. You may need to tweak the chunker
    params (see create options) if you have a lot of data and you want to keep
    the chunks index at some reasonable size.

Files index:
    Proportional to the amount of files in your last backup. Can be switched
    off (see create options), but next backup will be much slower if you do.

Network:
    If your repository is remote, all deduplicated (and optionally compressed/
    encrypted) data of course has to go over the connection (ssh: repo url).
    If you use a locally mounted network filesystem, additionally some copy
    operations used for transaction support also go over the connection. If
    you backup multiple sources to one target repository, additional traffic
    happens for cache resynchronization.

In case you are interested in more details, please read the internals documentation.


Units
~~~~~

To display quantities, |project_name| takes care of respecting the
usual conventions of scale. Disk sizes are displayed in `decimal
<https://en.wikipedia.org/wiki/Decimal>`_, using powers of ten (so
``kB`` means 1000 bytes). For memory usage, `binary prefixes
<https://en.wikipedia.org/wiki/Binary_prefix>`_ are used, and are
indicated using the `IEC binary prefixes
<https://en.wikipedia.org/wiki/IEC_80000-13#Prefixes_for_binary_multiples>`_,
using powers of two (so ``KiB`` means 1024 bytes).


Date and Time
~~~~~~~~~~~~~

We format date and time conforming to ISO-8601, that is: YYYY-MM-DD and HH:MM:SS

For more information, see: https://xkcd.com/1179/


.. include:: usage/init.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ borg init /mnt/backup

    # Remote repository (accesses a remote borg via ssh)
    $ borg init user@hostname:backup

    # Encrypted remote repository, store the key in the repo
    $ borg init --encryption=repokey user@hostname:backup

    # Encrypted remote repository, store the key your home dir
    $ borg init --encryption=keyfile user@hostname:backup

Important notes about encryption:

Use encryption! Repository encryption protects you e.g. against the case that
an attacker has access to your backup repository.

But be careful with the key / the passphrase:

``--encryption=passphrase`` is DEPRECATED and will be removed in next major release.
This mode has very fundamental, unfixable problems (like you can never change
your passphrase or the pbkdf2 iteration count for an existing repository, because
the encryption / decryption key is directly derived from the passphrase).

If you want "passphrase-only" security, just use the ``repokey`` mode. The key will
be stored inside the repository (in its "config" file). In above mentioned
attack scenario, the attacker will have the key (but not the passphrase).

If you want "passphrase and having-the-key" security, use the ``keyfile`` mode.
The key will be stored in your home directory (in ``.borg/keys``). In the attack
scenario, the attacker who has just access to your repo won't have the key (and
also not the passphrase).

Make a backup copy of the key file (``keyfile`` mode) or repo config file
(``repokey`` mode) and keep it at a safe place, so you still have the key in
case it gets corrupted or lost.
The backup that is encrypted with that key won't help you with that, of course.

Make sure you use a good passphrase. Not too short, not too simple. The real
encryption / decryption key is encrypted with / locked by your passphrase.
If an attacker gets your key, he can't unlock and use it without knowing the
passphrase. In ``repokey`` and ``keyfile`` modes, you can change your passphrase
for existing repos.


.. include:: usage/create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create /mnt/backup::my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create /mnt/backup::my-files   \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    # use zlib compression (good, but slow) - default is no compression
    NAME="root-`date +%Y-%m-%d`"
    $ borg create -C zlib,6 /mnt/backup::$NAME / --do-not-cross-mountpoints

    # Backup huge files with little chunk management overhead
    $ borg create --chunker-params 19,23,21,4095 /mnt/backup::VMs /srv/VMs

    # Backup a raw device (must not be active/in use/mounted at that time)
    $ dd if=/dev/sda bs=10M | borg create /mnt/backup::my-sda -

    # No compression (default)
    $ borg create /mnt/backup::repo ~

    # Super fast, low compression
    $ borg create --compression lz4 /mnt/backup::repo ~

    # Less fast, higher compression (N = 0..9)
    $ borg create --compression zlib,N /mnt/backup::repo ~

    # Even slower, even higher compression (N = 0..9)
    $ borg create --compression lzma,N /mnt/backup::repo ~

.. include:: usage/extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract /mnt/backup::my-files

    # Extract entire archive and list files while processing
    $ borg extract -v /mnt/backup::my-files

    # Extract the "src" directory
    $ borg extract /mnt/backup::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract /mnt/backup::my-files home/USERNAME/src --exclude '*.o'

Note: currently, extract always writes into the current working directory ("."),
      so make sure you ``cd`` to the right place before calling ``borg extract``.

.. include:: usage/check.rst.inc

.. include:: usage/rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create /mnt/backup::archivename ~
    $ borg list /mnt/backup
    archivename                          Mon Nov  2 20:40:06 2015

    $ borg rename /mnt/backup::archivename newname
    $ borg list /mnt/backup
    newname                              Mon Nov  2 20:40:06 2015


.. include:: usage/delete.rst.inc

.. include:: usage/list.rst.inc

Examples
~~~~~~~~
::

    $ borg list /mnt/backup
    my-files            Thu Aug  1 23:33:22 2013
    my-documents        Thu Aug  1 23:35:43 2013
    root-2013-08-01     Thu Aug  1 23:43:55 2013
    root-2013-08-02     Fri Aug  2 15:18:17 2013
    ...

    $ borg list /mnt/backup::root-2013-08-02
    drwxr-xr-x root   root          0 Jun 05 12:06 .
    lrwxrwxrwx root   root          0 May 31 20:40 bin -> usr/bin
    drwxr-xr-x root   root          0 Aug 01 22:08 etc
    drwxr-xr-x root   root          0 Jul 15 22:07 etc/ImageMagick-6
    -rw-r--r-- root   root       1383 May 22 22:25 etc/ImageMagick-6/colors.xml
    ...


.. include:: usage/prune.rst.inc

Examples
~~~~~~~~

Be careful, prune is potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using `--prefix`.
When using --prefix, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run `prune --dry-run ...` first so you
will see what it would do without it actually doing anything.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune /mnt/backup --dry-run --keep-daily=7 --keep-weekly=4

    # Same as above but only apply to archive names starting with "foo":
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --prefix=foo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --keep-monthly=-1

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-within=10d --keep-weekly=4 --keep-monthly=-1


.. include:: usage/info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /mnt/backup::root-2013-08-02
    Name: root-2013-08-02
    Fingerprint: bc3902e2c79b6d25f5d769b335c5c49331e6537f324d8d3badcb9a0917536dbb
    Hostname: myhostname
    Username: root
    Time: Fri Aug  2 15:18:17 2013
    Command line: /usr/bin/borg create --stats -C zlib,6 /mnt/backup::root-2013-08-02 / --do-not-cross-mountpoints
    Number of files: 147429
    Original size: 5344169493 (4.98 GB)
    Compressed size: 1748189642 (1.63 GB)
    Unique data: 64805454 (61.80 MB)


.. include:: usage/mount.rst.inc

Examples
~~~~~~~~
::

    $ borg mount /mnt/backup::root-2013-08-02 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc  lib  lib64  mnt  opt  root  sbin  srv  usr  var
    $ fusermount -u /tmp/mymountpoint


.. include:: usage/change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg init --encryption=keyfile /mnt/backup
    Initializing repository at "/mnt/backup"
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again: 
    Key file "/home/USER/.borg/keys/mnt_backup" created.
    Keep this file safe. Your data will be inaccessible without it.

    # Change key file passphrase
    $ borg change-passphrase /mnt/backup
    Enter passphrase for key file /home/USER/.borg/keys/mnt_backup:
    New passphrase: 
    Enter same passphrase again: 
    Key file "/home/USER/.borg/keys/mnt_backup" updated


.. include:: usage/serve.rst.inc

Examples
~~~~~~~~
::

    # Allow an SSH keypair to only run |project_name|, and only have access to /mnt/backup.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /mnt/backup" ssh-rsa AAAAB3[...]


Miscellaneous Help
------------------

.. include:: usage/help.rst.inc


Debug Commands
--------------
There are some more commands (all starting with "debug-") wich are are all
**not intended for normal use** and **potentially very dangerous** if used incorrectly.

They exist to improve debugging capabilities without direct system access, e.g.
in case you ever run into some severe malfunction. Use them only if you know
what you are doing or if a trusted |project_name| developer tells you what to do.


Additional Notes
----------------

Here are misc. notes about topics that are maybe not covered in enough detail in the usage section.

Item flags
~~~~~~~~~~

`borg create --changed` outputs a verbose list of all files, directories and other
file system items it considered, with the exception of unchanged files
(for this, also add `--unchanged`). For each item, it prefixes a single-letter
flag that indicates type and/or status of the item.

A uppercase character represents the status of a regular file relative to the
"files" cache (not relative to the repo - this is an issue if the files cache
is not used). Metadata is stored in any case and for 'A' and 'M' also new data
chunks are stored. For 'U' all data chunks refer to already existing chunks.

- 'A' = regular file, added (see also :ref:`a_status_oddity` in the FAQ)
- 'M' = regular file, modified
- 'U' = regular file, unchanged (only if `--unchanged` is specified)
- 'E' = regular file, an error happened while accessing/reading *this* file

A lowercase character means a file type other than a regular file,
borg usually just stores their metadata:

- 'd' = directory
- 'b' = block device
- 'c' = char device
- 'h' = regular file, hardlink (to already seen inodes)
- 's' = symlink
- 'f' = fifo

Other flags used include:

- 'i' = backup data was read from standard input (stdin)
- '-' = dry run, item was *not* backed up
- '?' = missing status code (if you see this, please file a bug report!)


--chunker-params
~~~~~~~~~~~~~~~~
The chunker params influence how input files are cut into pieces (chunks)
which are then considered for deduplication. They also have a big impact on
resource usage (RAM and disk space) as the amount of resources needed is
(also) determined by the total amount of chunks in the repository (see
`Indexes / Caches memory usage` for details).

`--chunker-params=10,23,16,4095 (default)` results in a fine-grained deduplication
and creates a big amount of chunks and thus uses a lot of resources to manage them.
This is good for relatively small data volumes and if the machine has a good
amount of free RAM and disk space.

`--chunker-params=19,23,21,4095` results in a coarse-grained deduplication and
creates a much smaller amount of chunks and thus uses less resources.
This is good for relatively big data volumes and if the machine has a relatively
low amount of free RAM and disk space.

If you already have made some archives in a repository and you then change
chunker params, this of course impacts deduplication as the chunks will be
cut differently.

In the worst case (all files are big and were touched in between backups), this
will store all content into the repository again.

Usually, it is not that bad though:
- usually most files are not touched, so it will just re-use the old chunks
it already has in the repo
- files smaller than the (both old and new) minimum chunksize result in only
one chunk anyway, so the resulting chunks are same and deduplication will apply

If you switch chunker params to save resources for an existing repo that
already has some backup archives, you will see an increasing effect over time,
when more and more files have been touched and stored again using the bigger
chunksize **and** all references to the smaller older chunks have been removed
(by deleting / pruning archives).

If you want to see an immediate big effect on resource usage, you better start
a new repository when changing chunker params.

For more details, see :ref:`chunker_details`.

--read-special
~~~~~~~~~~~~~~

The option ``--read-special`` is not intended for normal, filesystem-level (full or
partly-recursive) backups. You only give this option if you want to do something
rather ... special -- and if you have hand-picked some files that you want to treat
that way.

``borg create --read-special`` will open all files without doing any special
treatment according to the file type (the only exception here are directories:
they will be recursed into). Just imagine what happens if you do ``cat
filename`` --- the content you will see there is what borg will backup for that
filename.

So, for example, symlinks will be followed, block device content will be read,
named pipes / UNIX domain sockets will be read.

You need to be careful with what you give as filename when using ``--read-special``,
e.g. if you give ``/dev/zero``, your backup will never terminate.

The given files' metadata is saved as it would be saved without
``--read-special`` (e.g. its name, its size [might be 0], its mode, etc.) - but
additionally, also the content read from it will be saved for it.

Restoring such files' content is currently only supported one at a time via
``--stdout`` option (and you have to redirect stdout to where ever it shall go,
maybe directly into an existing device file of your choice or indirectly via
``dd``).

Example
+++++++

Imagine you have made some snapshots of logical volumes (LVs) you want to backup.

.. note::

    For some scenarios, this is a good method to get "crash-like" consistency
    (I call it crash-like because it is the same as you would get if you just
    hit the reset button or your machine would abrubtly and completely crash).
    This is better than no consistency at all and a good method for some use
    cases, but likely not good enough if you have databases running.

Then you create a backup archive of all these snapshots. The backup process will
see a "frozen" state of the logical volumes, while the processes working in the
original volumes continue changing the data stored there.

You also add the output of ``lvdisplay`` to your backup, so you can see the LV
sizes in case you ever need to recreate and restore them.

After the backup has completed, you remove the snapshots again. ::

    $ # create snapshots here
    $ lvdisplay > lvdisplay.txt
    $ borg create --read-special /mnt/backup::repo lvdisplay.txt /dev/vg0/*-snapshot
    $ # remove snapshots here

Now, let's see how to restore some LVs from such a backup. ::

    $ borg extract /mnt/backup::repo lvdisplay.txt
    $ # create empty LVs with correct sizes here (look into lvdisplay.txt).
    $ # we assume that you created an empty root and home LV and overwrite it now:
    $ borg extract --stdout /mnt/backup::repo dev/vg0/root-snapshot > /dev/vg0/root
    $ borg extract --stdout /mnt/backup::repo dev/vg0/home-snapshot > /dev/vg0/home

