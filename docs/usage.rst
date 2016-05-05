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

The log level of the builtin logging configuration defaults to WARNING.
This is because we want |project_name| to be mostly silent and only output
warnings, errors and critical messages.

Log levels: DEBUG < INFO < WARNING < ERROR < CRITICAL

Use ``--debug`` to set DEBUG log level -
to get debug, info, warning, error and critical level output.

Use ``--info`` (or ``-v`` or ``--verbose``) to set INFO log level -
to get info, warning, error and critical level output.

Use ``--warning`` (default) to set WARNING log level -
to get warning, error and critical level output.

Use ``--error`` to set ERROR log level -
to get error and critical level output.

Use ``--critical`` to set CRITICAL log level -
to get critical level output.

While you can set misc. log levels, do not expect that every command will
give different output on different log levels - it's just a possibility.

.. warning:: Options --critical and --error are provided for completeness,
             their usage is not recommended as you might miss important information.

.. warning:: While some options (like ``--stats`` or ``--list``) will emit more
             informational messages, you have to use INFO (or lower) log level to make
             them show up in log output. Use ``-v`` or a logging configuration.

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

If you use ``--show-rc``, the return code is also logged at the indicated
level as the last log entry.


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
    BORG_DISPLAY_PASSPHRASE
        When set, use the value to answer the "display the passphrase for verification" question when defining a new passphrase for encrypted repositories.
    BORG_LOGGING_CONF
        When set, use the given filename as INI_-style logging configuration.
    BORG_RSH
        When set, use this command instead of ``ssh``. This can be used to specify ssh options, such as
        a custom identity file ``ssh -i /path/to/private/key``. See ``man ssh`` for other options.
    TMPDIR
        where temporary files are stored (might need a lot of temporary space for some operations)

Some automatic "answerers" (if set, they automatically answer confirmation questions):
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no (or =yes)
        For "Warning: Attempting to access a previously unknown unencrypted repository"
    BORG_RELOCATED_REPO_ACCESS_IS_OK=no (or =yes)
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
        For "Warning: 'check --repair' is an experimental feature that might result in data loss."
    BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
        For "You requested to completely DELETE the repository *including* all archives it contains:"

    Note: answers are case sensitive. setting an invalid answer value might either give the default
    answer or ask you interactively, depending on whether retries are allowed (they by default are
    allowed). So please test your scripts interactively before making them a non-interactive script.

Directories:
    BORG_KEYS_DIR
        Default to '~/.config/borg/keys'. This directory contains keys for encrypted repositories.
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


.. _INI: https://docs.python.org/3.4/library/logging.config.html#configuration-file-format

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
    Proportional to the amount of data chunks in your repo. Lots of chunks
    in your repo imply a big chunks index.
    It is possible to tweak the chunker params (see create options).

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

We format date and time conforming to ISO-8601, that is: YYYY-MM-DD and
HH:MM:SS (24h clock).

For more information about that, see: https://xkcd.com/1179/

Unless otherwise noted, we display local date and time.
Internally, we store and process date and time as UTC.


.. include:: usage/init.rst.inc

Examples
~~~~~~~~
::

    # Local repository (default is to use encryption in repokey mode)
    $ borg init /path/to/repo

    # Local repository (no encryption)
    $ borg init --encryption=none /path/to/repo

    # Remote repository (accesses a remote borg via ssh)
    $ borg init user@hostname:backup

    # Remote repository (store the key your home dir)
    $ borg init --encryption=keyfile user@hostname:backup

Important notes about encryption:

It is not recommended to disable encryption. Repository encryption protects you
e.g. against the case that an attacker has access to your backup repository.

But be careful with the key / the passphrase:

If you want "passphrase-only" security, use the ``repokey`` mode. The key will
be stored inside the repository (in its "config" file). In above mentioned
attack scenario, the attacker will have the key (but not the passphrase).

If you want "passphrase and having-the-key" security, use the ``keyfile`` mode.
The key will be stored in your home directory (in ``.config/borg/keys``). In
the attack scenario, the attacker who has just access to your repo won't have
the key (and also not the passphrase).

Make a backup copy of the key file (``keyfile`` mode) or repo config file
(``repokey`` mode) and keep it at a safe place, so you still have the key in
case it gets corrupted or lost. Also keep the passphrase at a safe place.
The backup that is encrypted with that key won't help you with that, of course.

Make sure you use a good passphrase. Not too short, not too simple. The real
encryption / decryption key is encrypted with / locked by your passphrase.
If an attacker gets your key, he can't unlock and use it without knowing the
passphrase.

Be careful with special or non-ascii characters in your passphrase:

- |project_name| processes the passphrase as unicode (and encodes it as utf-8),
  so it does not have problems dealing with even the strangest characters.
- BUT: that does not necessarily apply to your OS / VM / keyboard configuration.

So better use a long passphrase made from simple ascii chars than one that
includes non-ascii stuff or characters that are hard/impossible to enter on
a different keyboard layout.

You can change your passphrase for existing repos at any time, it won't affect
the encryption/decryption key or other secrets.


.. include:: usage/create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create /path/to/repo::my-documents ~/Documents

    # same, but verbosely list all files as we process them
    $ borg create -v --list /path/to/repo::my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create /path/to/repo::my-files \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup home directories excluding image thumbnails (i.e. only
    # /home/*/.thumbnails is excluded, not /home/*/*/.thumbnails)
    $ borg create /path/to/repo::my-files /home \
        --exclude 're:^/home/[^/]+/\.thumbnails/'

    # Do the same using a shell-style pattern
    $ borg create /path/to/repo::my-files /home \
        --exclude 'sh:/home/*/.thumbnails'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    # use zlib compression (good, but slow) - default is no compression
    $ borg create -C zlib,6 /path/to/repo::root-{now:%Y-%m-%d} / --one-file-system

    # Make a big effort in fine granular deduplication (big chunk management
    # overhead, needs a lot of RAM and disk space, see formula in internals
    # docs - same parameters as borg < 1.0 or attic):
    $ borg create --chunker-params 10,23,16,4095 /path/to/repo::small /smallstuff

    # Backup a raw device (must not be active/in use/mounted at that time)
    $ dd if=/dev/sdx bs=10M | borg create /path/to/repo::my-sdx -

    # No compression (default)
    $ borg create /path/to/repo::arch ~

    # Super fast, low compression
    $ borg create --compression lz4 /path/to/repo::arch ~

    # Less fast, higher compression (N = 0..9)
    $ borg create --compression zlib,N /path/to/repo::arch ~

    # Even slower, even higher compression (N = 0..9)
    $ borg create --compression lzma,N /path/to/repo::arch ~

    # Use short hostname, user name and current time in archive name
    $ borg create /path/to/repo::{hostname}-{user}-{now} ~
    $ borg create /path/to/repo::{hostname}-{user}-{now:%Y-%m-%d_%H:%M:%S} ~

.. include:: usage/extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract /path/to/repo::my-files

    # Extract entire archive and list files while processing
    $ borg extract -v --list /path/to/repo::my-files

    # Extract the "src" directory
    $ borg extract /path/to/repo::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract /path/to/repo::my-files home/USERNAME/src --exclude '*.o'

    # Restore a raw device (must not be active/in use/mounted at that time)
    $ borg extract --stdout /path/to/repo::my-sdx | dd of=/dev/sdx bs=10M

Note: currently, extract always writes into the current working directory ("."),
      so make sure you ``cd`` to the right place before calling ``borg extract``.

.. include:: usage/check.rst.inc

.. include:: usage/rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create /path/to/repo::archivename ~
    $ borg list /path/to/repo
    archivename                          Mon, 2016-02-15 19:50:19

    $ borg rename /path/to/repo::archivename newname
    $ borg list /path/to/repo
    newname                              Mon, 2016-02-15 19:50:19


.. include:: usage/list.rst.inc

Examples
~~~~~~~~
::

    $ borg list /path/to/repo
    Monday                               Mon, 2016-02-15 19:15:11
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    ...

    $ borg list /path/to/repo::root-2016-02-15
    drwxr-xr-x root   root          0 Mon, 2016-02-15 17:44:27 .
    drwxrwxr-x root   root          0 Mon, 2016-02-15 19:04:49 bin
    -rwxr-xr-x root   root    1029624 Thu, 2014-11-13 00:08:51 bin/bash
    lrwxrwxrwx root   root          0 Fri, 2015-03-27 20:24:26 bin/bzcmp -> bzdiff
    -rwxr-xr-x root   root       2140 Fri, 2015-03-27 20:24:22 bin/bzdiff
    ...

    $ borg list /path/to/repo::archiveA --list-format="{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}"
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 .
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code/myproject
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.ext
    ...

    # see what is changed between archives, based on file modification time, size and file path
    $ borg list /path/to/repo::archiveA --list-format="{mtime:%s}{TAB}{size}{TAB}{path}{LF}" |sort -n > /tmp/list.archiveA
    $ borg list /path/to/repo::archiveB --list-format="{mtime:%s}{TAB}{size}{TAB}{path}{LF}" |sort -n > /tmp/list.archiveB
    $ diff -y /tmp/list.archiveA /tmp/list.archiveB
    1422781200      0       .                                       1422781200      0       .
    1422781200      0       code                                    1422781200      0       code
    1422781200      0       code/myproject                          1422781200      0       code/myproject
    1422781200      1416192 code/myproject/file.ext               | 1454664653      1416192 code/myproject/file.ext
    ...


.. include:: usage/delete.rst.inc

Examples
~~~~~~~~
::

    # delete a single backup archive:
    $ borg delete /path/to/repo::Monday

    # delete the whole repository and the related local cache:
    $ borg delete /path/to/repo
    You requested to completely DELETE the repository *including* all archives it contains:
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    Type 'YES' if you understand this and want to continue: YES


.. include:: usage/prune.rst.inc

Examples
~~~~~~~~

Be careful, prune is a potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using ``--prefix``.
When using ``--prefix``, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run ``prune --dry-run ...`` first so you
will see what it would do without it actually doing anything.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune --dry-run --keep-daily=7 --keep-weekly=4 /path/to/repo

    # Same as above but only apply to archive names starting with "foo":
    $ borg prune --keep-daily=7 --keep-weekly=4 --prefix=foo /path/to/repo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune --keep-daily=7 --keep-weekly=4 --keep-monthly=-1 /path/to/repo

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune --keep-within=10d --keep-weekly=4 --keep-monthly=-1 /path/to/repo


.. include:: usage/info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /path/to/repo::root-2016-02-15
    Name: root-2016-02-15
    Fingerprint: 57c827621f21b000a8d363c1e163cc55983822b3afff3a96df595077a660be50
    Hostname: myhostname
    Username: root
    Time (start): Mon, 2016-02-15 19:36:29
    Time (end):   Mon, 2016-02-15 19:39:26
    Command line: /usr/local/bin/borg create -v --list -C zlib,6 /path/to/repo::root-2016-02-15 / --one-file-system
    Number of files: 38100

                           Original size      Compressed size    Deduplicated size
    This archive:                1.33 GB            613.25 MB            571.64 MB
    All archives:                1.63 GB            853.66 MB            584.12 MB

                           Unique chunks         Total chunks
    Chunk index:                   36858                48844


.. include:: usage/mount.rst.inc

Examples
~~~~~~~~
::

    $ borg mount /path/to/repo::root-2016-02-15 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt  root  sbin  srv  tmp  usr  var
    $ fusermount -u /tmp/mymountpoint


.. include:: usage/change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg init --encryption=keyfile -v /path/to/repo
    Initializing repository at "/path/to/repo"
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key in "/root/.config/borg/keys/mnt_backup" created.
    Keep this key safe. Your data will be inaccessible without it.
    Synchronizing chunks cache...
    Archives: 0, w/ cached Idx: 0, w/ outdated Idx: 0, w/o cached Idx: 0.
    Done.

    # Change key file passphrase
    $ borg change-passphrase -v /path/to/repo
    Enter passphrase for key /root/.config/borg/keys/mnt_backup:
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key updated


.. include:: usage/serve.rst.inc

Examples
~~~~~~~~

borg serve has special support for ssh forced commands (see ``authorized_keys``
example below): it will detect that you use such a forced command and extract
the value of the ``--restrict-to-path`` option(s).
It will then parse the original command that came from the client, makes sure
that it is also ``borg serve`` and enforce path restriction(s) as given by the
forced command. That way, other options given by the client (like ``--info`` or
``--umask``) are preserved (and are not fixed by the forced command).

::

    # Allow an SSH keypair to only run borg, and only have access to /path/to/repo.
    # Use key options to disable unneeded and potentially dangerous SSH functionality.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /path/to/repo",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ssh-rsa AAAAB3[...]


.. include:: usage/upgrade.rst.inc

Examples
~~~~~~~~
::

    # Upgrade the borg repository to the most recent version.
    $ borg upgrade -v /path/to/repo
    making a hardlink copy in /path/to/repo.upgrade-2016-02-15-20:51:55
    opening attic repository with borg and converting
    no key file found for repository
    converting repo index /path/to/repo/index.0
    converting 1 segments...
    converting borg 0.xx to borg current
    no key file found for repository


.. include:: usage/break-lock.rst.inc


Miscellaneous Help
------------------

.. include:: usage/help.rst.inc


Debug Commands
--------------
There are some more commands (all starting with "debug-") which are all
**not intended for normal use** and **potentially very dangerous** if used incorrectly.

They exist to improve debugging capabilities without direct system access, e.g.
in case you ever run into some severe malfunction. Use them only if you know
what you are doing or if a trusted |project_name| developer tells you what to do.


Additional Notes
----------------

Here are misc. notes about topics that are maybe not covered in enough detail in the usage section.

Item flags
~~~~~~~~~~

``borg create -v --list`` outputs a verbose list of all files, directories and other
file system items it considered (no matter whether they had content changes
or not). For each item, it prefixes a single-letter flag that indicates type
and/or status of the item.

If you are interested only in a subset of that output, you can give e.g.
``--filter=AME`` and it will only show regular files with A, M or E status (see
below).

A uppercase character represents the status of a regular file relative to the
"files" cache (not relative to the repo -- this is an issue if the files cache
is not used). Metadata is stored in any case and for 'A' and 'M' also new data
chunks are stored. For 'U' all data chunks refer to already existing chunks.

- 'A' = regular file, added (see also :ref:`a_status_oddity` in the FAQ)
- 'M' = regular file, modified
- 'U' = regular file, unchanged
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

``--chunker-params=10,23,16,4095`` results in a fine-grained deduplication
and creates a big amount of chunks and thus uses a lot of resources to manage
them. This is good for relatively small data volumes and if the machine has a
good amount of free RAM and disk space.

``--chunker-params=19,23,21,4095`` (default) results in a coarse-grained
deduplication and creates a much smaller amount of chunks and thus uses less
resources. This is good for relatively big data volumes and if the machine has
a relatively low amount of free RAM and disk space.

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
``--read-special`` (e.g. its name, its size [might be 0], its mode, etc.) -- but
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
    $ borg create --read-special /path/to/repo::arch lvdisplay.txt /dev/vg0/*-snapshot
    $ # remove snapshots here

Now, let's see how to restore some LVs from such a backup. ::

    $ borg extract /path/to/repo::arch lvdisplay.txt
    $ # create empty LVs with correct sizes here (look into lvdisplay.txt).
    $ # we assume that you created an empty root and home LV and overwrite it now:
    $ borg extract --stdout /path/to/repo::arch dev/vg0/root-snapshot > /dev/vg0/root
    $ borg extract --stdout /path/to/repo::arch dev/vg0/home-snapshot > /dev/vg0/home


Append-only mode
~~~~~~~~~~~~~~~~

A repository can be made "append-only", which means that Borg will never overwrite or
delete committed data. This is useful for scenarios where multiple machines back up to
a central backup server using ``borg serve``, since a hacked machine cannot delete
backups permanently.

To activate append-only mode, edit the repository ``config`` file and add a line
``append_only=1`` to the ``[repository]`` section (or edit the line if it exists).

In append-only mode Borg will create a transaction log in the ``transactions`` file,
where each line is a transaction and a UTC timestamp.

Example
+++++++

Suppose an attacker remotely deleted all backups, but your repository was in append-only
mode. A transaction log in this situation might look like this: ::

    transaction 1, UTC time 2016-03-31T15:53:27.383532
    transaction 5, UTC time 2016-03-31T15:53:52.588922
    transaction 11, UTC time 2016-03-31T15:54:23.887256
    transaction 12, UTC time 2016-03-31T15:55:54.022540
    transaction 13, UTC time 2016-03-31T15:55:55.472564

From your security logs you conclude the attacker gained access at 15:54:00 and all
the backups where deleted or replaced by compromised backups. From the log you know
that transactions 11 and later are compromised. Note that the transaction ID is the
name of the *last* file in the transaction. For example, transaction 11 spans files 6
to 11.

In a real attack you'll likely want to keep the compromised repository
intact to analyze what the attacker tried to achieve. It's also a good idea to make this
copy just in case something goes wrong during the recovery. Since recovery is done by
deleting some files, a hard link copy (``cp -al``) is sufficient.

The first step to reset the repository to transaction 5, the last uncompromised transaction,
is to remove the ``hints.N`` and ``index.N`` files in the repository (these two files are
always expendable). In this example N is 13.

Then remove or move all segment files from the segment directories in ``data/`` starting
with file 6::

    rm data/**/{6..13}

That's all to it.

Drawbacks
+++++++++

As data is only appended, and nothing deleted, commands like ``prune`` or ``delete``
won't free disk space, they merely tag data as deleted in a new transaction.

Note that you can go back-and-forth between normal and append-only operation by editing
the configuration file, it's not a "one way trip".

Further considerations
++++++++++++++++++++++

Append-only mode is not respected by tools other than Borg. ``rm`` still works on the
repository. Make sure that backup client machines only get to access the repository via
``borg serve``.

Ensure that no remote access is possible if the repository is temporarily set to normal mode
for e.g. regular pruning.

Further protections can be implemented, but are outside of Borgs scope. For example,
file system snapshots or wrapping ``borg serve`` to set special permissions or ACLs on
new data files.
