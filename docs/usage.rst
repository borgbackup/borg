.. include:: global.rst.inc
.. _detailed_usage:

Usage
=====

|project_name| consists of a number of commands. Each command accepts
a number of arguments and options. The following sections will describe each
command in detail.

.. toctree::
   :maxdepth: 1

   usage/init
   usage/create
   usage/extract
   usage/check
   usage/rename
   usage/delete
   usage/list
   usage/prune
   usage/info
   usage/mount
   usage/change-passphrase
   usage/serve
   usage/upgrade
   usage/help

General
-------

Quiet by default
~~~~~~~~~~~~~~~~

Like most UNIX commands |project_name| is quiet by default but the ``-v`` or
``--verbose`` option can be used to get the program to output more status
messages as it is processing.

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

`borg create -v` outputs a verbose list of all files, directories and other
file system items it considered. For each item, it prefixes a single-letter
flag that indicates type and/or status of the item.

A uppercase character represents the status of a regular file relative to the
"files" cache (not relative to the repo - this is an issue if the files cache
is not used). Metadata is stored in any case and for 'A' and 'M' also new data
chunks are stored. For 'U' all data chunks refer to already existing chunks.

- 'A' = regular file, added
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
