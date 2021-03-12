.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_create:

borg create
-----------
.. code-block:: none

    borg [common options] create [options] ARCHIVE [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                         |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``ARCHIVE``                                       | name of archive to create (must be also a valid directory name)                                                                                      |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                                          | paths to archive                                                                                                                                     |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-n``, ``--dry-run``                             | do not create a backup archive                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``                               | print statistics for the created archive                                                                                                             |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--list``                                        | output verbose list of items (files, dirs, ...)                                                                                                      |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--filter STATUSCHARS``                          | only display items with the given status characters (see description)                                                                                |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json``                                        | output stats as JSON. Implies ``--stats``.                                                                                                           |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--no-cache-sync``                               | experimental: do not synchronize the cache. Implies not using the files cache.                                                                       |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--no-files-cache``                              | do not load/update the file metadata cache used to detect unchanged files                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--stdin-name NAME``                             | use NAME in archive for stdin data (default: "stdin")                                                                                                |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--stdin-user USER``                             | set user USER in archive for stdin data (default: 'root')                                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--stdin-group GROUP``                           | set group GROUP in archive for stdin data (default: 'root')                                                                                          |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--stdin-mode M``                                | set mode to M in archive for stdin data (default: 0660)                                                                                              |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                   |
    |                                                                                                                                                                                                                                                                  |
    | :ref:`common_options`                                                                                                                                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Exclusion options**                                                                                                                                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN``             | exclude paths matching PATTERN                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``                    | read exclude patterns from EXCLUDEFILE, one per line                                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                             | experimental: include/exclude paths matching PATTERN                                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``                   | experimental: read include/exclude patterns from PATTERNFILE, one per line                                                                           |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-caches``                              | exclude directories that contain a CACHEDIR.TAG file (http://www.bford.info/cachedir/spec.html)                                                      |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-if-present NAME``                     | exclude directories that are tagged by containing a filesystem object with the given NAME                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--keep-exclude-tags``, ``--keep-tag-files``     | if tag objects are specified with ``--exclude-if-present``, don't omit the tag objects themselves from the backup archive                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-nodump``                              | exclude files flagged NODUMP                                                                                                                         |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Filesystem options**                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-x``, ``--one-file-system``                     | stay in the same file system and do not store mount points of other file systems.  This might behave different from your expectations, see the docs. |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--numeric-owner``                               | only store numeric user and group identifiers                                                                                                        |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noatime``                                     | do not store atime into archive                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noctime``                                     | do not store ctime into archive                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--nobirthtime``                                 | do not store birthtime (creation date) into archive                                                                                                  |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--nobsdflags``                                  | do not read and store bsdflags (e.g. NODUMP, IMMUTABLE) into archive                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noacls``                                      | do not read and store ACLs into archive                                                                                                              |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noxattrs``                                    | do not read and store xattrs into archive                                                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--ignore-inode``                                | ignore inode data in the file metadata cache used to detect unchanged files.                                                                         |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--files-cache MODE``                            | operate files cache in MODE. default: ctime,size,inode                                                                                               |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--read-special``                                | open and read block and char device files as well as FIFOs as if they were regular files. Also follows symlinks pointing to these kinds of files.    |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive options**                                                                                                                                                                                                                                              |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--comment COMMENT``                             | add a comment text to the archive                                                                                                                    |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--timestamp TIMESTAMP``                         | manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). Alternatively, give a reference file/directory.                   |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-c SECONDS``, ``--checkpoint-interval SECONDS`` | write checkpoint every SECONDS seconds (Default: 1800)                                                                                               |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--chunker-params PARAMS``                       | specify the chunker parameters (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE). default: 19,23,21,4095                              |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details.                                                     |
    +-------------------------------------------------------+---------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    ARCHIVE
        name of archive to create (must be also a valid directory name)
    PATH
        paths to archive


    optional arguments
        -n, --dry-run    do not create a backup archive
        -s, --stats     print statistics for the created archive
        --list          output verbose list of items (files, dirs, ...)
        --filter STATUSCHARS    only display items with the given status characters (see description)
        --json          output stats as JSON. Implies ``--stats``.
        --no-cache-sync    experimental: do not synchronize the cache. Implies not using the files cache.
        --no-files-cache    do not load/update the file metadata cache used to detect unchanged files
        --stdin-name NAME    use NAME in archive for stdin data (default: "stdin")
        --stdin-user USER    set user USER in archive for stdin data (default: 'root')
        --stdin-group GROUP    set group GROUP in archive for stdin data (default: 'root')
        --stdin-mode M    set mode to M in archive for stdin data (default: 0660)


    :ref:`common_options`
        |

    Exclusion options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 experimental: include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       experimental: read include/exclude patterns from PATTERNFILE, one per line
        --exclude-caches                  exclude directories that contain a CACHEDIR.TAG file (http://www.bford.info/cachedir/spec.html)
        --exclude-if-present NAME         exclude directories that are tagged by containing a filesystem object with the given NAME
        --keep-exclude-tags, --keep-tag-files    if tag objects are specified with ``--exclude-if-present``, don't omit the tag objects themselves from the backup archive
        --exclude-nodump                  exclude files flagged NODUMP


    Filesystem options
        -x, --one-file-system     stay in the same file system and do not store mount points of other file systems.  This might behave different from your expectations, see the docs.
        --numeric-owner           only store numeric user and group identifiers
        --noatime                 do not store atime into archive
        --noctime                 do not store ctime into archive
        --nobirthtime             do not store birthtime (creation date) into archive
        --nobsdflags              do not read and store bsdflags (e.g. NODUMP, IMMUTABLE) into archive
        --noacls                  do not read and store ACLs into archive
        --noxattrs                do not read and store xattrs into archive
        --ignore-inode            ignore inode data in the file metadata cache used to detect unchanged files.
        --files-cache MODE        operate files cache in MODE. default: ctime,size,inode
        --read-special            open and read block and char device files as well as FIFOs as if they were regular files. Also follows symlinks pointing to these kinds of files.


    Archive options
        --comment COMMENT                             add a comment text to the archive
        --timestamp TIMESTAMP                         manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). Alternatively, give a reference file/directory.
        -c SECONDS, --checkpoint-interval SECONDS     write checkpoint every SECONDS seconds (Default: 1800)
        --chunker-params PARAMS                       specify the chunker parameters (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE). default: 19,23,21,4095
        -C COMPRESSION, --compression COMPRESSION     select compression algorithm, see the output of the "borg help compression" command for details.


Description
~~~~~~~~~~~

This command creates a backup archive containing all files found while recursively
traversing all paths specified. Paths are added to the archive as they are given,
that means if relative paths are desired, the command has to be run from the correct
directory.

When giving '-' as path, borg will read data from standard input and create a
file 'stdin' in the created archive from that data. See section *Reading from
stdin* below for details.

The archive will consume almost no disk space for files or parts of files that
have already been stored in other archives.

The archive name needs to be unique. It must not end in '.checkpoint' or
'.checkpoint.N' (with N being a number), because these names are used for
checkpoints and treated in special ways.

In the archive name, you may use the following placeholders:
{now}, {utcnow}, {fqdn}, {hostname}, {user} and some others.

Backup speed is increased by not reprocessing files that are already part of
existing archives and weren't modified. The detection of unmodified files is
done by comparing multiple file metadata values with previous values kept in
the files cache.

This comparison can operate in different modes as given by ``--files-cache``:

- ctime,size,inode (default)
- mtime,size,inode (default behaviour of borg versions older than 1.1.0rc4)
- ctime,size (ignore the inode number)
- mtime,size (ignore the inode number)
- rechunk,ctime (all files are considered modified - rechunk, cache ctime)
- rechunk,mtime (all files are considered modified - rechunk, cache mtime)
- disabled (disable the files cache, all files considered modified - rechunk)

inode number: better safety, but often unstable on network filesystems

Normally, detecting file modifications will take inode information into
consideration to improve the reliability of file change detection.
This is problematic for files located on sshfs and similar network file
systems which do not provide stable inode numbers, such files will always
be considered modified. You can use modes without `inode` in this case to
improve performance, but reliability of change detection might be reduced.

ctime vs. mtime: safety vs. speed

- ctime is a rather safe way to detect changes to a file (metadata and contents)
  as it can not be set from userspace. But, a metadata-only change will already
  update the ctime, so there might be some unnecessary chunking/hashing even
  without content changes. Some filesystems do not support ctime (change time).
  E.g. doing a chown or chmod to a file will change its ctime.
- mtime usually works and only updates if file contents were changed. But mtime
  can be arbitrarily set from userspace, e.g. to set mtime back to the same value
  it had before a content change happened. This can be used maliciously as well as
  well-meant, but in both cases mtime based cache modes can be problematic.

The mount points of filesystems or filesystem snapshots should be the same for every
creation of a new archive to ensure fast operation. This is because the file cache that
is used to determine changed files quickly uses absolute filenames.
If this is not possible, consider creating a bind mount to a stable location.

The ``--progress`` option shows (from left to right) Original, Compressed and Deduplicated
(O, C and D, respectively), then the Number of files (N) processed so far, followed by
the currently processed path.

When using ``--stats``, you will get some statistics about how much data was
added - the "This Archive" deduplicated size there is most interesting as that is
how much your repository will grow. Please note that the "All archives" stats refer to
the state after creation. Also, the ``--stats`` and ``--dry-run`` options are mutually
exclusive because the data is not actually compressed and deduplicated during a dry run.

See the output of the "borg help patterns" command for more help on exclude patterns.

See the output of the "borg help placeholders" command for more help on placeholders.

.. man NOTES

The ``--exclude`` patterns are not like tar. In tar ``--exclude`` .bundler/gems will
exclude foo/.bundler/gems. In borg it will not, you need to use ``--exclude``
'\*/.bundler/gems' to get the same effect. See ``borg help patterns`` for
more information.

In addition to using ``--exclude`` patterns, it is possible to use
``--exclude-if-present`` to specify the name of a filesystem object (e.g. a file
or folder name) which, when contained within another folder, will prevent the
containing folder from being backed up.  By default, the containing folder and
all of its contents will be omitted from the backup.  If, however, you wish to
only include the objects specified by ``--exclude-if-present`` in your backup,
and not include any other contents of the containing folder, this can be enabled
through using the ``--keep-exclude-tags`` option.

The ``-x`` or ``--one-file-system`` option excludes directories, that are mountpoints (and everything in them).
It detects mountpoints by comparing the device number from the output of ``stat()`` of the directory and its
parent directory. Specifically, it excludes directories for which ``stat()`` reports a device number different
from the device number of their parent. Be aware that in Linux (and possibly elsewhere) there are directories
with device number different from their parent, which the kernel does not consider a mountpoint and also the
other way around. Examples are bind mounts (possibly same device number, but always a mountpoint) and ALL
subvolumes of a btrfs (different device number from parent but not necessarily a mountpoint). Therefore when
using ``--one-file-system``, one should make doubly sure that the backup works as intended especially when using
btrfs. This is even more important, if the btrfs layout was created by someone else, e.g. a distribution
installer.


.. _list_item_flags:

Item flags
++++++++++

``--list`` outputs a list of all files, directories and other
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
- 'x' = excluded, item was *not* backed up
- '?' = missing status code (if you see this, please file a bug report!)

Reading from stdin
++++++++++++++++++

To read from stdin, specify ``-`` as path and pipe directly to borg::

    backup-vm --id myvm --stdout | borg create REPO::ARCHIVE -

Note that piping to borg creates an archive even if the command piping
to borg exits with a failure. In this case, **one can end up with
truncated output being backed up**.

Reading from stdin yields just a stream of data without file metadata
associated with it, and the files cache is not needed at all. So it is
safe to disable it via ``--no-files-cache`` and speed up backup
creation a bit.

By default, the content read from stdin is stored in a file called 'stdin'.
Use ``--stdin-name`` to change the name.