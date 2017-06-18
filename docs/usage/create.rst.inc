.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_create:

borg create
-----------
.. code-block:: none

    borg [common options] create [options] ARCHIVE PATH

positional arguments
    ARCHIVE
        name of archive to create (must be also a valid directory name)
    PATH
        paths to archive

optional arguments
    ``-n``, ``--dry-run``
        | do not create a backup archive
    ``-s``, ``--stats``
        | print statistics for the created archive
    ``--list``
        | output verbose list of items (files, dirs, ...)
    ``--filter STATUSCHARS``
        | only display items with the given status characters
    ``--json``
        | output stats as JSON (implies --stats)
    ``--no-cache-sync``
        | experimental: do not synchronize the cache. Implies --no-files-cache.

:ref:`common_options`
    |

Exclusion options
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line
    ``--exclude-caches``
        | exclude directories that contain a CACHEDIR.TAG file (http://www.brynosaurus.com/cachedir/spec.html)
    ``--exclude-if-present NAME``
        | exclude directories that are tagged by containing a filesystem object with the given NAME
    ``--keep-exclude-tags``, ``--keep-tag-files``
        | if tag objects are specified with --exclude-if-present, don't omit the tag objects themselves from the backup archive
    ``--pattern PATTERN``
        | experimental: include/exclude paths matching PATTERN
    ``--patterns-from PATTERNFILE``
        | experimental: read include/exclude patterns from PATTERNFILE, one per line

Filesystem options
    ``-x``, ``--one-file-system``
        | stay in the same file system and do not store mount points of other file systems
    ``--numeric-owner``
        | only store numeric user and group identifiers
    ``--noatime``
        | do not store atime into archive
    ``--noctime``
        | do not store ctime into archive
    ``--ignore-inode``
        | ignore inode data in the file metadata cache used to detect unchanged files.
    ``--read-special``
        | open and read block and char device files as well as FIFOs as if they were regular files. Also follows symlinks pointing to these kinds of files.

Archive options
    ``--comment COMMENT``
        | add a comment text to the archive
    ``--timestamp TIMESTAMP``
        | manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). alternatively, give a reference file/directory.
    ``-c SECONDS``, ``--checkpoint-interval SECONDS``
        | write checkpoint every SECONDS seconds (Default: 1800)
    ``--chunker-params PARAMS``
        | specify the chunker parameters (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE). default: 19,23,21,4095
    ``-C COMPRESSION``, ``--compression COMPRESSION``
        | select compression algorithm, see the output of the "borg help compression" command for details.

Description
~~~~~~~~~~~

This command creates a backup archive containing all files found while recursively
traversing all paths specified. Paths are added to the archive as they are given,
that means if relative paths are desired, the command has to be run from the correct
directory.

When giving '-' as path, borg will read data from standard input and create a
file 'stdin' in the created archive from that data.

The archive will consume almost no disk space for files or parts of files that
have already been stored in other archives.

The archive name needs to be unique. It must not end in '.checkpoint' or
'.checkpoint.N' (with N being a number), because these names are used for
checkpoints and treated in special ways.

In the archive name, you may use the following placeholders:
{now}, {utcnow}, {fqdn}, {hostname}, {user} and some others.

To speed up pulling backups over sshfs and similar network file systems which do
not provide correct inode information the ``--ignore-inode`` flag can be used. This
potentially decreases reliability of change detection, while avoiding always reading
all files on these file systems.

The mount points of filesystems or filesystem snapshots should be the same for every
creation of a new archive to ensure fast operation. This is because the file cache that
is used to determine changed files quickly uses absolute filenames.
If this is not possible, consider creating a bind mount to a stable location.

The ``--progress`` option shows (from left to right) Original, Compressed and Deduplicated
(O, C and D, respectively), then the Number of files (N) processed so far, followed by
the currently processed path.

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