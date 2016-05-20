.. _borg_create:

borg create
-----------
::

    usage: borg create [-h] [--critical] [--error] [--warning] [--info] [--debug]
                       [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH] [-s] [-p] [--list]
                       [--filter STATUSCHARS] [-e PATTERN]
                       [--exclude-from EXCLUDEFILE] [--exclude-caches]
                       [--exclude-if-present FILENAME] [--keep-tag-files]
                       [-c SECONDS] [-x] [--numeric-owner]
                       [--timestamp yyyy-mm-ddThh:mm:ss]
                       [--chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE]
                       [--ignore-inode] [-C COMPRESSION] [--read-special] [-n]
                       ARCHIVE PATH [PATH ...]
    
    Create new archive
    
    positional arguments:
      ARCHIVE               name of archive to create (must be also a valid
                            directory name)
      PATH                  paths to archive
    
    optional arguments:
      -h, --help            show this help message and exit
      --critical            work on log level CRITICAL
      --error               work on log level ERROR
      --warning             work on log level WARNING (default)
      --info, -v, --verbose
                            work on log level INFO
      --debug               work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -s, --stats           print statistics for the created archive
      -p, --progress        show progress display while creating the archive,
                            showing Original, Compressed and Deduplicated sizes,
                            followed by the Number of files seen and the path
                            being processed, default: False
      --list                output verbose list of items (files, dirs, ...)
      --filter STATUSCHARS  only display items with the given status characters
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      --exclude-from EXCLUDEFILE
                            read exclude patterns from EXCLUDEFILE, one per line
      --exclude-caches      exclude directories that contain a CACHEDIR.TAG file
                            (http://www.brynosaurus.com/cachedir/spec.html)
      --exclude-if-present FILENAME
                            exclude directories that contain the specified file
      --keep-tag-files      keep tag files of excluded caches/directories
      -c SECONDS, --checkpoint-interval SECONDS
                            write checkpoint every SECONDS seconds (Default: 300)
      -x, --one-file-system
                            stay in same file system, do not cross mount points
      --numeric-owner       only store numeric user and group identifiers
      --timestamp yyyy-mm-ddThh:mm:ss
                            manually specify the archive creation date/time (UTC).
                            alternatively, give a reference file/directory.
      --chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE
                            specify the chunker parameters. default: 19,23,21,4095
      --ignore-inode        ignore inode data in the file metadata cache used to
                            detect unchanged files.
      -C COMPRESSION, --compression COMPRESSION
                            select compression algorithm (and level): none == no
                            compression (default), lz4 == lz4, zlib == zlib
                            (default level 6), zlib,0 .. zlib,9 == zlib (with
                            level 0..9), lzma == lzma (default level 6), lzma,0 ..
                            lzma,9 == lzma (with level 0..9).
      --read-special        open and read special files as if they were regular
                            files
      -n, --dry-run         do not create a backup archive
    
Description
~~~~~~~~~~~

This command creates a backup archive containing all files found while recursively
traversing all paths specified. The archive will consume almost no disk space for
files or parts of files that have already been stored in other archives.

The archive name needs to be unique. It must not end in '.checkpoint' or
'.checkpoint.N' (with N being a number), because these names are used for
checkpoints and treated in special ways.

In the archive name, you may use the following format tags:
{now}, {utcnow}, {fqdn}, {hostname}, {user}, {pid}

To speed up pulling backups over sshfs and similar network file systems which do
not provide correct inode information the --ignore-inode flag can be used. This
potentially decreases reliability of change detection, while avoiding always reading
all files on these file systems.

See the output of the "borg help patterns" command for more help on exclude patterns.
