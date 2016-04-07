.. _borg_recreate:

borg recreate
-------------
::

    usage: borg recreate [-h] [-v] [--debug] [--lock-wait N] [--show-version]
                         [--show-rc] [--no-files-cache] [--umask M]
                         [--remote-path PATH] [--list] [--filter STATUSCHARS] [-p]
                         [-n] [-s] [-e PATTERN] [--exclude-from EXCLUDEFILE]
                         [--exclude-caches] [--exclude-if-present FILENAME]
                         [--keep-tag-files] [-C COMPRESSION]
                         [--chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE]
                         [REPOSITORY_OR_ARCHIVE] [PATH [PATH ...]]
    
    Re-create archives
    
    positional arguments:
      REPOSITORY_OR_ARCHIVE
                            repository/archive to recreate
      PATH                  paths to recreate; patterns are supported
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose, --info
                            enable informative (verbose) output, work on log level
                            INFO
      --debug               enable debug output, work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-version        show/log the borg version
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      --list                output verbose list of items (files, dirs, ...)
      --filter STATUSCHARS  only display items with the given status characters
      -p, --progress        show progress display while rewriting archives
      -n, --dry-run         do not change anything
      -s, --stats           print statistics at end
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      --exclude-from EXCLUDEFILE
                            read exclude patterns from EXCLUDEFILE, one per line
      --exclude-caches      exclude directories that contain a CACHEDIR.TAG file
                            (http://www.brynosaurus.com/cachedir/spec.html)
      --exclude-if-present FILENAME
                            exclude directories that contain the specified file
      --keep-tag-files      keep tag files of excluded caches/directories
      -C COMPRESSION, --compression COMPRESSION
                            select compression algorithm (and level): none == no
                            compression (default), lz4 == lz4, zlib == zlib
                            (default level 6), zlib,0 .. zlib,9 == zlib (with
                            level 0..9), lzma == lzma (default level 6), lzma,0 ..
                            lzma,9 == lzma (with level 0..9).
      --chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE
                            specify the chunker parameters (or "default").
    
Description
~~~~~~~~~~~

Recreate the contents of existing archives.

--exclude, --exclude-from and PATH have the exact same semantics
as in "borg create". If a PATH is specified the resulting archive
will only contain files under PATH.

--compression: all chunks seen will be stored using the given method.
Due to how Borg stores compressed size information this might display
incorrect information for archives that were not rewritten at the same time.
There is no risk of data loss by this.

--chunker-params will re-chunk all files in the archive, this can be
used to have upgraded Borg 0.xx or Attic archives deduplicate with
Borg 1.x archives.

borg recreate is signal safe. Send either SIGINT (Ctrl-C on most terminals) or
SIGTERM to request termination.

Use the *exact same* command line to resume the operation later - changing excludes
or paths will lead to inconsistencies (changed excludes will only apply to newly
processed files/dirs). Changing compression leads to incorrect size information
(which does not cause any data loss, but can be misleading).
Changing chunker params between invocations might lead to data loss.

USE WITH CAUTION.
Permanent data loss by specifying incorrect patterns or PATHS is possible.
When in doubt, use "--dry-run --verbose --list" to see how patterns/PATHS are
interpreted.

The archive being recreated is only removed after the operation completes. The
archive that is built during the operation exists at the same time at
"<ARCHIVE>.recreate". The new archive will have a different archive ID.

When rechunking space usage can be substantial, expect at least the entire
deduplicated size of the archives using the older chunker params.
When recompressing approximately 1 % of the repository size or 512 MB
(whichever is greater) of additional space is used.
