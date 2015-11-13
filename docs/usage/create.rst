.. _borg_create:

borg create
-----------

Create new archive

Synopsis
~~~~~~~~

::

    borg create [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH] [-s] [-p] [-e PATTERN]
                       [--exclude-from EXCLUDEFILE] [--exclude-caches]
                       [--exclude-if-present FILENAME] [--keep-tag-files]
                       [-c SECONDS] [-x] [--numeric-owner]
                       [--timestamp yyyy-mm-ddThh:mm:ss]
                       [--chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE]
                       [-C COMPRESSION] [--read-special] [-n]
                       ARCHIVE PATH [PATH ...]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~

::
      
    
      ARCHIVE               name of archive to create (must be also a valid
                            directory name)
      PATH                  paths to archive
    
optional arguments
~~~~~~~~~~~~~~~~~~

::
      
    
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      -s, --stats           print statistics for the created archive
      -p, --progress        toggle progress display while creating the archive,
                            showing Original, Compressed and Deduplicated sizes,
                            followed by the Number of files seen and the path
                            being processed, default: True
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
                            specify the chunker parameters. default: 10,23,16,4095
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

See the output of the "borg help patterns" command for more help on exclude patterns.

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
