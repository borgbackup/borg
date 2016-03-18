.. _borg_recompress:

borg recompress
---------------
::

    usage: borg recompress [-h] [-v] [--debug] [--lock-wait N] [--show-version]
                           [--show-rc] [--no-files-cache] [--umask M]
                           [--remote-path PATH] [-f] [-s] [-p] [-C COMPRESSION]
                           [-n]
                           REPOSITORY
    
    Recompress data
    
    positional arguments:
      REPOSITORY            repository to recompress
    
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
      -f, --force           even recompress chunks already compressed with the
                            algorithm set with --compression
      -s, --stats           print statistics at end
      -p, --progress        show progress, one dot is printed for each processed
                            chunk
      -C COMPRESSION, --compression COMPRESSION
                            select compression algorithm (and level): none == no
                            compression (default), lz4 == lz4, zlib == zlib
                            (default level 6), zlib,0 .. zlib,9 == zlib (with
                            level 0..9), lzma == lzma (default level 6), lzma,0 ..
                            lzma,9 == lzma (with level 0..9).
      -n, --dry-run         do not write any data
    
Description
~~~~~~~~~~~

Recompress data in a repository.
