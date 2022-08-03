.. include:: create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create my-documents ~/Documents

    # same, but list all files as we process them
    $ borg create --list my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create my-files                \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup home directories excluding image thumbnails (i.e. only
    # /home/<one directory>/.thumbnails is excluded, not /home/*/*/.thumbnails etc.)
    $ borg create my-files /home --exclude 'sh:home/*/.thumbnails'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    # use zlib compression (good, but slow) - default is lz4 (fast, low compression ratio)
    $ borg create -C zlib,6 --one-file-system root-{now:%Y-%m-%d} /

    # Backup into an archive name like FQDN-root-TIMESTAMP
    $ borg create '{fqdn}-root-{now}' /

    # Backup a remote host locally ("pull" style) using sshfs
    $ mkdir sshfs-mount
    $ sshfs root@example.com:/ sshfs-mount
    $ cd sshfs-mount
    $ borg create example.com-root-{now:%Y-%m-%d} .
    $ cd ..
    $ fusermount -u sshfs-mount

    # Make a big effort in fine granular deduplication (big chunk management
    # overhead, needs a lot of RAM and disk space, see formula in internals
    # docs - same parameters as borg < 1.0):
    $ borg create --chunker-params buzhash,10,23,16,4095 small /smallstuff

    # Backup a raw device (must not be active/in use/mounted at that time)
    $ borg create --read-special --chunker-params fixed,4194304 my-sdx /dev/sdX

    # Backup a sparse disk image (must not be active/in use/mounted at that time)
    $ borg create --sparse --chunker-params fixed,4194304 my-disk my-disk.raw

    # No compression (none)
    $ borg create --compression none arch ~

    # Super fast, low compression (lz4, default)
    $ borg create arch ~

    # Less fast, higher compression (zlib, N = 0..9)
    $ borg create --compression zlib,N arch ~

    # Even slower, even higher compression (lzma, N = 0..9)
    $ borg create --compression lzma,N arch ~

    # Only compress compressible data with lzma,N (N = 0..9)
    $ borg create --compression auto,lzma,N arch ~

    # Use short hostname, user name and current time in archive name
    $ borg create '{hostname}-{user}-{now}' ~
    # Similar, use the same datetime format that is default as of borg 1.1
    $ borg create '{hostname}-{user}-{now:%Y-%m-%dT%H:%M:%S}' ~
    # As above, but add nanoseconds
    $ borg create '{hostname}-{user}-{now:%Y-%m-%dT%H:%M:%S.%f}' ~

    # Backing up relative paths by moving into the correct directory first
    $ cd /home/user/Documents
    # The root directory of the archive will be "projectA"
    $ borg create 'daily-projectA-{now:%Y-%m-%d}' projectA

    # Use external command to determine files to archive
    # Use --paths-from-stdin with find to only backup files less than 1MB in size
    $ find ~ -size -1000k | borg create --paths-from-stdin small-files-only
    # Use --paths-from-command with find to only backup files from a given user
    $ borg create --paths-from-command joes-files -- find /srv/samba/shared -user joe
    # Use --paths-from-stdin with --paths-delimiter (for example, for filenames with newlines in them)
    $ find ~ -size -1000k -print0 | borg create \
        --paths-from-stdin \
        --paths-delimiter "\0" \
        smallfiles-handle-newline

