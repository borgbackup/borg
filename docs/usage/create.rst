.. include:: create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create my-documents ~/Documents

    # same, but list all files as we process them
    $ borg create --list my-documents ~/Documents

    # Backup /mnt/disk/docs, but strip path prefix using the slashdot hack
    $ borg create --repo /path/to/repo docs /mnt/disk/./docs

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create my-files                \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup home directories excluding image thumbnails (i.e. only
    # /home/<one directory>/.thumbnails is excluded, not /home/*/*/.thumbnails etc.)
    $ borg create my-files /home --exclude 'sh:home/*/.thumbnails'

    # Back up the root filesystem into an archive named "root-archive"
    # Use zlib compression (good, but slow) — default is LZ4 (fast, low compression ratio)
    $ borg create -C zlib,6 --one-file-system root-archive /

    # Backup into an archive name like FQDN-root
    $ borg create '{fqdn}-root' /

    # Back up a remote host locally ("pull" style) using SSHFS
    $ mkdir sshfs-mount
    $ sshfs root@example.com:/ sshfs-mount
    $ cd sshfs-mount
    $ borg create example.com-root .
    $ cd ..
    $ fusermount -u sshfs-mount

    # Make a big effort in fine-grained deduplication (big chunk management
    # overhead, needs a lot of RAM and disk space; see the formula in the internals docs):
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

    # Use the short hostname and username as the archive name
    $ borg create '{hostname}-{user}' ~

    # Back up relative paths by moving into the correct directory first
    $ cd /home/user/Documents
    # The root directory of the archive will be "projectA"
    $ borg create 'daily-projectA' projectA

    # Use external command to determine files to archive
    # Use --paths-from-stdin with find to back up only files less than 1 MB in size
    $ find ~ -size -1000k | borg create --paths-from-stdin small-files-only
    # Use --paths-from-command with find to back up files from only a given user
    $ borg create --paths-from-command joes-files -- find /srv/samba/shared -user joe
    # Use --paths-from-stdin with --paths-delimiter (for example, for filenames with newlines in them)
    $ find ~ -size -1000k -print0 | borg create \
        --paths-from-stdin \
        --paths-delimiter "\0" \
        smallfiles-handle-newline

