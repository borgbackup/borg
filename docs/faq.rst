.. _faq:
.. include:: global.rst.inc

Frequently asked questions
==========================

Which platforms are supported?
    Currently Linux, FreeBSD and MacOS X are supported.

    You can try your luck on other POSIX-like systems, like Cygwin,
    other BSDs, etc. but they are not officially supported.

Can I backup VM disk images?
    Yes, the :ref:`deduplication <deduplication_def>` technique used by |project_name|
    makes sure only the modified parts of the file are stored.
    Also, we have optional simple sparse file support for extract.

Can I backup from multiple servers into a single repository?
    Yes, but in order for the deduplication used by |project_name| to work, it
    needs to keep a local cache containing checksums of all file
    chunks already stored in the repository. This cache is stored in
    ``~/.cache/borg/``.  If |project_name| detects that a repository has been
    modified since the local cache was updated it will need to rebuild
    the cache. This rebuild can be quite time consuming.

    So, yes it's possible. But it will be most efficient if a single
    repository is only modified from one place. Also keep in mind that
    |project_name| will keep an exclusive lock on the repository while creating
    or deleting archives, which may make *simultaneous* backups fail.

Which file types, attributes, etc. are preserved?
    * Directories
    * Regular files
    * Hardlinks (considering all files in the same archive)
    * Symlinks (stored as symlink, the symlink is not followed)
    * Character and block device files
    * FIFOs ("named pipes")
    * Name
    * Contents
    * Time of last modification (nanosecond precision with Python >= 3.3)
    * User ID of owner
    * Group ID of owner
    * Unix Mode/Permissions (u/g/o permissions, suid, sgid, sticky)
    * Extended Attributes (xattrs)
    * Access Control Lists (ACL_) on Linux, OS X and FreeBSD
    * BSD flags on OS X and FreeBSD

Which file types, attributes, etc. are *not* preserved?
    * UNIX domain sockets (because it does not make sense - they are meaningless
      without the running process that created them and the process needs to
      recreate them in any case). So, don't panic if your backup misses a UDS!
    * The precise on-disk representation of the holes in a sparse file.
      Archive creation has no special support for sparse files, holes are
      backed up as (deduplicated and compressed) runs of zero bytes.
      Archive extraction has optional support to extract all-zero chunks as
      holes in a sparse file.

How can I specify the encryption passphrase programmatically?
    The encryption passphrase can be specified programmatically using the
    `BORG_PASSPHRASE` environment variable. This is convenient when setting up
    automated encrypted backups. Another option is to use
    key file based encryption with a blank passphrase. See
    :ref:`encrypted_repos` for more details.

When backing up to remote encrypted repos, is encryption done locally?
    Yes, file and directory metadata and data is locally encrypted, before
    leaving the local machine. We do not mean the transport layer encryption
    by that, but the data/metadata itself. Transport layer encryption (e.g.
    when ssh is used as a transport) applies additionally.

When backing up to remote servers, do I have to trust the remote server?
    Yes and No.
    No, as far as data confidentiality is concerned - all your files/dirs data
    and metadata are stored in their encrypted form into the repository.
    Yes, as an attacker with access to the remote server could delete (or
    otherwise make unavailable) all your backups.

If a backup stops mid-way, does the already-backed-up data stay there? I.e. does |project_name| resume backups?
    Yes, during a backup a special checkpoint archive named ``<archive-name>.checkpoint`` is saved every 5 minutes
    containing all the data backed-up until that point. This means that at most 5 minutes worth of data needs to be
    retransmitted if a backup needs to be restarted.

If it crashes with a UnicodeError, what can I do?
    Check if your encoding is set correctly. For most POSIX-like systems, try::

        export LANG=en_US.UTF-8  # or similar, important is correct charset

If I want to run |project_name| on a ARM CPU older than ARM v6?
    You need to enable the alignment trap handler to fixup misaligned accesses::
    
        echo "2" > /proc/cpu/alignment

Why was Borg forked from Attic?
    Borg was created in May 2015 in response to the difficulty of
    getting new code or larger changes incorporated into Attic and
    establishing a bigger developer community / more open development.

    More details can be found in `ticket 217
    <https://github.com/jborg/attic/issues/217>`_ that led to the fork.

    Borg intends to be:

    * simple:

      * as simple as possible, but no simpler
      * do the right thing by default, but offer options
    * open:

      * welcome feature requests
      * accept pull requests of good quality and coding style
      * give feedback on PRs that can't be accepted "as is"
      * discuss openly, don't work in the dark
    * changing:

      * Borg is not compatible with Attic
      * do not break compatibility accidentally, without a good reason
        or without warning. allow compatibility breaking for other cases.
      * if major version number changes, it may have incompatible changes
