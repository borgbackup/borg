File systems
~~~~~~~~~~~~

We recommend using a reliable, scalable journaling filesystem for the
repository, e.g., zfs, btrfs, ext4, apfs.

Borg now uses the ``borgstore`` package to implement the key/value store it
uses for the repository.

For a local repository (or a locally mounted network filesystem) it uses the
``file:`` store (posixfs backend). For a remote repository it uses the ``rest:``
store, talking to a ``borg serve --rest`` process on the remote side (which in
turn uses borgstore there). Other backends (``sftp:``, ``rclone:``, ``s3:``/
``b2:``) do not need a filesystem on the repository side at all.

Borg does not store each chunk as a separate store object. It groups many chunks
into *pack files* of up to about 50 MB and stores each pack as one object; reading
a single chunk is a partial read at a known offset inside its pack. Thus, the
repository holds far fewer objects than it has chunks (see :ref:`packs` in the
Internals chapter for the details).

This has some pros and cons (compared to legacy Borg 1.x segment files):

Pros:

- Simplicity and better maintainability of the Borg code.
- The repository is just a key/value store, so it is easy to adapt to other kinds
  of storage: borgstore's backends are quite simple to implement.
  ``sftp:``, ``rclone:`` and ``s3:``/``b2:`` backends already exist, others might
  be easy to add.
- Parallel repository access with less locking is easier to implement.

Cons:

- Individual chunks cannot be deleted from a pack file; ``borg compact`` can only
  remove a pack once none of its chunks are referenced any more, so space is not
  always reclaimed immediately.
- Greater filesystem space overhead (depends on the allocation block size — modern
  filesystems like zfs are rather clever here, using a variable block size).
- Sometimes slower, due to less sequential and more random access operations.
