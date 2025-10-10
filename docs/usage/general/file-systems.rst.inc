File systems
~~~~~~~~~~~~

We recommend using a reliable, scalable journaling filesystem for the
repository, e.g., zfs, btrfs, ext4, apfs.

Borg now uses the ``borgstore`` package to implement the key/value store it
uses for the repository.

It currently uses the ``file:`` store (posixfs backend) either with a local
directory or via SSH and a remote ``borg serve`` agent using borgstore on the
remote side.

This means that it will store each chunk into a separate filesystem file
(for more details, see the ``borgstore`` project).

This has some pros and cons (compared to legacy Borg 1.x segment files):

Pros:

- Simplicity and better maintainability of the Borg code.
- Sometimes faster, less I/O, better scalability: e.g., borg compact can just
  remove unused chunks by deleting a single file and does not need to read
  and rewrite segment files to free space.
- In the future, easier to adapt to other kinds of storage:
  borgstore's backends are quite simple to implement.
  ``sftp:`` and ``rclone:`` backends already exist, others might be easy to add.
- Parallel repository access with less locking is easier to implement.

Cons:

- The repository filesystem will have to deal with a large number of files (there
  are provisions in borgstore against having too many files in a single directory
  by using a nested directory structure).
- Greater filesystem space overhead (depends on the allocation block size — modern
  filesystems like zfs are rather clever here, using a variable block size).
- Sometimes slower, due to less sequential and more random access operations.
