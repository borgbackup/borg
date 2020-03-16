Support for file metadata
~~~~~~~~~~~~~~~~~~~~~~~~~

Besides regular file and directory structures, Borg can preserve

* symlinks (stored as symlink, the symlink is not followed)
* special files:

  * character and block device files (restored via mknod)
  * FIFOs ("named pipes")
  * special file *contents* can be backed up in ``--read-special`` mode.
    By default the metadata to create them with mknod(2), mkfifo(2) etc. is stored.
* hardlinked regular files, devices, FIFOs (considering all items in the same archive)
* timestamps in nanosecond precision: mtime, atime, ctime
* other timestamps: birthtime (on platforms supporting it)
* permissions:

  * IDs of owning user and owning group
  * names of owning user and owning group (if the IDs can be resolved)
  * Unix Mode/Permissions (u/g/o permissions, suid, sgid, sticky)

On some platforms additional features are supported:

.. Yes/No's are grouped by reason/mechanism/reference.

+-------------------------+----------+-----------+------------+
| Platform                | ACLs     | xattr     | Flags      |
|                         | [#acls]_ | [#xattr]_ | [#flags]_  |
+=========================+==========+===========+============+
| Linux                   | Yes      | Yes       | Yes [1]_   |
+-------------------------+----------+-----------+------------+
| Mac OS X                | Yes      | Yes       | Yes (all)  |
+-------------------------+----------+-----------+------------+
| FreeBSD                 | Yes      | Yes       | Yes (all)  |
+-------------------------+----------+-----------+------------+
| OpenBSD                 | n/a      | n/a       | Yes (all)  |
+-------------------------+----------+-----------+------------+
| NetBSD                  | n/a      | No [2]_   | Yes (all)  |
+-------------------------+----------+-----------+------------+
| Solaris and derivatives | No [3]_  | No [3]_   | n/a        |
+-------------------------+----------+-----------+------------+
| Windows (cygwin)        | No [4]_  | No        | No         |
+-------------------------+----------+-----------+------------+

Other Unix-like operating systems may work as well, but have not been tested at all.

Note that most of the platform-dependent features also depend on the file system.
For example, ntfs-3g on Linux isn't able to convey NTFS ACLs.

.. [1] Only "nodump", "immutable", "compressed" and "append" are supported.
    Feature request :issue:`618` for more flags.
.. [2] Feature request :issue:`1332`
.. [3] Feature request :issue:`1337`
.. [4] Cygwin tries to map NTFS ACLs to permissions with varying degrees of success.

.. [#acls] The native access control list mechanism of the OS. This normally limits access to
    non-native ACLs. For example, NTFS ACLs aren't completely accessible on Linux with ntfs-3g.
.. [#xattr] extended attributes; key-value pairs attached to a file, mainly used by the OS.
    This includes resource forks on Mac OS X.
.. [#flags] aka *BSD flags*. The Linux set of flags [1]_ is portable across platforms.
    The BSDs define additional flags.
