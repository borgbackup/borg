.. include:: global.rst.inc
.. highlight:: none
.. _faq:

Frequently asked questions
==========================

Can I backup VM disk images?
----------------------------

Yes, the `deduplication`_ technique used by
|project_name| makes sure only the modified parts of the file are stored.
Also, we have optional simple sparse file support for extract.

If you use non-snapshotting backup tools like Borg to back up virtual machines,
then these should be turned off for doing so. Backing up live VMs this way can (and will)
result in corrupted or inconsistent backup contents: a VM image is just a regular file to
Borg with the same issues as regular files when it comes to concurrent reading and writing from
the same file.

For backing up live VMs use file system snapshots on the VM host, which establishes
crash-consistency for the VM images. This means that with most file systems
(that are journaling) the FS will always be fine in the backup (but may need a
journal replay to become accessible).

Usually this does not mean that file *contents* on the VM are consistent, since file
contents are normally not journaled. Notable exceptions are ext4 in data=journal mode,
ZFS and btrfs (unless nodatacow is used).

Applications designed with crash-consistency in mind (most relational databases
like PostgreSQL, SQLite etc. but also for example Borg repositories) should always
be able to recover to a consistent state from a backup created with
crash-consistent snapshots (even on ext4 with data=writeback or XFS).

Hypervisor snapshots capturing most of the VM's state can also be used for backups
and can be a better alternative to pure file system based snapshots of the VM's disk,
since no state is lost. Depending on the application this can be the easiest and most
reliable way to create application-consistent backups.

Other applications may require a lot of work to reach application-consistency:
It's a broad and complex issue that cannot be explained in entirety here.

Borg doesn't intend to address these issues due to their huge complexity
and platform/software dependency. Combining Borg with the mechanisms provided
by the platform (snapshots, hypervisor features) will be the best approach
to start tackling them.

Can I backup from multiple servers into a single repository?
------------------------------------------------------------

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

Can I copy or synchronize my repo to another location?
------------------------------------------------------

Yes, you could just copy all the files. Make sure you do that while no
backup is running. So what you get here is this:

- client machine ---borg create---> repo1
- repo1 ---copy---> repo2

There is no special borg command to do the copying, just use cp or rsync if
you want to do that.

But think about whether that is really what you want. If something goes
wrong in repo1, you will have the same issue in repo2 after the copy.

If you want to have 2 independent backups, it is better to do it like this:

- client machine ---borg create---> repo1
- client machine ---borg create---> repo2

Which file types, attributes, etc. are *not* preserved?
-------------------------------------------------------

    * UNIX domain sockets (because it does not make sense - they are
      meaningless without the running process that created them and the process
      needs to recreate them in any case). So, don't panic if your backup
      misses a UDS!
    * The precise on-disk (or rather: not-on-disk) representation of the holes
      in a sparse file.
      Archive creation has no special support for sparse files, holes are
      backed up as (deduplicated and compressed) runs of zero bytes.
      Archive extraction has optional support to extract all-zero chunks as
      holes in a sparse file.
    * filesystem specific attributes, like ext4 immutable bit, see :issue:`618`.

Are there other known limitations?
----------------------------------

- A single archive can only reference a limited volume of file/dir metadata,
  usually corresponding to tens or hundreds of millions of files/dirs.
  When trying to go beyond that limit, you will get a fatal IntegrityError
  exception telling that the (archive) object is too big.
  An easy workaround is to create multiple archives with less items each.
  See also the :ref:`archive_limitation` and :issue:`1452`.


Why is my backup bigger than with attic? Why doesn't |project_name| do compression by default?
----------------------------------------------------------------------------------------------

Attic was rather unflexible when it comes to compression, it always
compressed using zlib level 6 (no way to switch compression off or
adjust the level or algorithm).

|project_name| offers a lot of different compression algorithms and
levels. Which of them is the best for you pretty much depends on your
use case, your data, your hardware -- so you need to do an informed
decision about whether you want to use compression, which algorithm
and which level you want to use. This is why compression defaults to
none.

How can I specify the encryption passphrase programmatically?
-------------------------------------------------------------

The encryption passphrase can be specified programmatically using the
`BORG_PASSPHRASE` environment variable. This is convenient when setting up
automated encrypted backups. Another option is to use
key file based encryption with a blank passphrase. See
:ref:`encrypted_repos` for more details.

.. _password_env:
.. note:: Be careful how you set the environment; using the ``env``
          command, a ``system()`` call or using inline shell scripts
          might expose the credentials in the process list directly
          and they will be readable to all users on a system. Using
          ``export`` in a shell script file should be safe, however, as
          the environment of a process is `accessible only to that
          user
          <https://security.stackexchange.com/questions/14000/environment-variable-accessibility-in-linux/14009#14009>`_.

When backing up to remote encrypted repos, is encryption done locally?
----------------------------------------------------------------------

Yes, file and directory metadata and data is locally encrypted, before
leaving the local machine. We do not mean the transport layer encryption
by that, but the data/metadata itself. Transport layer encryption (e.g.
when ssh is used as a transport) applies additionally.

When backing up to remote servers, do I have to trust the remote server?
------------------------------------------------------------------------

Yes and No.

No, as far as data confidentiality is concerned - if you use encryption,
all your files/dirs data and metadata are stored in their encrypted form
into the repository.

Yes, as an attacker with access to the remote server could delete (or
otherwise make unavailable) all your backups.

How can I protect against a hacked backup client?
-------------------------------------------------

Assume you backup your backup client machine C to the backup server S and
C gets hacked. In a simple push setup, the attacker could then use borg on
C to delete all backups residing on S.

These are your options to protect against that:

- Do not allow to permanently delete data from the repo, see :ref:`append_only_mode`.
- Use a pull-mode setup using ``ssh -R``, see :issue:`900`.
- Mount C's filesystem on another machine and then create a backup of it.
- Do not give C filesystem-level access to S.

How can I protect against a hacked backup server?
-------------------------------------------------

Just in case you got the impression that pull-mode backups are way more safe
than push-mode, you also need to consider the case that your backup server S
gets hacked. In case S has access to a lot of clients C, that might bring you
into even bigger trouble than a hacked backup client in the previous FAQ entry.

These are your options to protect against that:

- Use the standard push-mode setup (see also previous FAQ entry).
- Mount (the repo part of) S's filesystem on C.
- Do not give S file-system level access to C.
- Have your backup server at a well protected place (maybe not reachable from
  the internet), configure it safely, apply security updates, monitor it, ...

How can I protect against theft, sabotage, lightning, fire, ...?
----------------------------------------------------------------

In general: if your only backup medium is nearby the backupped machine and
always connected, you can easily get into trouble: they likely share the same
fate if something goes really wrong.

Thus:

- have multiple backup media
- have media disconnected from network, power, computer
- have media at another place
- have a relatively recent backup on your media

Why do I get "connection closed by remote" after a while?
---------------------------------------------------------

When doing a backup to a remote server (using a ssh: repo URL), it sometimes
stops after a while (some minutes, hours, ... - not immediately) with
"connection closed by remote" error message. Why?

That's a good question and we are trying to find a good answer in :issue:`636`.

Why am I seeing idle borg serve processes on the repo server?
-------------------------------------------------------------

Maybe the ssh connection between client and server broke down and that was not
yet noticed on the server. Try these settings:

::

    # /etc/ssh/sshd_config on borg repo server - kill connection to client
    # after ClientAliveCountMax * ClientAliveInterval seconds with no response
    ClientAliveInterval 20
    ClientAliveCountMax 3

If you have multiple borg create ... ; borg create ... commands in a already
serialized way in a single script, you need to give them --lock-wait N (with N
being a bit more than the time the server needs to terminate broken down
connections and release the lock).

The borg cache eats way too much disk space, what can I do?
-----------------------------------------------------------

There is a temporary (but maybe long lived) hack to avoid using lots of disk
space for chunks.archive.d (see :issue:`235` for details):

::

    # this assumes you are working with the same user as the backup.
    # you can get the REPOID from the "config" file inside the repository.
    cd ~/.cache/borg/<REPOID>
    rm -rf chunks.archive.d ; touch chunks.archive.d

This deletes all the cached archive chunk indexes and replaces the directory
that kept them with a file, so borg won't be able to store anything "in" there
in future.

This has some pros and cons, though:

- much less disk space needs for ~/.cache/borg.
- chunk cache resyncs will be slower as it will have to transfer chunk usage
  metadata for all archives from the repository (which might be slow if your
  repo connection is slow) and it will also have to build the hashtables from
  that data.
  chunk cache resyncs happen e.g. if your repo was written to by another
  machine (if you share same backup repo between multiple machines) or if
  your local chunks cache was lost somehow.

The long term plan to improve this is called "borgception", see :issue:`474`.

If a backup stops mid-way, does the already-backed-up data stay there?
----------------------------------------------------------------------

Yes, |project_name| supports resuming backups.

During a backup a special checkpoint archive named ``<archive-name>.checkpoint``
is saved every checkpoint interval (the default value for this is 5
minutes) containing all the data backed-up until that point.

Checkpoints only happen between files (so they don't help for interruptions
happening while a very large file is being processed).

This checkpoint archive is a valid archive (all files in it are valid and complete),
but it is only a partial backup (not all files that you wanted to backup are
contained in it). Having it in the repo until a successful, full backup is
completed is useful because it references all the transmitted chunks up
to the checkpoint. This means that in case of an interruption, you only need to
retransfer the data since the last checkpoint.

If a backup was interrupted, you do not need to do any special considerations,
just invoke ``borg create`` as you always do. You may use the same archive name
as in previous attempt or a different one (e.g. if you always include the current
datetime), it does not matter.

|project_name| always does full single-pass backups, so it will start again
from the beginning - but it will be much faster, because some of the data was
already stored into the repo (and is still referenced by the checkpoint
archive), so it does not need to get transmitted and stored again.

Once your backup has finished successfully, you can delete all
``<archive-name>.checkpoint`` archives.

How can I backup huge file(s) over a unstable connection?
---------------------------------------------------------

You can use this "split trick" as a workaround for the in-between-files-only
checkpoints (see above), huge files and a instable connection to the repository:

Split the huge file(s) into parts of manageable size (e.g. 100MB) and create
a temporary archive of them. Borg will create checkpoints now more frequently
than if you try to backup the files in their original form (e.g. 100GB).

After that, you can remove the parts again and backup the huge file(s) in
their original form. This will now work a lot faster as a lot of content chunks
are already in the repository.

After you have successfully backed up the huge original file(s), you can remove
the temporary archive you made from the parts.

We realize that this is just a better-than-nothing workaround, see :issue:`1198`
for a potential solution.

Please note that this workaround only helps you for backup, not for restore.

If it crashes with a UnicodeError, what can I do?
-------------------------------------------------

Check if your encoding is set correctly. For most POSIX-like systems, try::

  export LANG=en_US.UTF-8  # or similar, important is correct charset

I can't extract non-ascii filenames by giving them on the commandline!?
-----------------------------------------------------------------------

This might be due to different ways to represent some characters in unicode
or due to other non-ascii encoding issues.

If you run into that, try this:

- avoid the non-ascii characters on the commandline by e.g. extracting
  the parent directory (or even everything)
- mount the repo using FUSE and use some file manager

Can |project_name| add redundancy to the backup data to deal with hardware malfunction?
---------------------------------------------------------------------------------------

No, it can't. While that at first sounds like a good idea to defend against
some defect HDD sectors or SSD flash blocks, dealing with this in a
reliable way needs a lot of low-level storage layout information and
control which we do not have (and also can't get, even if we wanted).

So, if you need that, consider RAID or a filesystem that offers redundant
storage or just make backups to different locations / different hardware.

See also :issue:`225`.

Can |project_name| verify data integrity of a backup archive?
-------------------------------------------------------------

Yes, if you want to detect accidental data damage (like bit rot), use the
``check`` operation. It will notice corruption using CRCs and hashes.
If you want to be able to detect malicious tampering also, use an encrypted
repo. It will then be able to check using CRCs and HMACs.

.. _a_status_oddity:

I am seeing 'A' (added) status for a unchanged file!?
-----------------------------------------------------

The files cache is used to determine whether |project_name| already
"knows" / has backed up a file and if so, to skip the file from
chunking. It does intentionally *not* contain files that have a modification
time (mtime) same as the newest mtime in the created archive.

So, if you see an 'A' status for unchanged file(s), they are likely the files
with the most recent mtime in that archive.

This is expected: it is to avoid data loss with files that are backed up from
a snapshot and that are immediately changed after the snapshot (but within
mtime granularity time, so the mtime would not change). Without the code that
removes these files from the files cache, the change that happened right after
the snapshot would not be contained in the next backup as |project_name| would
think the file is unchanged.

This does not affect deduplication, the file will be chunked, but as the chunks
will often be the same and already stored in the repo (except in the above
mentioned rare condition), it will just re-use them as usual and not store new
data chunks.

If you want to avoid unnecessary chunking, just create or touch a small or
empty file in your backup source file set (so that one has the latest mtime,
not your 50GB VM disk image) and, if you do snapshots, do the snapshot after
that.

Since only the files cache is used in the display of files status,
those files are reported as being added when, really, chunks are
already used.


.. _always_chunking:

It always chunks all my files, even unchanged ones!
---------------------------------------------------

|project_name| maintains a files cache where it remembers the mtime, size and
inode of files. When |project_name| does a new backup and starts processing a
file, it first looks whether the file has changed (compared to the values
stored in the files cache). If the values are the same, the file is assumed
unchanged and thus its contents won't get chunked (again).

|project_name| can't keep an infinite history of files of course, thus entries
in the files cache have a "maximum time to live" which is set via the
environment variable BORG_FILES_CACHE_TTL (and defaults to 20).
Every time you do a backup (on the same machine, using the same user), the
cache entries' ttl values of files that were not "seen" are incremented by 1
and if they reach BORG_FILES_CACHE_TTL, the entry is removed from the cache.

So, for example, if you do daily backups of 26 different data sets A, B,
C, ..., Z on one machine (using the default TTL), the files from A will be
already forgotten when you repeat the same backups on the next day and it
will be slow because it would chunk all the files each time. If you set
BORG_FILES_CACHE_TTL to at least 26 (or maybe even a small multiple of that),
it would be much faster.

Another possible reason is that files don't always have the same path, for
example if you mount a filesystem without stable mount points for each backup.
If the directory where you mount a filesystem is different every time,
|project_name| assume they are different files.


Is there a way to limit bandwidth with |project_name|?
------------------------------------------------------

There is no command line option to limit bandwidth with |project_name|, but
bandwidth limiting can be accomplished with pipeviewer_:

Create a wrapper script:  /usr/local/bin/pv-wrapper  ::

    #!/bin/bash
        ## -q, --quiet              do not output any transfer information at all
        ## -L, --rate-limit RATE    limit transfer to RATE bytes per second
    export RATE=307200
    pv -q -L $RATE  | "$@"

Add BORG_RSH environment variable to use pipeviewer wrapper script with ssh. ::

    export BORG_RSH='/usr/local/bin/pv-wrapper ssh'

Now |project_name| will be bandwidth limited. Nice thing about pv is that you can change rate-limit on the fly: ::

    pv -R $(pidof pv) -L 102400

.. _pipeviewer: http://www.ivarch.com/programs/pv.shtml


I am having troubles with some network/FUSE/special filesystem, why?
--------------------------------------------------------------------

|project_name| is doing nothing special in the filesystem, it only uses very
common and compatible operations (even the locking is just "mkdir").

So, if you are encountering issues like slowness, corruption or malfunction
when using a specific filesystem, please try if you can reproduce the issues
with a local (non-network) and proven filesystem (like ext4 on Linux).

If you can't reproduce the issue then, you maybe have found an issue within
the filesystem code you used (not with |project_name|). For this case, it is
recommended that you talk to the developers / support of the network fs and
maybe open an issue in their issue tracker. Do not file an issue in the
|project_name| issue tracker.

If you can reproduce the issue with the proven filesystem, please file an
issue in the |project_name| issue tracker about that.


Requirements for the borg single-file binary, esp. (g)libc?
-----------------------------------------------------------

We try to build the binary on old, but still supported systems - to keep the
minimum requirement for the (g)libc low. The (g)libc can't be bundled into
the binary as it needs to fit your kernel and OS, but Python and all other
required libraries will be bundled into the binary.

If your system fulfills the minimum (g)libc requirement (see the README that
is released with the binary), there should be no problem. If you are slightly
below the required version, maybe just try. Due to the dynamic loading (or not
loading) of some shared libraries, it might still work depending on what
libraries are actually loaded and used.

In the borg git repository, there is scripts/glibc_check.py that can determine
(based on the symbols' versions they want to link to) whether a set of given
(Linux) binaries works with a given glibc version.


Why was Borg forked from Attic?
-------------------------------

Borg was created in May 2015 in response to the difficulty of getting new
code or larger changes incorporated into Attic and establishing a bigger
developer community / more open development.

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
