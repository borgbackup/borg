.. include:: global.rst.inc
.. highlight:: none
.. _detailed_usage:

Usage
=====

|project_name| consists of a number of commands. Each command accepts
a number of arguments and options. The following sections will describe each
command in detail.

General
-------

.. include:: usage_general.rst.inc

In case you are interested in more details (like formulas), please see
:ref:`internals`. For details on the available JSON output, refer to
:ref:`json_output`.

Common options
~~~~~~~~~~~~~~

All |project_name| commands share these options:

.. include:: usage/common-options.rst.inc

.. include:: usage/init.rst.inc

Examples
~~~~~~~~
::

    # Local repository, repokey encryption, BLAKE2b (often faster, since Borg 1.1)
    $ borg init --encryption=repokey-blake2 /path/to/repo

    # Local repository (no encryption)
    $ borg init --encryption=none /path/to/repo

    # Remote repository (accesses a remote borg via ssh)
    $ borg init --encryption=repokey-blake2 user@hostname:backup

    # Remote repository (store the key your home dir)
    $ borg init --encryption=keyfile user@hostname:backup

.. include:: usage/create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create /path/to/repo::my-documents ~/Documents

    # same, but list all files as we process them
    $ borg create --list /path/to/repo::my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create /path/to/repo::my-files \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup home directories excluding image thumbnails (i.e. only
    # /home/*/.thumbnails is excluded, not /home/*/*/.thumbnails)
    $ borg create /path/to/repo::my-files /home \
        --exclude 're:^/home/[^/]+/\.thumbnails/'

    # Do the same using a shell-style pattern
    $ borg create /path/to/repo::my-files /home \
        --exclude 'sh:/home/*/.thumbnails'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    # use zlib compression (good, but slow) - default is lz4 (fast, low compression ratio)
    $ borg create -C zlib,6 /path/to/repo::root-{now:%Y-%m-%d} / --one-file-system

    # Backup a remote host locally ("pull" style) using sshfs
    $ mkdir sshfs-mount
    $ sshfs root@example.com:/ sshfs-mount
    $ cd sshfs-mount
    $ borg create /path/to/repo::example.com-root-{now:%Y-%m-%d} .
    $ cd ..
    $ fusermount -u sshfs-mount

    # Make a big effort in fine granular deduplication (big chunk management
    # overhead, needs a lot of RAM and disk space, see formula in internals
    # docs - same parameters as borg < 1.0 or attic):
    $ borg create --chunker-params 10,23,16,4095 /path/to/repo::small /smallstuff

    # Backup a raw device (must not be active/in use/mounted at that time)
    $ dd if=/dev/sdx bs=10M | borg create /path/to/repo::my-sdx -

    # No compression (default)
    $ borg create /path/to/repo::arch ~

    # Super fast, low compression
    $ borg create --compression lz4 /path/to/repo::arch ~

    # Less fast, higher compression (N = 0..9)
    $ borg create --compression zlib,N /path/to/repo::arch ~

    # Even slower, even higher compression (N = 0..9)
    $ borg create --compression lzma,N /path/to/repo::arch ~

    # Use short hostname, user name and current time in archive name
    $ borg create /path/to/repo::{hostname}-{user}-{now} ~
    # Similar, use the same datetime format as borg 1.1 will have as default
    $ borg create /path/to/repo::{hostname}-{user}-{now:%Y-%m-%dT%H:%M:%S} ~
    # As above, but add nanoseconds
    $ borg create /path/to/repo::{hostname}-{user}-{now:%Y-%m-%dT%H:%M:%S.%f} ~

    # Backing up relative paths by moving into the correct directory first
    $ cd /home/user/Documents
    # The root directory of the archive will be "projectA"
    $ borg create /path/to/repo::daily-projectA-{now:%Y-%m-%d} projectA


.. include:: usage/extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract /path/to/repo::my-files

    # Extract entire archive and list files while processing
    $ borg extract --list /path/to/repo::my-files

    # Verify whether an archive could be successfully extracted, but do not write files to disk
    $ borg extract --dry-run /path/to/repo::my-files

    # Extract the "src" directory
    $ borg extract /path/to/repo::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract /path/to/repo::my-files home/USERNAME/src --exclude '*.o'

    # Restore a raw device (must not be active/in use/mounted at that time)
    $ borg extract --stdout /path/to/repo::my-sdx | dd of=/dev/sdx bs=10M


.. Note::

    Currently, extract always writes into the current working directory ("."),
    so make sure you ``cd`` to the right place before calling ``borg extract``.

.. include:: usage/check.rst.inc

.. include:: usage/rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create /path/to/repo::archivename ~
    $ borg list /path/to/repo
    archivename                          Mon, 2016-02-15 19:50:19

    $ borg rename /path/to/repo::archivename newname
    $ borg list /path/to/repo
    newname                              Mon, 2016-02-15 19:50:19


.. include:: usage/list.rst.inc

Examples
~~~~~~~~
::

    $ borg list /path/to/repo
    Monday                               Mon, 2016-02-15 19:15:11
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    ...

    $ borg list /path/to/repo::root-2016-02-15
    drwxr-xr-x root   root          0 Mon, 2016-02-15 17:44:27 .
    drwxrwxr-x root   root          0 Mon, 2016-02-15 19:04:49 bin
    -rwxr-xr-x root   root    1029624 Thu, 2014-11-13 00:08:51 bin/bash
    lrwxrwxrwx root   root          0 Fri, 2015-03-27 20:24:26 bin/bzcmp -> bzdiff
    -rwxr-xr-x root   root       2140 Fri, 2015-03-27 20:24:22 bin/bzdiff
    ...

    $ borg list /path/to/repo::archiveA --list-format="{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}"
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 .
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code/myproject
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.ext
    ...


.. include:: usage/diff.rst.inc

Examples
~~~~~~~~
::

    $ borg init -e=none testrepo
    $ mkdir testdir
    $ cd testdir
    $ echo asdf > file1
    $ dd if=/dev/urandom bs=1M count=4 > file2
    $ touch file3
    $ borg create ../testrepo::archive1 .

    $ chmod a+x file1
    $ echo "something" >> file2
    $ borg create ../testrepo::archive2 .

    $ rm file3
    $ touch file4
    $ borg create ../testrepo::archive3 .

    $ cd ..
    $ borg diff testrepo::archive1 archive2
    [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2

    $ borg diff testrepo::archive2 archive3
    added           0 B file4
    removed         0 B file3

    $ borg diff testrepo::archive1 archive3
    [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2
    added           0 B file4
    removed         0 B file3

.. include:: usage/delete.rst.inc

Examples
~~~~~~~~
::

    # delete a single backup archive:
    $ borg delete /path/to/repo::Monday

    # delete the whole repository and the related local cache:
    $ borg delete /path/to/repo
    You requested to completely DELETE the repository *including* all archives it contains:
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    Type 'YES' if you understand this and want to continue: YES


.. include:: usage/prune.rst.inc

Examples
~~~~~~~~

Be careful, prune is a potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using ``--prefix``.
When using ``--prefix``, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run ``prune -v --list --dry-run ...``
first so you will see what it would do without it actually doing anything.

There is also a visualized prune example in ``docs/misc/prune-example.txt``.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune -v --list --dry-run --keep-daily=7 --keep-weekly=4 /path/to/repo

    # Same as above but only apply to archive names starting with the hostname
    # of the machine followed by a "-" character:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --prefix='{hostname}-' /path/to/repo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --keep-monthly=-1 /path/to/repo

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-within=10d --keep-weekly=4 --keep-monthly=-1 /path/to/repo


.. include:: usage/info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /path/to/repo::root-2016-02-15
    Name: root-2016-02-15
    Fingerprint: 57c827621f21b000a8d363c1e163cc55983822b3afff3a96df595077a660be50
    Hostname: myhostname
    Username: root
    Time (start): Mon, 2016-02-15 19:36:29
    Time (end):   Mon, 2016-02-15 19:39:26
    Command line: /usr/local/bin/borg create --list -C zlib,6 /path/to/repo::root-2016-02-15 / --one-file-system
    Number of files: 38100

                           Original size      Compressed size    Deduplicated size
    This archive:                1.33 GB            613.25 MB            571.64 MB
    All archives:                1.63 GB            853.66 MB            584.12 MB

                           Unique chunks         Total chunks
    Chunk index:                   36858                48844


.. include:: usage/mount.rst.inc

.. include:: usage/umount.rst.inc

Examples
~~~~~~~~

borg mount
++++++++++
::

    $ borg mount /path/to/repo::root-2016-02-15 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt  root  sbin  srv  tmp  usr  var
    $ borg umount /tmp/mymountpoint

::

    $ borg mount -o versions /path/to/repo /tmp/mymountpoint
    $ ls -l /tmp/mymountpoint/home/user/doc.txt/
    total 24
    -rw-rw-r-- 1 user group 12357 Aug 26 21:19 doc.txt.cda00bc9
    -rw-rw-r-- 1 user group 12204 Aug 26 21:04 doc.txt.fa760f28
    $ fusermount -u /tmp/mymountpoint

borgfs
++++++
::

    $ echo '/mnt/backup /tmp/myrepo fuse.borgfs defaults,noauto 0 0' >> /etc/fstab
    $ echo '/mnt/backup::root-2016-02-15 /tmp/myarchive fuse.borgfs defaults,noauto 0 0' >> /etc/fstab
    $ mount /tmp/myrepo
    $ mount /tmp/myarchive
    $ ls /tmp/myrepo
    root-2016-02-01 root-2016-02-2015
    $ ls /tmp/myarchive
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt  root  sbin  srv  tmp  usr  var

.. Note::

    ``borgfs`` will be automatically provided if you used a distribution
    package, ``pip`` or ``setup.py`` to install |project_name|. Users of the
    standalone binary will have to manually create a symlink (see
    :ref:`pyinstaller-binary`).

.. include:: usage/key_export.rst.inc


.. include:: usage/key_import.rst.inc

.. _borg-change-passphrase:

.. include:: usage/key_change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg init --encryption=keyfile -v /path/to/repo
    Initializing repository at "/path/to/repo"
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key in "/root/.config/borg/keys/mnt_backup" created.
    Keep this key safe. Your data will be inaccessible without it.
    Synchronizing chunks cache...
    Archives: 0, w/ cached Idx: 0, w/ outdated Idx: 0, w/o cached Idx: 0.
    Done.

    # Change key file passphrase
    $ borg key change-passphrase -v /path/to/repo
    Enter passphrase for key /root/.config/borg/keys/mnt_backup:
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key updated

Fully automated using environment variables:

::

    $ BORG_NEW_PASSPHRASE=old borg init -e=repokey repo
    # now "old" is the current passphrase.
    $ BORG_PASSPHRASE=old BORG_NEW_PASSPHRASE=new borg key change-passphrase repo
    # now "new" is the current passphrase.


.. include:: usage/serve.rst.inc

Examples
~~~~~~~~

borg serve has special support for ssh forced commands (see ``authorized_keys``
example below): it will detect that you use such a forced command and extract
the value of the ``--restrict-to-path`` option(s).

It will then parse the original command that came from the client, makes sure
that it is also ``borg serve`` and enforce path restriction(s) as given by the
forced command. That way, other options given by the client (like ``--info`` or
``--umask``) are preserved (and are not fixed by the forced command).

Environment variables (such as BORG_HOSTNAME_IS_UNIQUE) contained in the original
command sent by the client are *not* interpreted, but ignored. If BORG_XXX environment
variables should be set on the ``borg serve`` side, then these must be set in system-specific
locations like ``/etc/environment`` or in the forced command itself (example below).

::

    # Allow an SSH keypair to only run borg, and only have access to /path/to/repo.
    # Use key options to disable unneeded and potentially dangerous SSH functionality.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /path/to/repo",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ssh-rsa AAAAB3[...]

    # Set a BORG_XXX environment variable on the "borg serve" side
    $ cat ~/.ssh/authorized_keys
    command="export BORG_XXX=value; borg serve [...]",restrict ssh-rsa [...]

.. include:: usage/upgrade.rst.inc

Examples
~~~~~~~~
::

    # Upgrade the borg repository to the most recent version.
    $ borg upgrade -v /path/to/repo
    making a hardlink copy in /path/to/repo.upgrade-2016-02-15-20:51:55
    opening attic repository with borg and converting
    no key file found for repository
    converting repo index /path/to/repo/index.0
    converting 1 segments...
    converting borg 0.xx to borg current
    no key file found for repository

.. _borg_key_migrate-to-repokey:

Upgrading a passphrase encrypted attic repo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

attic offered a "passphrase" encryption mode, but this was removed in borg 1.0
and replaced by the "repokey" mode (which stores the passphrase-protected
encryption key into the repository config).

Thus, to upgrade a "passphrase" attic repo to a "repokey" borg repo, 2 steps
are needed, in this order:

- borg upgrade repo
- borg key migrate-to-repokey repo


.. include:: usage/recreate.rst.inc

Examples
~~~~~~~~
::

    # Make old (Attic / Borg 0.xx) archives deduplicate with Borg 1.x archives
    # Archives created with Borg 1.1+ and the default chunker params are skipped (archive ID stays the same)
    $ borg recreate /mnt/backup --chunker-params default --progress

    # Create a backup with little but fast compression
    $ borg create /mnt/backup::archive /some/files --compression lz4
    # Then compress it - this might take longer, but the backup has already completed, so no inconsistencies
    # from a long-running backup job.
    $ borg recreate /mnt/backup::archive --recompress --compression zlib,9

    # Remove unwanted files from all archives in a repository
    $ borg recreate /mnt/backup -e /home/icke/Pictures/drunk_photos


    # Change archive comment
    $ borg create --comment "This is a comment" /mnt/backup::archivename ~
    $ borg info /mnt/backup::archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a comment
    ...
    $ borg recreate --comment "This is a better comment" /mnt/backup::archivename
    $ borg info /mnt/backup::archivename
    Name: archivename
    Fingerprint: ...
    Comment: This is a better comment
    ...

.. include:: usage/export-tar.rst.inc

Examples
~~~~~~~~
::

    # export as uncompressed tar
    $ borg export-tar /path/to/repo::Monday Monday.tar

    # exclude some types, compress using gzip
    $ borg export-tar /path/to/repo::Monday Monday.tar.gz --exclude '*.so'

    # use higher compression level with gzip
    $ borg export-tar testrepo::linux --tar-filter="gzip -9" Monday.tar.gz

    # export a gzipped tar, but instead of storing it on disk,
    # upload it to a remote site using curl.
    $ borg export-tar ... --tar-filter="gzip" - | curl --data-binary @- https://somewhere/to/POST

.. include:: usage/with-lock.rst.inc


.. include:: usage/break-lock.rst.inc


Miscellaneous Help
------------------

.. include:: usage/help.rst.inc


Debugging Facilities
--------------------

There is a ``borg debug`` command that has some subcommands which are all
**not intended for normal use** and **potentially very dangerous** if used incorrectly.

For example, ``borg debug put-obj`` and ``borg debug delete-obj`` will only do
what their name suggests: put objects into repo / delete objects from repo.

Please note:

- they will not update the chunks cache (chunks index) about the object
- they will not update the manifest (so no automatic chunks index resync is triggered)
- they will not check whether the object is in use (e.g. before delete-obj)
- they will not update any metadata which may point to the object

They exist to improve debugging capabilities without direct system access, e.g.
in case you ever run into some severe malfunction. Use them only if you know
what you are doing or if a trusted |project_name| developer tells you what to do.

Borg has a ``--debug-topic TOPIC`` option to enable specific debugging messages. Topics
are generally not documented.

A ``--debug-profile FILE`` option exists which writes a profile of the main program's
execution to a file. The format of these files is not directly compatible with the
Python profiling tools, since these use the "marshal" format, which is not intended
to be secure (quoting the Python docs: "Never unmarshal data received from an untrusted
or unauthenticated source.").

The ``borg debug profile-convert`` command can be used to take a Borg profile and convert
it to a profile file that is compatible with the Python tools.

Additionally, if the filename specified for ``--debug-profile`` ends with ".pyprof" a
Python compatible profile is generated. This is only intended for local use by developers.

Additional Notes
----------------

Here are misc. notes about topics that are maybe not covered in enough detail in the usage section.

--chunker-params
~~~~~~~~~~~~~~~~

The chunker params influence how input files are cut into pieces (chunks)
which are then considered for deduplication. They also have a big impact on
resource usage (RAM and disk space) as the amount of resources needed is
(also) determined by the total amount of chunks in the repository (see
`Indexes / Caches memory usage` for details).

``--chunker-params=10,23,16,4095`` results in a fine-grained deduplication
and creates a big amount of chunks and thus uses a lot of resources to manage
them. This is good for relatively small data volumes and if the machine has a
good amount of free RAM and disk space.

``--chunker-params=19,23,21,4095`` (default) results in a coarse-grained
deduplication and creates a much smaller amount of chunks and thus uses less
resources. This is good for relatively big data volumes and if the machine has
a relatively low amount of free RAM and disk space.

If you already have made some archives in a repository and you then change
chunker params, this of course impacts deduplication as the chunks will be
cut differently.

In the worst case (all files are big and were touched in between backups), this
will store all content into the repository again.

Usually, it is not that bad though:

- usually most files are not touched, so it will just re-use the old chunks
  it already has in the repo
- files smaller than the (both old and new) minimum chunksize result in only
  one chunk anyway, so the resulting chunks are same and deduplication will apply

If you switch chunker params to save resources for an existing repo that
already has some backup archives, you will see an increasing effect over time,
when more and more files have been touched and stored again using the bigger
chunksize **and** all references to the smaller older chunks have been removed
(by deleting / pruning archives).

If you want to see an immediate big effect on resource usage, you better start
a new repository when changing chunker params.

For more details, see :ref:`chunker_details`.


--umask
~~~~~~~

If you use ``--umask``, make sure that all repository-modifying borg commands
(create, delete, prune) that access the repository in question use the same
``--umask`` value.

If multiple machines access the same repository, this should hold true for all
of them.

--read-special
~~~~~~~~~~~~~~

The --read-special option is special - you do not want to use it for normal
full-filesystem backups, but rather after carefully picking some targets for it.

The option ``--read-special`` triggers special treatment for block and char
device files as well as FIFOs. Instead of storing them as such a device (or
FIFO), they will get opened, their content will be read and in the backup
archive they will show up like a regular file.

Symlinks will also get special treatment if (and only if) they point to such
a special file: instead of storing them as a symlink, the target special file
will get processed as described above.

One intended use case of this is backing up the contents of one or multiple
block devices, like e.g. LVM snapshots or inactive LVs or disk partitions.

You need to be careful about what you include when using ``--read-special``,
e.g. if you include ``/dev/zero``, your backup will never terminate.

Restoring such files' content is currently only supported one at a time via
``--stdout`` option (and you have to redirect stdout to where ever it shall go,
maybe directly into an existing device file of your choice or indirectly via
``dd``).

To some extent, mounting a backup archive with the backups of special files
via ``borg mount`` and then loop-mounting the image files from inside the mount
point will work. If you plan to access a lot of data in there, it likely will
scale and perform better if you do not work via the FUSE mount.

Example
+++++++

Imagine you have made some snapshots of logical volumes (LVs) you want to backup.

.. note::

    For some scenarios, this is a good method to get "crash-like" consistency
    (I call it crash-like because it is the same as you would get if you just
    hit the reset button or your machine would abrubtly and completely crash).
    This is better than no consistency at all and a good method for some use
    cases, but likely not good enough if you have databases running.

Then you create a backup archive of all these snapshots. The backup process will
see a "frozen" state of the logical volumes, while the processes working in the
original volumes continue changing the data stored there.

You also add the output of ``lvdisplay`` to your backup, so you can see the LV
sizes in case you ever need to recreate and restore them.

After the backup has completed, you remove the snapshots again. ::

    $ # create snapshots here
    $ lvdisplay > lvdisplay.txt
    $ borg create --read-special /path/to/repo::arch lvdisplay.txt /dev/vg0/*-snapshot
    $ # remove snapshots here

Now, let's see how to restore some LVs from such a backup. ::

    $ borg extract /path/to/repo::arch lvdisplay.txt
    $ # create empty LVs with correct sizes here (look into lvdisplay.txt).
    $ # we assume that you created an empty root and home LV and overwrite it now:
    $ borg extract --stdout /path/to/repo::arch dev/vg0/root-snapshot > /dev/vg0/root
    $ borg extract --stdout /path/to/repo::arch dev/vg0/home-snapshot > /dev/vg0/home


.. _append_only_mode:

Append-only mode
~~~~~~~~~~~~~~~~

A repository can be made "append-only", which means that Borg will never overwrite or
delete committed data (append-only refers to the segment files, but borg will also
reject to delete the repository completely). This is useful for scenarios where a
backup client machine backups remotely to a backup server using ``borg serve``, since
a hacked client machine cannot delete backups on the server permanently.

To activate append-only mode, edit the repository ``config`` file and add a line
``append_only=1`` to the ``[repository]`` section (or edit the line if it exists).

In append-only mode Borg will create a transaction log in the ``transactions`` file,
where each line is a transaction and a UTC timestamp.

In addition, ``borg serve`` can act as if a repository is in append-only mode with
its option ``--append-only``. This can be very useful for fine-tuning access control
in ``.ssh/authorized_keys`` ::

    command="borg serve --append-only ..." ssh-rsa <key used for not-always-trustable backup clients>
    command="borg serve ..." ssh-rsa <key used for backup management>

Running ``borg init`` via a ``borg serve --append-only`` server will *not* create
an append-only repository. Running ``borg init --append-only`` creates an append-only
repository regardless of server settings.

Example
+++++++

Suppose an attacker remotely deleted all backups, but your repository was in append-only
mode. A transaction log in this situation might look like this: ::

    transaction 1, UTC time 2016-03-31T15:53:27.383532
    transaction 5, UTC time 2016-03-31T15:53:52.588922
    transaction 11, UTC time 2016-03-31T15:54:23.887256
    transaction 12, UTC time 2016-03-31T15:55:54.022540
    transaction 13, UTC time 2016-03-31T15:55:55.472564

From your security logs you conclude the attacker gained access at 15:54:00 and all
the backups where deleted or replaced by compromised backups. From the log you know
that transactions 11 and later are compromised. Note that the transaction ID is the
name of the *last* file in the transaction. For example, transaction 11 spans files 6
to 11.

In a real attack you'll likely want to keep the compromised repository
intact to analyze what the attacker tried to achieve. It's also a good idea to make this
copy just in case something goes wrong during the recovery. Since recovery is done by
deleting some files, a hard link copy (``cp -al``) is sufficient.

The first step to reset the repository to transaction 5, the last uncompromised transaction,
is to remove the ``hints.N`` and ``index.N`` files in the repository (these two files are
always expendable). In this example N is 13.

Then remove or move all segment files from the segment directories in ``data/`` starting
with file 6::

    rm data/**/{6..13}

That's all to it.

Drawbacks
+++++++++

As data is only appended, and nothing removed, commands like ``prune`` or ``delete``
won't free disk space, they merely tag data as deleted in a new transaction.

Be aware that as soon as you write to the repo in non-append-only mode (e.g. prune,
delete or create archives from an admin machine), it will remove the deleted objects
permanently (including the ones that were already marked as deleted, but not removed,
in append-only mode).

Note that you can go back-and-forth between normal and append-only operation by editing
the configuration file, it's not a "one way trip".

Further considerations
++++++++++++++++++++++

Append-only mode is not respected by tools other than Borg. ``rm`` still works on the
repository. Make sure that backup client machines only get to access the repository via
``borg serve``.

Ensure that no remote access is possible if the repository is temporarily set to normal mode
for e.g. regular pruning.

Further protections can be implemented, but are outside of Borg's scope. For example,
file system snapshots or wrapping ``borg serve`` to set special permissions or ACLs on
new data files.

SSH batch mode
~~~~~~~~~~~~~~

When running |project_name| using an automated script, ``ssh`` might still ask for a password,
even if there is an SSH key for the target server. Use this to make scripts more robust::

    export BORG_RSH='ssh -oBatchMode=yes'
