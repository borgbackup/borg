Additional Notes
----------------

Here are misc. notes about topics that are maybe not covered in enough detail in the usage section.

.. _chunker-params:

``--chunker-params``
~~~~~~~~~~~~~~~~~~~~

The chunker params influence how input files are cut into pieces (chunks)
which are then considered for deduplication. They also have a big impact on
resource usage (RAM and disk space) as the amount of resources needed is
(also) determined by the total amount of chunks in the repository (see
:ref:`cache-memory-usage` for details).

``--chunker-params=10,23,16,4095`` results in a fine-grained deduplication|
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


``--noatime / --noctime``
~~~~~~~~~~~~~~~~~~~~~~~~~

You can use these ``borg create`` options to not store the respective timestamp
into the archive, in case you do not really need it.

Besides saving a little space for the not archived timestamp, it might also
affect metadata stream deduplication: if only this timestamp changes between
backups and is stored into the metadata stream, the metadata stream chunks
won't deduplicate just because of that.

``--nobsdflags``
~~~~~~~~~~~~~~~~

You can use this to not query and store (or not extract and set) bsdflags -
in case you don't need them or if they are broken somehow for your fs.

On Linux, dealing with the bsflags needs some additional syscalls.
Especially when dealing with lots of small files, this causes a noticeable
overhead, so you can use this option also for speeding up operations.

``--umask``
~~~~~~~~~~~

If you use ``--umask``, make sure that all repository-modifying borg commands
(create, delete, prune) that access the repository in question use the same
``--umask`` value.

If multiple machines access the same repository, this should hold true for all
of them.

``--read-special``
~~~~~~~~~~~~~~~~~~

The ``--read-special`` option is special - you do not want to use it for normal
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
    hit the reset button or your machine would abruptly and completely crash).
    This is better than no consistency at all and a good method for some use
    cases, but likely not good enough if you have databases running.

Then you create a backup archive of all these snapshots. The backup process will
see a "frozen" state of the logical volumes, while the processes working in the
original volumes continue changing the data stored there.

You also add the output of ``lvdisplay`` to your backup, so you can see the LV
sizes in case you ever need to recreate and restore them.

After the backup has completed, you remove the snapshots again.

::

    $ # create snapshots here
    $ lvdisplay > lvdisplay.txt
    $ borg create --read-special /path/to/repo::arch lvdisplay.txt /dev/vg0/*-snapshot
    $ # remove snapshots here

Now, let's see how to restore some LVs from such a backup.

::

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

To activate append-only mode, set ``append_only`` to 1 in the repository config:

::

    borg config /path/to/repo append_only 1

Note that you can go back-and-forth between normal and append-only operation with
``borg config``; it's not a "one way trip."

In append-only mode Borg will create a transaction log in the ``transactions`` file,
where each line is a transaction and a UTC timestamp.

In addition, ``borg serve`` can act as if a repository is in append-only mode with
its option ``--append-only``. This can be very useful for fine-tuning access control
in ``.ssh/authorized_keys``:

::

    command="borg serve --append-only ..." ssh-rsa <key used for not-always-trustable backup clients>
    command="borg serve ..." ssh-rsa <key used for backup management>

Running ``borg init`` via a ``borg serve --append-only`` server will *not* create
an append-only repository. Running ``borg init --append-only`` creates an append-only
repository regardless of server settings.

Example
+++++++

Suppose an attacker remotely deleted all backups, but your repository was in append-only
mode. A transaction log in this situation might look like this:

::

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
is to remove the ``hints.N``, ``index.N`` and ``integrity.N`` files in the repository (these
files are always expendable). In this example N is 13.

Then remove or move all segment files from the segment directories in ``data/`` starting
with file 6::

    rm data/**/{6..13}

That's all to do in the repository.

If you want to access this rollbacked repository from a client that already has
a cache for this repository, the cache will reflect a newer repository state
than what you actually have in the repository now, after the rollback.

Thus, you need to clear the cache::

    borg delete --cache-only repo

The cache will get rebuilt automatically. Depending on repo size and archive
count, it may take a while.

You also will need to remove ~/.config/borg/security/REPOID/manifest-timestamp.

Drawbacks
+++++++++

As data is only appended, and nothing removed, commands like ``prune`` or ``delete``
won't free disk space, they merely tag data as deleted in a new transaction.

Be aware that as soon as you write to the repo in non-append-only mode (e.g. prune,
delete or create archives from an admin machine), it will remove the deleted objects
permanently (including the ones that were already marked as deleted, but not removed,
in append-only mode). Automated edits to the repository (such as a cron job running
``borg prune``) will render append-only mode moot if data is deleted.

Even if an archive appears to be available, it is possible an attacker could delete
just a few chunks from an archive and silently corrupt its data. While in append-only
mode, this is reversible, but ``borg check`` should be run before a writing/pruning
operation on an append-only repository to catch accidental or malicious corruption::

    # run without append-only mode
    borg check --verify-data repo

Aside from checking repository & archive integrity you may want to also manually check
backups to ensure their content seems correct.

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

When running Borg using an automated script, ``ssh`` might still ask for a password,
even if there is an SSH key for the target server. Use this to make scripts more robust::

    export BORG_RSH='ssh -oBatchMode=yes'
