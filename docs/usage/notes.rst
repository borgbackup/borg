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

``--chunker-params=buzhash,10,23,16,4095`` results in a fine-grained deduplication|
and creates a big amount of chunks and thus uses a lot of resources to manage
them. This is good for relatively small data volumes and if the machine has a
good amount of free RAM and disk space.

``--chunker-params=buzhash,19,23,21,4095`` (default) results in a coarse-grained
deduplication and creates a much smaller amount of chunks and thus uses less
resources. This is good for relatively big data volumes and if the machine has
a relatively low amount of free RAM and disk space.

``--chunker-params=fixed,4194304`` results in fixed 4MiB sized block
deduplication and is more efficient than the previous example when used for
for block devices (like disks, partitions, LVM LVs) or raw disk image files.

``--chunker-params=fixed,4096,512`` results in fixed 4kiB sized blocks,
but the first header block will only be 512B long. This might be useful to
dedup files with 1 header + N fixed size data blocks. Be careful not to
produce a too big amount of chunks (like using small block size for huge
files).

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

You can use these ``borg create`` options not to store the respective timestamp
into the archive, in case you do not really need it.

Besides saving a little space for the not archived timestamp, it might also
affect metadata stream deduplication: if only this timestamp changes between
backups and is stored into the metadata stream, the metadata stream chunks
won't deduplicate just because of that.

``--nobsdflags / --noflags``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can use this not to query and store (or not extract and set) flags - in case
you don't need them or if they are broken somehow for your fs.

On Linux, dealing with the flags needs some additional syscalls. Especially when
dealing with lots of small files, this causes a noticeable overhead, so you can
use this option also for speeding up operations.

``--umask``
~~~~~~~~~~~

borg uses a safe default umask of 077 (that means the files borg creates have
only permissions for owner, but no permissions for group and others) - so there
should rarely be a need to change the default behaviour.

This option only affects the process to which it is given. Thus, when you run
borg in client/server mode and you want to change the behaviour on the server
side, you need to use ``borg serve --umask=XXX ...`` as a ssh forced command
in ``authorized_keys``. The ``--umask`` value given on the client side is
**not** transferred to the server side.

Also, if you choose to use the ``--umask`` option, always be consistent and use
the same umask value so you do not create a mixup of permissions in a borg
repository or with other files borg creates.

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

Imagine you have made some snapshots of logical volumes (LVs) you want to back up.

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
    $ borg create --read-special arch lvdisplay.txt /dev/vg0/*-snapshot
    $ # remove snapshots here

Now, let's see how to restore some LVs from such a backup.

::

    $ borg extract arch lvdisplay.txt
    $ # create empty LVs with correct sizes here (look into lvdisplay.txt).
    $ # we assume that you created an empty root and home LV and overwrite it now:
    $ borg extract --stdout arch dev/vg0/root-snapshot > /dev/vg0/root
    $ borg extract --stdout arch dev/vg0/home-snapshot > /dev/vg0/home


.. _separate_compaction:

Separate compaction
~~~~~~~~~~~~~~~~~~~

Borg does not auto-compact the segment files in the repository at commit time
(at the end of each repository-writing command) any more (since borg 1.2.0).

This has some notable consequences:

- repository space is not freed immediately when deleting / pruning archives
- commands finish quicker
- repository is more robust and might be easier to recover after damages (as
  it contains data in a more sequential manner, historic manifests, multiple
  commits - until you run ``borg compact``)
- user can choose when to run compaction (it should be done regularly, but not
  necessarily after each single borg command)
- user can choose from where to invoke ``borg compact`` to do the compaction
  (from client or from server, it does not need a key)
- less repo sync data traffic in case you create a copy of your repository by
  using a sync tool (like rsync, rclone, ...)

You can manually run compaction by invoking the ``borg compact`` command.

SSH batch mode
~~~~~~~~~~~~~~

When running Borg using an automated script, ``ssh`` might still ask for a password,
even if there is an SSH key for the target server. Use this to make scripts more robust::

    export BORG_RSH='ssh -oBatchMode=yes'

