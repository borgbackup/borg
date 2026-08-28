Additional Notes
----------------

Here are miscellaneous notes about topics that may not be covered in enough detail in the usage section.

.. _chunker-params:

``--chunker-params``
~~~~~~~~~~~~~~~~~~~~

The chunker parameters influence how input files are cut into pieces (chunks)
which are then considered for deduplication. They also have a big impact on
resource usage (RAM and disk space) as the amount of resources needed is
(also) determined by the total number of chunks in the repository (see
:ref:`cache-memory-usage` for details).

``--chunker-params=fastcdc,10,23,16,2`` results in a fine-grained deduplication
and creates a large number of chunks and thus uses a lot of resources to manage
them. This is good for relatively small data volumes and if the machine has a
good amount of free RAM and disk space.

``--chunker-params=fastcdc,19,23,21,2`` (default) results in a coarse-grained
deduplication and creates a much smaller number of chunks and thus uses less
resources. This is good for relatively big data volumes and if the machine has
a relatively low amount of free RAM and disk space.

``--chunker-params=fixed,4194304`` results in fixed 4 MiB-sized block
deduplication and is more efficient than the previous example when used with
for block devices (like disks, partitions, LVM LVs) or raw disk image files.

``--chunker-params=fixed,4096,512`` results in fixed 4 KiB-sized blocks,
but the first header block will only be 512B long. This might be useful to
dedup files with 1 header + N fixed size data blocks. Be careful not to
produce too many chunks (for example, using a small block size for huge
files).

If you have already created some archives in a repository and then change
chunker parameters, this of course impacts deduplication as the chunks will be
cut differently.

In the worst case (all files are big and were touched in between backups), this
will store all content into the repository again.

Usually, it is not that bad though:

- usually most files are not touched, so it will just re-use the old chunks
  it already has in the repo
- files smaller than the (both old and new) minimum chunk size result in only
  one chunk anyway, so the resulting chunks are the same and deduplication will apply

If you switch chunker parameters to save resources for an existing repository that
already has some backup archives, you will see an increasing effect over time,
when more and more files have been touched and stored again using the bigger
chunk size **and** all references to the smaller, older chunks have been removed
(by deleting / pruning archives).

If you want to see an immediate, significant effect on resource usage, you should start
a new repository when changing chunker parameters.

For more details, see :ref:`chunker_details`.


``--atime / --noctime / --nobirthtime``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``borg create`` does not store atime by default — use ``--atime`` if you do
need it. ctime and birthtime are stored by default and can be omitted with
``--noctime`` and ``--nobirthtime``.

Besides saving a little space by omitting a timestamp, storing fewer timestamps
might also help metadata stream deduplication: if only such a timestamp changes
between backups and is stored into the metadata stream, the metadata stream
chunks will not deduplicate just because of that.

``--noflags``
~~~~~~~~~~~~~

You can use this to avoid querying and storing (or extracting and setting) flags — in case
you don't need them or if they are broken for your filesystem.

On Linux, dealing with the flags needs some additional syscalls. Especially when
dealing with lots of small files, this causes a noticeable overhead, so you can
use this option also for speeding up operations.

File flags (bsdflags) between platforms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Borg archives file flags as BSD-style ``chflags(2)`` values, on all platforms.
On Linux, the file attributes nodump, immutable and append-only (see
``ioctl_iflags(2)`` / ``chattr(1)``) are translated to/from the corresponding
BSD-style flags; other Linux attributes are not archived.

The available flags differ between platforms, so when extracting, borg only
sets the flags known to be settable from userspace on the destination platform —
unsupported flags are dropped individually, the supported ones are still set.
Flag bits that are not settable from userspace (like macOS's ``UF_COMPRESSED``
or ``SF_DATALESS``, or unknown/future flags) are never modified: the extracted
file keeps whatever the OS gives it.

Some flags need special privileges to set (the super-user-only ``SF_*`` flags
on BSD/macOS, immutable/append-only on Linux). If setting them is not
permitted, borg still restores the remaining flags (like nodump) and skips the
privileged ones. If the flags of a file cannot be set at all, borg issues a
warning and sets the exit code to warning status.

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

Reading from a FIFO blocks until a writer connects and sends data - if that
never happens (e.g. due to a broken producer script), ``borg create`` would
appear to hang. Thus, when no data arrives from a FIFO or character device
for ``--read-special-timeout SECONDS`` (default: 1800, i.e. 30 minutes; this
includes waiting for a FIFO's writer to connect), borg gives up on that file:
it is skipped with an error and the backup continues with the remaining
files. Choose a timeout larger than the pauses a legitimate (slow) producer
makes while sending data - or give 0 to disable the timeout and wait forever.
Note: with the timeout active, a writer that connects, but closes without
sending anything, is reported as a timeout, too (instead of storing a file
with empty content).

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

Efficient backups of LVM thin volume snapshots
++++++++++++++++++++++++++++++++++++++++++++++

Backing up a block device as shown above reads the whole device every time.
For snapshots of LVM *thin* volumes, the thin pool's metadata already knows
which ranges are allocated and which ranges changed between two snapshots,
so most of the reading can be skipped: see the ``--map`` and ``--reuse-from``
options of ``borg create`` (section *Input maps* in ``borg create --help``)
and the ``scripts/lvm-thin-map.py`` converter in the borg sources, which
turns ``thin_dump`` / ``thin_delta`` XML into borg input maps. The script's
docstring shows the complete workflow: an initial full backup using the
allocation map (unallocated ranges are stored as holes without reading them),
then incremental backups that only read the ranges that changed since the
previous snapshot, while reusing the previous archive's chunks for everything
else. Use ``--chunker-params fixed,4194304`` (or similar) for such backups.

Note that borg trusts these maps - it cannot detect a wrong or stale map, so
keep the snapshot discipline described in the script's docstring and consider
doing a periodic full read backup (without ``--map``).


.. _separate_compaction:

Separate compaction
~~~~~~~~~~~~~~~~~~~

Borg does not automatically compact the files in the repository when doing
borg operations.

This has some notable consequences:

- repository space is not freed immediately when deleting / pruning archives
- commands finish quicker, less I/O
- it is possible to undelete deleted archives as long as no compaction has been
  invoked.
- user can choose when to run compaction (it should be done regularly, but not
  necessarily after each single borg command)
- less repo sync data traffic in case you create a copy of your repository by
  using a sync tool (like rsync, rclone, ...)

You can run compaction by invoking the ``borg compact`` command.

SSH batch mode
~~~~~~~~~~~~~~

When running Borg using an automated script, ``ssh`` might still ask for a password,
even if there is an SSH key for the target server. Use this to make scripts more robust::

    export BORG_RSH='ssh -oBatchMode=yes'

