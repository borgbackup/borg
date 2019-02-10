.. include:: global.rst.inc
.. highlight:: none
.. _faq:

Frequently asked questions
==========================

Usage & Limitations
###################

Can I backup from multiple servers into a single repository?
------------------------------------------------------------

Yes, but in order for the deduplication used by Borg to work, it
needs to keep a local cache containing checksums of all file
chunks already stored in the repository. This cache is stored in
``~/.cache/borg/``.  If Borg detects that a repository has been
modified since the local cache was updated it will need to rebuild
the cache. This rebuild can be quite time consuming.

So, yes it's possible. But it will be most efficient if a single
repository is only modified from one place. Also keep in mind that
Borg will keep an exclusive lock on the repository while creating
or deleting archives, which may make *simultaneous* backups fail.

Can I copy or synchronize my repo to another location?
------------------------------------------------------

If you want to have redundant backup repositories (preferably at separate
locations), the recommended way to do that is like this:

- ``borg init repo1``
- ``borg init repo2``
- client machine ---borg create---> repo1
- client machine ---borg create---> repo2

This will create distinct repositories (separate repo ID, separate
keys) and nothing bad happening in repo1 will influence repo2.

Some people decide against above recommendation and create identical
copies of a repo (using some copy / sync / clone tool).

While this might be better than having no redundancy at all, you have
to be very careful about how you do that and what you may / must not
do with the result (if you decide against our recommendation).

What you would get with this is:

- client machine ---borg create---> repo
- repo ---copy/sync---> copy-of-repo

There is no special borg command to do the copying, you could just
use any reliable tool that creates an identical copy (cp, rsync, rclone
might be options).

But think about whether that is really what you want. If something goes
wrong in repo, you will have the same issue in copy-of-repo.

Make sure you do the copy/sync while no backup is running, see
:ref:`borg_with-lock` about how to do that.

Also, you must not run borg against multiple instances of the same repo
(like repo and copy-of-repo) as that would create severe issues:

- Data loss: they have the same repository ID, so the borg client will
  think they are identical and e.g. use the same local cache for them
  (which is an issue if they happen to be not the same).
  See :issue:`4272` for an example.
- Encryption security issues if you would update repo and copy-of-repo
  independently, due to AES counter reuse.

There is also a similar encryption security issue for the disaster case:
If you lose repo and the borg client-side config/cache and you restore
the repo from an older copy-of-repo, you also run into AES counter reuse.

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
    * Some filesystem specific attributes, like btrfs NOCOW, see :ref:`platforms`.
    * For hardlinked symlinks, the hardlinking can not be archived (and thus,
      the hardlinking will not be done at extraction time). The symlinks will
      be archived and extracted as non-hardlinked symlinks, see :issue:`2379`.

Are there other known limitations?
----------------------------------

- A single archive can only reference a limited volume of file/dir metadata,
  usually corresponding to tens or hundreds of millions of files/dirs.
  When trying to go beyond that limit, you will get a fatal IntegrityError
  exception telling that the (archive) object is too big.
  An easy workaround is to create multiple archives with fewer items each.
  See also the :ref:`archive_limitation` and :issue:`1452`.

  :ref:`borg_info` shows how large (relative to the maximum size) existing
  archives are.

.. _checkpoints_parts:

If a backup stops mid-way, does the already-backed-up data stay there?
----------------------------------------------------------------------

Yes, Borg supports resuming backups.

During a backup a special checkpoint archive named ``<archive-name>.checkpoint``
is saved every checkpoint interval (the default value for this is 30
minutes) containing all the data backed-up until that point.

This checkpoint archive is a valid archive,
but it is only a partial backup (not all files that you wanted to backup are
contained in it). Having it in the repo until a successful, full backup is
completed is useful because it references all the transmitted chunks up
to the checkpoint. This means that in case of an interruption, you only need to
retransfer the data since the last checkpoint.

If a backup was interrupted, you normally do not need to do anything special,
just invoke ``borg create`` as you always do. If the repository is still locked,
you may need to run ``borg break-lock`` before the next backup. You may use the
same archive name as in previous attempt or a different one (e.g. if you always
include the current datetime), it does not matter.

Borg always does full single-pass backups, so it will start again
from the beginning - but it will be much faster, because some of the data was
already stored into the repo (and is still referenced by the checkpoint
archive), so it does not need to get transmitted and stored again.

Once your backup has finished successfully, you can delete all
``<archive-name>.checkpoint`` archives. If you run ``borg prune``, it will
also care for deleting unneeded checkpoints.

Note: the checkpointing mechanism creates hidden, partial files in an archive,
so that checkpoints even work while a big file is being processed.
They are named ``<filename>.borg_part_<N>`` and all operations usually ignore
these files, but you can make them considered by giving the option
``--consider-part-files``. You usually only need that option if you are
really desperate (e.g. if you have no completed backup of that file and you'ld
rather get a partial file extracted than nothing). You do **not** want to give
that option under any normal circumstances.

Note that checkpoints inside files are created only since version 1.1, 
make sure you have an up-to-date version of borgbackup if you want to continue instead of retransferring a huge file.
In some cases, there is only an outdated version shipped with your distribution (e.g. Debian). See :ref:`_installation`

How can I backup huge file(s) over a unstable connection?
---------------------------------------------------------

This is not a problem anymore.

For more details, see :ref:`checkpoints_parts`.

How can I restore huge file(s) over an unstable connection?
-----------------------------------------------------------

If you cannot manage to extract the whole big file in one go, you can extract
all the part files and manually concatenate them together.

For more details, see :ref:`checkpoints_parts`.

Can Borg add redundancy to the backup data to deal with hardware malfunction?
-----------------------------------------------------------------------------

No, it can't. While that at first sounds like a good idea to defend against
some defect HDD sectors or SSD flash blocks, dealing with this in a
reliable way needs a lot of low-level storage layout information and
control which we do not have (and also can't get, even if we wanted).

So, if you need that, consider RAID or a filesystem that offers redundant
storage or just make backups to different locations / different hardware.

See also :issue:`225`.

Can Borg verify data integrity of a backup archive?
---------------------------------------------------

Yes, if you want to detect accidental data damage (like bit rot), use the
``check`` operation. It will notice corruption using CRCs and hashes.
If you want to be able to detect malicious tampering also, use an encrypted
repo. It will then be able to check using CRCs and HMACs.

Can I use Borg on SMR hard drives?
----------------------------------

SMR (shingled magnetic recording) hard drives are very different from
regular hard drives. Applications have to behave in certain ways or
performance will be heavily degraded.

Borg 1.1 ships with default settings suitable for SMR drives,
and has been successfully tested on *Seagate Archive v2* drives
using the ext4 file system.

Some Linux kernel versions between 3.19 and 4.5 had various bugs
handling device-managed SMR drives, leading to IO errors, unresponsive
drives and unreliable operation in general.

For more details, refer to :issue:`2252`.

.. _faq-integrityerror:

I get an IntegrityError or similar - what now?
----------------------------------------------

A single error does not necessarily indicate bad hardware or a Borg
bug. All hardware exhibits a bit error rate (BER). Hard drives are typically
specified as exhibiting fewer than one error every 12 to 120 TB
(one bit error in 10e14 to 10e15 bits). The specification is often called
*unrecoverable read error rate* (URE rate).

Apart from these very rare errors there are two main causes of errors:

(i) Defective hardware: described below.
(ii) Bugs in software (Borg, operating system, libraries):
     Ensure software is up to date.
     Check whether the issue is caused by any fixed bugs described in :ref:`important_notes`.


.. rubric:: Finding defective hardware

.. note::

   Hardware diagnostics are operating system dependent and do not
   apply universally. The commands shown apply for popular Unix-like
   systems. Refer to your operating system's manual.

Checking hard drives
  Find the drive containing the repository and use *findmnt*, *mount* or *lsblk*
  to learn the device path (typically */dev/...*) of the drive.
  Then, smartmontools can retrieve self-diagnostics of the drive in question::

      # smartctl -a /dev/sdSomething

  The *Offline_Uncorrectable*, *Current_Pending_Sector* and *Reported_Uncorrect*
  attributes indicate data corruption. A high *UDMA_CRC_Error_Count* usually
  indicates a bad cable.

  I/O errors logged by the system (refer to the system journal or
  dmesg) can point to issues as well. I/O errors only affecting the
  file system easily go unnoticed, since they are not reported to
  applications (e.g. Borg), while these errors can still corrupt data.

  Drives can corrupt some sectors in one event, while remaining
  reliable otherwise. Conversely, drives can fail completely with no
  advance warning. If in doubt, copy all data from the drive in
  question to another drive -- just in case it fails completely.

  If any of these are suspicious, a self-test is recommended::

      # smartctl -t long /dev/sdSomething

  Running ``fsck`` if not done already might yield further insights.

Checking memory
  Intermittent issues, such as ``borg check`` finding errors
  inconsistently between runs, are frequently caused by bad memory.

  Run memtest86+ (or an equivalent memory tester) to verify that
  the memory subsystem is operating correctly.

Checking processors
  Processors rarely cause errors. If they do, they are usually overclocked
  or otherwise operated outside their specifications. We do not recommend to
  operate hardware outside its specifications for productive use.

  Tools to verify correct processor operation include Prime95 (mprime), linpack,
  and the `Intel Processor Diagnostic Tool
  <https://downloadcenter.intel.com/download/19792/Intel-Processor-Diagnostic-Tool>`_
  (applies only to Intel processors).

.. rubric:: Repairing a damaged repository

With any defective hardware found and replaced, the damage done to the repository
needs to be ascertained and fixed.

:ref:`borg_check` provides diagnostics and ``--repair`` options for repositories with
issues. We recommend to first run without ``--repair`` to assess the situation.
If the found issues and proposed repairs seem right, re-run "check" with ``--repair`` enabled.

Why is the time elapsed in the archive stats different from wall clock time?
----------------------------------------------------------------------------

Borg needs to write the time elapsed into the archive metadata before finalizing
the archive, compacting the segments, and committing the repo & cache. This means
when Borg is run with e.g. the ``time`` command, the duration shown in the archive
stats may be shorter than the full time the command runs for.

How do I configure different prune policies for different directories?
----------------------------------------------------------------------

Say you want to prune ``/var/log`` faster than the rest of
``/``. How do we implement that? The answer is to backup to different
archive *names* and then implement different prune policies for
different prefixes. For example, you could have a script that does::

    borg create --exclude /var/log $REPOSITORY:main-$(date +%Y-%m-%d) /
    borg create $REPOSITORY:logs-$(date +%Y-%m-%d) /var/log

Then you would have two different prune calls with different policies::

    borg prune --verbose --list -d 30 --prefix main- "$REPOSITORY"
    borg prune --verbose --list -d 7  --prefix logs- "$REPOSITORY"

This will keep 7 days of logs and 30 days of everything else. Borg 1.1
also supports the ``--glob-archives`` parameter.

How do I remove files from an existing backup?
----------------------------------------------

Say you now want to remove old logfiles because you changed your
backup policy as described above. The only way to do this is to use
the :ref:`borg_recreate` command to rewrite all archives with a
different ``--exclude`` pattern. See the examples in the
:ref:`borg_recreate` manpage for more information.

Can I safely change the compression level or algorithm?
--------------------------------------------------------

The compression level and algorithm don't affect deduplication. Chunk ID hashes
are calculated *before* compression. New compression settings
will only be applied to new chunks, not existing chunks. So it's safe
to change them.


Security
########

How can I specify the encryption passphrase programmatically?
-------------------------------------------------------------

There are several ways to specify a passphrase without human intervention:

Setting ``BORG_PASSPHRASE``
  The passphrase can be specified using the ``BORG_PASSPHRASE`` enviroment variable.
  This is often the simplest option, but can be insecure if the script that sets it
  is world-readable.

  .. _password_env:
  .. note:: Be careful how you set the environment; using the ``env``
          command, a ``system()`` call or using inline shell scripts
          (e.g. ``BORG_PASSPHRASE=hunter2 borg ...``)
          might expose the credentials in the process list directly
          and they will be readable to all users on a system. Using
          ``export`` in a shell script file should be safe, however, as
          the environment of a process is `accessible only to that
          user
          <https://security.stackexchange.com/questions/14000/environment-variable-accessibility-in-linux/14009#14009>`_.

Using ``BORG_PASSCOMMAND`` with a properly permissioned file
  Another option is to create a file with a password in it in your home
  directory and use permissions to keep anyone else from reading it. For
  example, first create a key::

    head -c 1024 /dev/urandom | base64 > ~/.borg-passphrase
    chmod 400 ~/.borg-passphrase

  Then in an automated script one can put::

    export BORG_PASSCOMMAND="cat $HOME/.borg-passphrase"

  and Borg will automatically use that passphrase.

Using keyfile-based encryption with a blank passphrase
  It is possible to encrypt your repository in ``keyfile`` mode instead of the default
  ``repokey`` mode and use a blank passphrase for the key file (simply press Enter twice
  when ``borg init`` asks for the password). See :ref:`encrypted_repos`
  for more details.

Using ``BORG_PASSCOMMAND`` with macOS Keychain
  macOS has a native manager for secrets (such as passphrases) which is safer
  than just using a file as it is encrypted at rest and unlocked manually
  (fortunately, the login keyring automatically unlocks when you login). With
  the built-in ``security`` command, you can access it from the command line,
  making it useful for ``BORG_PASSCOMMAND``.

  First generate a passphrase and use ``security`` to save it to your login
  (default) keychain::

    security add-generic-password -D secret -U -a $USER -s borg-passphrase -w $(head -c 1024 /dev/urandom | base64)

  In your backup script retrieve it in the ``BORG_PASSCOMMAND``::

    export BORG_PASSCOMMAND="security find-generic-password -a $USER -s borg-passphrase -w"

Using ``BORG_PASSCOMMAND`` with GNOME Keyring
  GNOME also has a keyring daemon that can be used to store a Borg passphrase.
  First ensure ``libsecret-tools``, ``gnome-keyring`` and ``libpam-gnome-keyring``
  are installed. If ``libpam-gnome-keyring`` wasn't already installed, ensure it
  runs on login::

    sudo sh -c "echo session optional pam_gnome_keyring.so auto_start >> /etc/pam.d/login"
    sudo sh -c "echo password optional pam_gnome_keyring.so >> /etc/pam.d/passwd"
    # you may need to relogin afterwards to activate the login keyring

  Then add a secret to the login keyring::

    head -c 1024 /dev/urandom | base64 | secret-tool store borg-repository repo-name --label="Borg Passphrase"

  If a dialog box pops up prompting you to pick a password for a new keychain, use your
  login password. If there is a checkbox for automatically unlocking on login, check it
  to allow backups without any user intervention whatsoever.

  Once the secret is saved, retrieve it in a backup script using ``BORG_PASSCOMMAND``::

    export BORG_PASSCOMMAND="secret-tool lookup borg-repository repo-name"

  .. note:: For this to automatically unlock the keychain it must be run
    in the ``dbus`` session of an unlocked terminal; for example, running a backup
    script as a ``cron`` job might not work unless you also ``export DISPLAY=:0``
    so ``secret-tool`` can pick up your open session. `It gets even more complicated`__
    when you are running the tool as a different user (e.g. running a backup as root
    with the password stored in the user keyring).

__ https://github.com/borgbackup/borg/pull/2837#discussion_r127641330

Using ``BORG_PASSCOMMAND`` with KWallet
  KDE also has a keychain feature in the form of KWallet. The command-line tool
  ``kwalletcli`` can be used to store and retrieve secrets. Ensure ``kwalletcli``
  is installed, generate a passphrase, and store it in your "wallet"::

    head -c 1024 /dev/urandom | base64 | kwalletcli -Pe borg-passphrase -f Passwords

  Once the secret is saved, retrieve it in a backup script using ``BORG_PASSCOMMAND``::

    export BORG_PASSCOMMAND="kwalletcli -e borg-passphrase -f Passwords"

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

How do I report a security issue with Borg?
-------------------------------------------

Send a private email to the :ref:`security contact <security-contact>`
if you think you have discovered a security issue.
Please disclose security issues responsibly.

Common issues
#############

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
serialized way in a single script, you need to give them ``--lock-wait N`` (with N
being a bit more than the time the server needs to terminate broken down
connections and release the lock).

.. _disable_archive_chunks:

The borg cache eats way too much disk space, what can I do?
-----------------------------------------------------------

There is a temporary (but maybe long lived) hack to avoid using lots of disk
space for chunks.archive.d (see :issue:`235` for details):

::

    # this assumes you are working with the same user as the backup.
    cd ~/.cache/borg/$(borg config /path/to/repo id)
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

Can I backup my root partition (/) with Borg?
---------------------------------------------

Backing up your entire root partition works just fine, but remember to
exclude directories that make no sense to backup, such as /dev, /proc,
/sys, /tmp and /run, and to use ``--one-file-system`` if you only want to
backup the root partition (and not any mounted devices e.g.).

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

.. _a_status_oddity:

I am seeing 'A' (added) status for an unchanged file!?
------------------------------------------------------

The files cache is used to determine whether Borg already
"knows" / has backed up a file and if so, to skip the file from
chunking. It does intentionally *not* contain files that have a modification
time (mtime) same as the newest mtime in the created archive.

So, if you see an 'A' status for unchanged file(s), they are likely the files
with the most recent mtime in that archive.

This is expected: it is to avoid data loss with files that are backed up from
a snapshot and that are immediately changed after the snapshot (but within
mtime granularity time, so the mtime would not change). Without the code that
removes these files from the files cache, the change that happened right after
the snapshot would not be contained in the next backup as Borg would
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

Borg maintains a files cache where it remembers the mtime, size and
inode of files. When Borg does a new backup and starts processing a
file, it first looks whether the file has changed (compared to the values
stored in the files cache). If the values are the same, the file is assumed
unchanged and thus its contents won't get chunked (again).

Borg can't keep an infinite history of files of course, thus entries
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
example if you mount a filesystem without stable mount points for each backup or if you are running the backup from a filesystem snapshot whose name is not stable.
If the directory where you mount a filesystem is different every time,
Borg assume they are different files.


Is there a way to limit bandwidth with Borg?
--------------------------------------------

To limit upload (i.e. :ref:`borg_create`) bandwidth, use the
``--remote-ratelimit`` option.

There is no built-in way to limit *download*
(i.e. :ref:`borg_extract`) bandwidth, but limiting download bandwidth
can be accomplished with pipeviewer_:

Create a wrapper script:  /usr/local/bin/pv-wrapper  ::

    #!/bin/sh
        ## -q, --quiet              do not output any transfer information at all
        ## -L, --rate-limit RATE    limit transfer to RATE bytes per second
    RATE=307200
    pv -q -L $RATE  | "$@"

Add BORG_RSH environment variable to use pipeviewer wrapper script with ssh. ::

    export BORG_RSH='/usr/local/bin/pv-wrapper ssh'

Now Borg will be bandwidth limited. Nice thing about pv is that you can change rate-limit on the fly: ::

    pv -R $(pidof pv) -L 102400

.. _pipeviewer: http://www.ivarch.com/programs/pv.shtml


I am having troubles with some network/FUSE/special filesystem, why?
--------------------------------------------------------------------

Borg is doing nothing special in the filesystem, it only uses very
common and compatible operations (even the locking is just "mkdir").

So, if you are encountering issues like slowness, corruption or malfunction
when using a specific filesystem, please try if you can reproduce the issues
with a local (non-network) and proven filesystem (like ext4 on Linux).

If you can't reproduce the issue then, you maybe have found an issue within
the filesystem code you used (not with Borg). For this case, it is
recommended that you talk to the developers / support of the network fs and
maybe open an issue in their issue tracker. Do not file an issue in the
Borg issue tracker.

If you can reproduce the issue with the proven filesystem, please file an
issue in the Borg issue tracker about that.


Why does running 'borg check --repair' warn about data loss?
------------------------------------------------------------

Repair usually works for recovering data in a corrupted archive. However,
it's impossible to predict all modes of corruption. In some very rare
instances, such as malfunctioning storage hardware, additional repo
corruption may occur. If you can't afford to lose the repo, it's strongly
recommended that you perform repair on a copy of the repo.

In other words, the warning is there to emphasize that Borg:
  - Will perform automated routines that modify your backup repository
  - Might not actually fix the problem you are experiencing
  - Might, in very rare cases, further corrupt your repository

In the case of malfunctioning hardware, such as a drive or USB hub
corrupting data when read or written, it's best to diagnose and fix the
cause of the initial corruption before attempting to repair the repo. If
the corruption is caused by a one time event such as a power outage,
running `borg check --repair` will fix most problems.


Why isn't there more progress / ETA information displayed?
----------------------------------------------------------

Some borg runs take quite a bit, so it would be nice to see a progress display,
maybe even including a ETA (expected time of "arrival" [here rather "completion"]).

For some functionality, this can be done: if the total amount of work is more or
less known, we can display progress. So check if there is a ``--progress`` option.

But sometimes, the total amount is unknown (e.g. for ``borg create`` we just do
a single pass over the filesystem, so we do not know the total file count or data
volume before reaching the end). Adding another pass just to determine that would
take additional time and could be incorrect, if the filesystem is changing.

Even if the fs does not change and we knew count and size of all files, we still
could not compute the ``borg create`` ETA as we do not know the amount of changed
chunks, how the bandwidth of source and destination or system performance might
fluctuate.

You see, trying to display ETA would be futile. The borg developers prefer to
rather not implement progress / ETA display than doing futile attempts.

See also: https://xkcd.com/612/


Why am I getting 'Operation not permitted' errors when backing up on sshfs?
---------------------------------------------------------------------------

By default, ``sshfs`` is not entirely POSIX-compliant when renaming files due to
a technicality in the SFTP protocol. Fortunately, it also provides a workaround_
to make it behave correctly::

    sshfs -o workaround=rename user@host:dir /mnt/dir

.. _workaround: https://unix.stackexchange.com/a/123236


Can I disable checking for free disk space?
-------------------------------------------

In some cases, the free disk space of the target volume is reported incorrectly.
This can happen for CIFS- or FUSE shares. If you are sure that your target volume
will always have enough disk space, you can use the following workaround to disable
checking for free disk space::

    borg config -- $REPO_LOCATION additional_free_space -2T


Miscellaneous
#############

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

Migrating from Attic
####################

What are the differences between Attic and Borg?
------------------------------------------------

Borg is a fork of `Attic`_ and maintained by "`The Borg collective`_".

.. _Attic: https://github.com/jborg/attic
.. _The Borg collective: https://borgbackup.readthedocs.org/en/latest/authors.html

Here's a (incomplete) list of some major changes:

* lots of attic issues fixed (see `issue #5 <https://github.com/borgbackup/borg/issues/5>`_),
  including critical data corruption bugs and security issues.
* more open, faster paced development (see `issue #1 <https://github.com/borgbackup/borg/issues/1>`_)
* less chunk management overhead (less memory and disk usage for chunks index)
* faster remote cache resync (useful when backing up multiple machines into same repo)
* compression: no, lz4, zstd, zlib or lzma compression, adjustable compression levels
* repokey replaces problematic passphrase mode (you can't change the passphrase nor the pbkdf2 iteration count in "passphrase" mode)
* simple sparse file support, great for virtual machine disk files
* can read special files (e.g. block devices) or from stdin, write to stdout
* mkdir-based locking is more compatible than attic's posix locking
* uses fadvise to not spoil / blow up the fs cache
* better error messages / exception handling
* better logging, screen output, progress indication
* tested on misc. Linux systems, 32 and 64bit, FreeBSD, OpenBSD, NetBSD, macOS

Please read the :ref:`changelog` (or ``docs/changes.rst`` in the source distribution) for more
information.

Borg is not compatible with original Attic (but there is a one-way conversion).

How do I migrate from Attic to Borg?
------------------------------------

Use :ref:`borg_upgrade`. This is a one-way process that cannot be reversed.

There are some caveats:

- The upgrade can only be performed on local repositories.
  It cannot be performed on remote repositories.

- If the repository is in "keyfile" encryption mode, the keyfile must
  exist locally or it must be manually moved after performing the upgrade:

  1. Get the repository ID with ``borg config /path/to/repo id``.
  2. Locate the attic key file at ``~/.attic/keys/``. The correct key for the
     repository starts with the line ``ATTIC_KEY <repository id>``.
  3. Copy the attic key file to ``~/.config/borg/keys/``
  4. Change the first line from ``ATTIC_KEY ...`` to ``BORG_KEY ...``.
  5. Verify that the repository is now accessible (e.g. ``borg list <repository>``).
- Attic and Borg use different :ref:`"chunker params" <chunker-params>`.
  This means that data added by Borg won't deduplicate with the existing data
  stored by Attic. The effect is lessened if the files cache is used with Borg.
- Repositories in "passphrase" mode *must* be migrated to "repokey" mode using
  :ref:`borg_key_migrate-to-repokey`. Borg does not support the "passphrase" mode
  any other way.

Why is my backup bigger than with attic?
----------------------------------------

Attic was rather unflexible when it comes to compression, it always
compressed using zlib level 6 (no way to switch compression off or
adjust the level or algorithm).

The default in Borg is lz4, which is fast enough to not use significant CPU time
in most cases, but can only achieve modest compression. It still compresses
easily compressed data fairly well.

Borg also offers zstd, zlib and lzma compression, choose wisely.

Which choice is the best option depends on a number of factors, like
bandwidth to the repository, how well the data compresses, available CPU
power and so on.
