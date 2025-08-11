.. include:: global.rst.inc
.. highlight:: none
.. _faq:

Frequently asked questions
==========================

Usage & Limitations
###################

What is the difference between a repo on an external hard drive vs. repo on a server?
-------------------------------------------------------------------------------------

If Borg is running in client/server mode, the client uses SSH as a transport to
talk to the remote agent, which is another Borg process (Borg is installed on
the server, too) started automatically by the client. The Borg server is doing
storage-related low-level repo operations (get, put, commit, check, compact),
while the Borg client does the high-level stuff: deduplication, encryption,
compression, dealing with archives, backups, restores, etc., which reduces the
amount of data that goes over the network.

When Borg is writing to a repo on a locally mounted remote file system, e.g.
SSHFS, the Borg client only can do file system operations and has no agent
running on the remote side, so *every* operation needs to go over the network,
which is slower.

Can I backup from multiple servers into a single repository?
------------------------------------------------------------

Yes, this is *possible* from the technical standpoint, but it is
*not recommended* from the security perspective. BorgBackup is
built upon a defined :ref:`attack_model` that cannot provide its
guarantees for multiple clients using the same repository. See
:ref:`borg_security_critique` for a detailed explanation.

Also, in order for the deduplication used by Borg to work, it
needs to keep a local cache containing checksums of all file
chunks already stored in the repository. This cache is stored in
``~/.cache/borg/``.  If Borg detects that a repository has been
modified since the local cache was updated it will need to rebuild
the cache. This rebuild can be quite time consuming.

So, yes it's possible. But it will be most efficient if a single
repository is only modified from one place. Also keep in mind that
Borg will keep an exclusive lock on the repository while creating
or deleting archives, which may make *simultaneous* backups fail.

Can I back up to multiple, swapped backup targets?
--------------------------------------------------

It is possible to swap your backup disks if each backup medium is assigned its
own repository by creating a new one with :ref:`borg_init`.

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

See also: :ref:`faq_corrupt_repo`

"this is either an attack or unsafe" warning
--------------------------------------------

About the warning:

  Cache, or information obtained from the security directory is newer than
  repository - this is either an attack or unsafe (multiple repos with same ID)

"unsafe": If not following the advice from the previous section, you can easily
run into this by yourself by restoring an older copy of your repository.

"attack": maybe an attacker has replaced your repo by an older copy, trying to
trick you into AES counter reuse, trying to break your repo encryption.

Borg users have also reported that fs issues (like hw issues / I/O errors causing
the fs to become read-only) can cause this warning, see :issue:`7853`.

If you'ld decide to ignore this and accept unsafe operation for this repository,
you could delete the manifest-timestamp and the local cache:

::

  borg config repo id   # shows the REPO_ID
  rm ~/.config/borg/security/REPO_ID/manifest-timestamp
  borg delete --cache-only REPO

This is an unsafe and unsupported way to use borg, you have been warned.

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
- borg extract only supports restoring into an empty destination. After that,
  the destination will exactly have the contents of the extracted archive.
  If you extract into a non-empty destination, borg will (for example) not
  remove files which are in the destination, but not in the archive.
  See :issue:`4598` for a workaround and more details.

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

Note that checkpoints inside files are created only since version 1.1, make
sure you have an up-to-date version of borgbackup if you want to continue
instead of retransferring a huge file. In some cases, there is only an outdated
version shipped with your distribution (e.g. Debian). See :ref:`installation`.

How can I backup huge file(s) over a unstable connection?
---------------------------------------------------------

This is not a problem anymore.

For more details, see :ref:`checkpoints_parts`.

How can I switch append-only mode on and off?
---------------------------------------------

You could do that (via borg config REPO append_only 0/1), but using different
ssh keys and different entries in ``authorized_keys`` is much easier and also
maybe has less potential of things going wrong somehow.


My machine goes to sleep causing `Broken pipe`
----------------------------------------------

While backing up your data over the network, your machine should not go to sleep.
On Linux you can use `systemd-inhibit` to avoid that. On macOS you can use `caffeinate`.

``systemd-inhibit borg create ...``

``caffeinate -i borg create ...``

How can I restore huge file(s) over an unstable connection?
-----------------------------------------------------------

If you cannot manage to extract the whole big file in one go, you can extract
all the part files and manually concatenate them together.

For more details, see :ref:`checkpoints_parts`.

How can I compare contents of an archive to my local filesystem?
-----------------------------------------------------------------

You can instruct ``export-tar`` to send a tar stream to the stdout, and
then use ``tar`` to perform the comparison:

::

    borg export-tar /path/to/repo::archive-name - | tar --compare -f - -C /path/to/compare/to


.. _faq_corrupt_repo:

My repository is corrupt, how can I restore from an older copy of it?
---------------------------------------------------------------------

If your repositories are encrypted and have the same ID, the recommended method
is to delete the corrupted repository, but keep its security info, and then copy
the working repository to the same location:

::

    borg delete --keep-security-info /path/to/repo
    rsync -aH /path/to/repo-working/ /path/to/repo  # Note the trailing slash.

A plain delete command would remove the security info in
``~/.config/borg/security``, including the nonce value. In BorgBackup
:ref:`security_encryption` is AES-CTR, where the nonce is a counter. When the
working repo was used later for creating new archives, Borg would re-use nonce
values due to starting from a lower counter value given by the older copy of the
repository. To prevent this, the ``keep-security-info`` option is applied so
that the client-side nonce counter is kept.

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
     Check whether the issue is caused by any fixed bugs described in
     :ref:`important_notes`.

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

How probable is it to get a hash collision problem?
---------------------------------------------------

If you noticed, there are some issues (:issue:`170` (**warning: hell**) and :issue:`4884`)
about the probability of a chunk having the same hash as another chunk, making the file
corrupted because it grabbed the wrong chunk. This is called the `Birthday Problem
<https://en.wikipedia.org/wiki/Birthday_problem>`_.

There is a lot of probability in here so, I can give you my interpretation of
such math but it's honestly better that you read it yourself and grab your own
resolution from that.

Assuming that all your chunks have a size of :math:`2^{21}` bytes (approximately 2.1 MB)
and we have a "perfect" hash algorithm, we can think that the probability of collision
would be of :math:`p^2/2^{n+1}` then, using SHA-256 (:math:`n=256`) and for example
we have 1000 million chunks (:math:`p=10^9`) (1000 million chunks would be about 2100TB).
The probability would be around to 0.0000000000000000000000000000000000000000000000000000000000043.

A mass-murderer space rock happens about once every 30 million years on average.
This leads to a probability of such an event occurring in the next second to about :math:`10^{-15}`.
That's **45** orders of magnitude more probable than the SHA-256 collision. Briefly stated,
if you find SHA-256 collisions scary then your priorities are wrong. This example was grabbed from
`this SO answer <https://stackoverflow.com/a/4014407/13359375>`_, it's great honestly.

Still, the real question is if Borg tries to not make this happen?

Well... it used to not check anything but there was a feature added which saves the size
of the chunks too, so the size of the chunks is compared to the size that you got with the
hash and if the check says there is a mismatch it will raise an exception instead of corrupting
the file. This doesn't save us from everything but reduces the chances of corruption.
There are other ways of trying to escape this but it would affect performance so much that
it wouldn't be worth it and it would contradict Borg's design, so if you don't want this to
happen, simply don't use Borg.

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
different --glob-archives matching patterns.

For example, you could have a script that does::

    borg create --exclude var/log $REPOSITORY:main-$(date +%Y-%m-%d) /
    borg create $REPOSITORY:logs-$(date +%Y-%m-%d) /var/log

Then you would have two different prune calls with different policies::

    borg prune --verbose --list -d 30 --glob-archives 'main-*' "$REPOSITORY"
    borg prune --verbose --list -d 7  --glob-archives 'logs-*' "$REPOSITORY"

This will keep 7 days of logs and 30 days of everything else.

How do I remove files from an existing backup?
----------------------------------------------

A file is only removed from a BorgBackup repository if all archives that contain
the file are deleted and the corresponding data chunks are removed from the
repository There are two ways how to remove files from a repository.

1. Use :ref:`borg_delete` to remove all archives that contain the files. This
will of course delete everything in the archive, not only some files.

2. If you really want to remove only some specific files, you can run the
:ref:`borg_recreate` command to rewrite all archives with a different
``--exclude`` pattern. See the examples in the manpage for more information.

Finally, run :ref:`borg_compact` with the ``--threshold 0`` option to delete the
data chunks from the repository.

Can I safely change the compression level or algorithm?
--------------------------------------------------------

The compression level and algorithm don't affect deduplication. Chunk ID hashes
are calculated *before* compression. New compression settings
will only be applied to new chunks, not existing chunks. So it's safe
to change them.


Why is backing up an unmodified FAT filesystem slow on Linux?
-------------------------------------------------------------

By default, the files cache used by BorgBackup considers the inode of files.
When an inode number changes compared to the last backup, it hashes the file
again. The ``vfat`` kernel driver does not produce stable inode numbers by
default.  One way to achieve stable inode numbering is mounting the filesystem
using ``nfs=nostale_ro``. Doing so implies mounting the filesystem read-only.
Another option is to not consider inode numbers in the files cache by passing
``--files-cache=ctime,size``.

Why are backups slow on a Linux server that is a member of a Windows domain?
----------------------------------------------------------------------------

If a Linux server is a member of a Windows domain, username to userid resolution might be 
performed via ``winbind`` without caching, which can slow down backups significantly. 
You can use e.g. ``nscd`` to add caching and improve the speed.

Security
########

.. _borg_security_critique:

Isn't BorgBackup's AES-CTR crypto broken?
-----------------------------------------

If a nonce (counter) value is reused, AES-CTR mode crypto is broken.

To exploit the AES counter management issue, an attacker would need to have
access to the borg repository.

By tampering with the repo, the attacker could bring the repo into a state so
that it reports a lower "highest used counter value" than the one that actually
was used. The client would usually notice that, because it rather trusts the
clientside stored "highest used counter value" than trusting the server.

But there are situations, where this is simply not possible:

- If clients A and B used the repo, the client A can only know its own highest
  CTR value, but not the one produced by B. That is only known to (B and) the
  server (the repo) and thus the client A needs to trust the server about the
  value produced by B in that situation. You can't do much about this except
  not having multiple clients per repo.

- Even if there is only one client, if client-side information is completely
  lost (e.g. due to disk defect), the client also needs to trust the value from
  server side. You can avoid this by not continuing to write to the repository
  after you have lost clientside borg information.

.. _home_config_borg:

How important is the $HOME/.config/borg directory?
--------------------------------------------------

The Borg config directory has content that you should take care of:

``security`` subdirectory
  Each directory here represents one Borg repository by its ID and contains the last known status.
  If a repository's status is different from this information at the beginning of BorgBackup
  operation, Borg outputs warning messages and asks for confirmation, so make sure you do not lose
  or manipulate these files. However, apart from those warnings, a loss of these files can be
  recovered.

``keys`` subdirectory
  All your borg keyfile keys are stored in this directory. Please note that
  borg repokey keys are stored inside the repository. You MUST make sure to have an
  independent backup of these keyfiles, otherwise you cannot access your backups anymore if you lose
  them. You also MUST keep these files secret; everyone who gains access to your repository and has
  the corresponding keyfile (and the key passphrase) can extract it.

Make sure that only you have access to the Borg config directory.

.. _cache_security:

Do I need to take security precautions regarding the cache?
-----------------------------------------------------------

The cache contains a lot of metadata information about the files in
your repositories and it is not encrypted.

However, the assumption is that the cache is being stored on the very
same system which also contains the original files which are being
backed up. So someone with access to the cache files would also have
access the original files anyway.

The Internals section contains more details about :ref:`cache`. If you ever need to move the cache
to a different location, this can be achieved by using the appropriate :ref:`env_vars`.

How can I specify the encryption passphrase programmatically?
-------------------------------------------------------------

There are several ways to specify a passphrase without human intervention:

Setting ``BORG_PASSPHRASE``
  The passphrase can be specified using the ``BORG_PASSPHRASE`` environment variable.
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

    (umask 0077; head -c 32 /dev/urandom | base64 -w 0 > ~/.borg-passphrase)

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

    security add-generic-password -D secret -U -a $USER -s borg-passphrase -w $(head -c 32 /dev/urandom | base64 -w 0)

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

    head -c 32 /dev/urandom | base64 -w 0 | secret-tool store borg-repository repo-name --label="Borg Passphrase"

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

    head -c 32 /dev/urandom | base64 -w 0 | kwalletcli -Pe borg-passphrase -f Passwords

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
- Use a pull-mode setup using ``ssh -R``, see :ref:`pull_backup` for more information.
- Mount C's filesystem on another machine and then create a backup of it.
- Do not give C filesystem-level access to S.

See :ref:`hosting_repositories` for a detailed protection guide.

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

How important are the nonce files?
------------------------------------

Borg uses :ref:`AES-CTR encryption <borg_security_critique>`. An
essential part of AES-CTR is a sequential counter that must **never**
repeat. If the same value of the counter is used twice in the same repository,
an attacker can decrypt the data. The counter is stored in the home directory
of each user ($HOME/.config/borg/security/$REPO_ID/nonce) as well as
in the repository (/path/to/repo/nonce). When creating a new archive borg uses
the highest of the two values. The value of the counter in the repository may be
higher than your local value if another user has created an archive more recently
than you did.

Since the nonce is not necessary to read the data that is already encrypted,
``borg info``, ``borg list``, ``borg extract`` and ``borg mount`` should work
just fine without it.

If the nonce file stored in the repo is lost, but you still have your local copy,
borg will recreate the repository nonce file the next time you run ``borg create``.
This should be safe for repositories that are only used from one user account
on one machine.

For repositories that are used by multiple users and/or from multiple machines
it is safest to avoid running *any* commands that modify the repository after
the nonce is deleted or if you suspect it may have been tampered with. See :ref:`attack_model`.

Common issues
#############

/path/to/repo is not a valid repository. Check repo config.
-----------------------------------------------------------

There can be many causes of this error. E.g. you have incorrectly specified the repository path.

You will also get this error if you try to access a repository that uses the argon2 key algorithm using an old version of borg.
We recommend upgrading to the latest stable version and trying again. We are sorry. We should have thought abount forward
compatibility and implemented a more helpful error message.

Why am I seeing idle borg serve processes on the repo server?
-------------------------------------------------------------

Please see the next question.

Why does Borg disconnect or hang when backing up to a remote server?
--------------------------------------------------------------------

Communication with the remote server (using an ssh: repo URL) happens via an SSH
connection. This can lead to some issues that would not occur during a local backup:

- Since Borg does not send data all the time, the connection may get closed, leading
  to errors like "connection closed by remote".
- On the other hand, network issues may lead to a dysfunctional connection
  that is only detected after some time by the server, leading to stale ``borg serve``
  processes and locked repositories.

To fix such problems, please apply these :ref:`SSH settings <ssh_configuration>` so that
keep-alive requests are sent regularly.

How can I deal with my very unstable SSH connection?
----------------------------------------------------

If you have issues with lost connections during long-running borg commands, you
could try to work around:

- Make partial extracts like ``borg extract REPO PATTERN`` to do multiple
  smaller extraction runs that complete before your connection has issues.
- Try using ``borg mount REPO MOUNTPOINT`` and ``rsync -avH`` from
  ``MOUNTPOINT`` to your desired extraction directory. If the connection breaks
  down, just repeat that over and over again until rsync does not find anything
  to do any more. Due to the way borg mount works, this might be less efficient
  than borg extract for bigger volumes of data.


.. _disable_archive_chunks:

The borg cache eats way too much disk space, what can I do?
-----------------------------------------------------------

This may especially happen if borg needs to rebuild the local "chunks" index -
either because it was removed, or because it was not coherent with the
repository state any more (e.g. because another borg instance changed the
repository).

To optimize this rebuild process, borg caches per-archive information in the
``chunks.archive.d/`` directory. It won't help the first time it happens, but it
will make the subsequent rebuilds faster (because it needs to transfer less data
from the repository). While being faster, the cache needs quite some disk space,
which might be unwanted.

You can disable the cached archive chunk indexes by setting the environment
variable ``BORG_USE_CHUNKS_ARCHIVE`` to ``no``.

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

If that does not help:

- check for typos, check if you really used ``export``.
- check if you have set ``LC_ALL`` - if so, try not setting it.
- check if you generated the respective locale via ``locale-gen``.

I can't extract non-ascii filenames by giving them on the commandline!?
-----------------------------------------------------------------------

This might be due to different ways to represent some characters in unicode
or due to other non-ascii encoding issues.

If you run into that, try this:

- avoid the non-ascii characters on the commandline by e.g. extracting
  the parent directory (or even everything)
- mount the repo using FUSE and use some file manager

.. _expected_performance:

What's the expected backup performance?
---------------------------------------

A first backup will usually be somehow "slow" because there is a lot of data
to process. Performance here depends on a lot of factors, so it is hard to
give specific numbers.

Subsequent backups are usually very fast if most files are unchanged and only
a few are new or modified. The high performance on unchanged files primarily depends
only on a few factors (like fs recursion + metadata reading performance and the
files cache working as expected) and much less on other factors.

E.g., for this setup:

- server grade machine (4C/8T 2013 Xeon, 64GB RAM, 2x good 7200RPM disks)
- local zfs filesystem (mirrored) containing the backup source data
- repository is remote (does not matter much for unchanged files)
- backup job runs while machine is otherwise idle

The observed performance is that Borg can process about
**1 million unchanged files (and a few small changed ones) in 4 minutes!**

If you are seeing much less than that in similar circumstances, read the next
few FAQ entries below.

.. _slow_backup:

Why is backup slow for me?
--------------------------

So, if you feel your Borg backup is too slow somehow, you should find out why.

The usual way to approach this is to add ``--list --filter=AME --stats`` to your
``borg create`` call to produce more log output, including a file list (with file status
characters) and also some statistics at the end of the backup.

Then you do the backup and look at the log output:

- stats: Do you really have little changes or are there more changes than you thought?
  In the stats you can see the overall volume of changed data, which needed to be
  added to the repo. If that is a lot, that can be the reason why it is slow.
- ``A`` status ("added") in the file list:
  If you see that often, you have a lot of new files (files that Borg did not find
  in the files cache). If you think there is something wrong with that (the file was there
  already in the previous backup), please read the FAQ entries below.
- ``M`` status ("modified") in the file list:
  If you see that often, Borg thinks that a lot of your files might be modified
  (Borg found them in the files cache, but the metadata read from the filesystem did
  not match the metadata stored in the files cache).
  In such a case, Borg will need to process the files' contents completely, which is
  much slower than processing unmodified files (Borg does not read their contents!).
  The metadata values used in this comparison are determined by the ``--files-cache`` option
  and could be e.g. size, ctime and inode number (see the ``borg create`` docs for more
  details and potential issues).
  You can use the ``stat`` command on files to manually look at fs metadata to debug if
  there is any unexpected change triggering the ``M`` status.
  Also, the ``--debug-topic=files_cache`` option of ``borg create`` provides a lot of debug
  output helping to analyse why the files cache does not give its expected high performance.

When borg runs inside a virtual machine, there are some more things to look at:

Some hypervisors (e.g. kvm on proxmox) give some broadly compatible CPU type to the
VM (usually to ease migration between VM hosts of potentially different hardware CPUs).

It is broadly compatible because they leave away modern CPU features that could be
not present in older or other CPUs, e.g. hardware acceleration for AES crypto, for
sha2 hashes, for (P)CLMUL(QDQ) computations useful for crc32.

So, basically you pay for compatibility with bad performance. If you prefer better
performance, you should try to expose the host CPU's misc. hw acceleration features
to the VM which runs borg.

On Linux, check ``/proc/cpuinfo`` for the CPU flags inside the VM.
For kvm check the docs about "Host model" and "Host passthrough".

See also the next few FAQ entries for more details.

.. _a_status_oddity:

I am seeing 'A' (added) status for an unchanged file!?
------------------------------------------------------

The files cache is used to determine whether Borg already
"knows" / has backed up a file and if so, to skip the file from
chunking. It intentionally *excludes* files that have a timestamp
which is the same as the newest timestamp in the created archive.

So, if you see an 'A' status for unchanged file(s), they are likely the files
with the most recent timestamp in that archive.

This is expected: it is to avoid data loss with files that are backed up from
a snapshot and that are immediately changed after the snapshot (but within
timestamp granularity time, so the timestamp would not change). Without the code that
removes these files from the files cache, the change that happened right after
the snapshot would not be contained in the next backup as Borg would
think the file is unchanged.

This does not affect deduplication, the file will be chunked, but as the chunks
will often be the same and already stored in the repo (except in the above
mentioned rare condition), it will just re-use them as usual and not store new
data chunks.

If you want to avoid unnecessary chunking, just create or touch a small or
empty file in your backup source file set (so that one has the latest timestamp,
not your 50GB VM disk image) and, if you do snapshots, do the snapshot after
that.

Since only the files cache is used in the display of files status,
those files are reported as being added when, really, chunks are
already used.

By default, ctime (change time) is used for the timestamps to have a rather
safe change detection (see also the --files-cache option).

Furthermore, pathnames recorded in files cache are always absolute, even if you
specify source directories with relative pathname. If relative pathnames are
stable, but absolute are not (for example if you mount a filesystem without
stable mount points for each backup or if you are running the backup from a
filesystem snapshot whose name is not stable), borg will assume that files are
different and will report them as 'added', even though no new chunks will be
actually recorded for them. To avoid this, you could bind mount your source
directory in a directory with the stable path.

.. _always_chunking:

It always chunks all my files, even unchanged ones!
---------------------------------------------------

Borg maintains a files cache where it remembers the timestamp, size and
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

Besides using a higher BORG_FILES_CACHE_TTL (which also increases memory usage),
there is also BORG_FILES_CACHE_SUFFIX which can be used to have separate (smaller)
files caches for each backup set instead of the default one (big) unified files cache.

Another possible reason is that files don't always have the same path, for
example if you mount a filesystem without stable mount points for each backup
or if you are running the backup from a filesystem snapshot whose name is not
stable. If the directory where you mount a filesystem is different every time,
Borg assumes they are different files. This is true even if you backup these
files with relative pathnames - borg uses full pathnames in files cache regardless.

It is possible for some filesystems, such as ``mergerfs`` or network filesystems,
to return inconsistent inode numbers across runs, causing borg to consider them changed.
A workaround is to set the option ``--files-cache=ctime,size`` to exclude the inode
number comparison from the files cache check so that files with different inode
numbers won't be treated as modified.

Using a pure-python msgpack! This will result in lower performance.
-------------------------------------------------------------------

borg uses `msgpack` to serialize/deserialize data.

`msgpack` has 2 implementations:

- a fast one (C code compiled into a platform specific binary), and
- a slow pure-python one.

The slow one is used if it can't successfully import the fast one.

If you use the pyinstaller-made borg "fat binary" which we offer on github
releases, it could be that you downloaded a binary that does not match the
(g)libc on your system.

Binaries made for an older glibc than the one you have on your system usually
just work, but the opposite is not necessarily the case and can lead to misc.
issues - like failing to load the fast msgpack code or not working at all.

So: try a binary made for an older glibc.

If you see this without using a "fat binary" from us, it usually means that
msgpack is not built / installed correctly. It could be also that the platform
is not fully supported (so the python code works, but there is no fast binary
code).

Is there a way to limit bandwidth with Borg?
--------------------------------------------

To limit upload (i.e. :ref:`borg_create`) bandwidth, use the
``--remote-ratelimit`` option.

There is no built-in way to limit *download*
(i.e. :ref:`borg_extract`) bandwidth, but limiting download bandwidth
can be accomplished with pipeviewer_:

Create a wrapper script:  /usr/local/bin/pv-wrapper

::

    #!/bin/sh
        ## -q, --quiet              do not output any transfer information at all
        ## -L, --rate-limit RATE    limit transfer to RATE bytes per second
    RATE=307200
    pv -q -L $RATE  | "$@"

Add BORG_RSH environment variable to use pipeviewer wrapper script with ssh.

::

    export BORG_RSH='/usr/local/bin/pv-wrapper ssh'

Now Borg will be bandwidth limited. The nice thing about ``pv`` is that you can
change rate-limit on the fly:

::

    pv -R $(pidof pv) -L 102400

.. _pipeviewer: http://www.ivarch.com/programs/pv.shtml


How can I avoid unwanted base directories getting stored into archives?
-----------------------------------------------------------------------

Possible use cases:

- Another file system is mounted and you want to backup it with original paths.
- You have created a BTRFS snapshot in a ``/.snapshots`` directory for backup.

To achieve this, run ``borg create`` within the mountpoint/snapshot directory:

::

    # Example: Some file system mounted in /mnt/rootfs.
    cd /mnt/rootfs
    borg create /path/to/repo::rootfs_backup .


I am having troubles with some network/FUSE/special filesystem, why?
--------------------------------------------------------------------

Borg is doing nothing special in the filesystem, it only uses very
common and compatible operations (even the locking is just "rename").

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

How do I rename a repository?
-----------------------------

There is nothing special that needs to be done, you can simply rename the
directory that corresponds to the repository. However, the next time borg
interacts with the repository (i.e, via ``borg list``), depending on the value
of ``BORG_RELOCATED_REPO_ACCESS_IS_OK``, borg may warn you that the repository
has been moved. You will be given a prompt to confirm you are OK with this.

If ``BORG_RELOCATED_REPO_ACCESS_IS_OK`` is unset, borg will interactively ask for
each repository whether it's OK.

It may be useful to set ``BORG_RELOCATED_REPO_ACCESS_IS_OK=yes`` to avoid the
prompts when renaming multiple repositories or in a non-interactive context
such as a script. See :doc:`deployment` for an example.

The repository quota size is reached, what can I do?
----------------------------------------------------

The simplest solution is to increase or disable the quota and resume the backup:

::

    borg config /path/to/repo storage_quota 0

If you are bound to the quota, you have to free repository space. The first to
try is running :ref:`borg_compact` to free unused backup space (see also
:ref:`separate_compaction`):

::

    borg compact /path/to/repo

If your repository is already compacted, run :ref:`borg_prune` or
:ref:`borg_delete` to delete archives that you do not need anymore, and then run
``borg compact`` again.

My backup disk is full, what can I do?
--------------------------------------

Borg cannot work if you really have zero free space on the backup disk, so the
first thing you must do is deleting some files to regain free disk space. See
:ref:`about_free_space` for further details.

Some Borg commands that do not change the repository might work under disk-full
conditions, but generally this should be avoided. If your backup disk is already
full when Borg starts a write command like `borg create`, it will abort
immediately and the repository will stay as-is.

If you run a backup that stops due to a disk running full, Borg will roll back,
delete the new new segment file and thus freeing disk space automatically. There
may be a checkpoint archive left that has been saved before the disk got full.
You can keep it to speed up the next backup or delete it to get back more disk
space.

Miscellaneous
#############

macOS: borg mounts not shown in Finder's side bar
-------------------------------------------------

https://github.com/osxfuse/osxfuse/wiki/Mount-options#local

Read the above first and use this on your own risk::

    borg mount -olocal REPO MOUNTPOINT


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

* lots of attic issues fixed
  (see `issue #5 <https://github.com/borgbackup/borg/issues/5>`_),
  including critical data corruption bugs and security issues.
* more open, faster paced development
  (see `issue #1 <https://github.com/borgbackup/borg/issues/1>`_)
* less chunk management overhead (less memory and disk usage for chunks index)
* faster remote cache resync (useful when backing up multiple machines into same repo)
* compression: no, lz4, zstd, zlib or lzma compression, adjustable compression levels
* repokey replaces problematic passphrase mode (you can't change the passphrase
  nor the pbkdf2 iteration count in "passphrase" mode)
* simple sparse file support, great for virtual machine disk files
* can read special files (e.g. block devices) or from stdin, write to stdout
* rename-based locking is more compatible than attic's posix locking
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
