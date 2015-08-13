.. include:: global.rst.inc
.. _detailed_usage:

Usage
=====

|project_name| consists of a number of commands. Each command accepts
a number of arguments and options. The following sections will describe each
command in detail.

Quiet by default
----------------

Like most UNIX commands |project_name| is quiet by default but the ``-v`` or
``--verbose`` option can be used to get the program to output more status
messages as it is processing.

Return codes
------------

|project_name| can exit with the following return codes (rc):

::

    0      no error, normal termination
    1      some error occurred (this can be a complete or a partial failure)
    128+N  killed by signal N (e.g. 137 == kill -9)


Note: we are aware that more distinct return codes might be useful, but it is
not clear yet which return codes should be used for which precise conditions.

See issue #61 for a discussion about that. Depending on the outcome of the
discussion there, return codes may change in future (the only thing rather sure
is that 0 will always mean some sort of success and "not 0" will always mean
some sort of warning / error / failure - but the definition of success might
change).

Environment Variables
---------------------

|project_name| uses some environment variables for automation:

::

    Specifying a passphrase:
        BORG_PASSPHRASE : When set, use the value to answer the passphrase question for encrypted repositories.

    Some "yes" sayers (if set, they automatically confirm that you really want to do X even if there is that warning):
        BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK : For "Warning: Attempting to access a previously unknown unencrypted repository"
        BORG_RELOCATED_REPO_ACCESS_IS_OK : For "Warning: The repository at location ... was previously located at ..."
        BORG_CHECK_I_KNOW_WHAT_I_AM_DOING : For "Warning: 'check --repair' is an experimental feature that might result in data loss."

    Directories:
        BORG_KEYS_DIR : Default to '~/.borg/keys'. This directory contains keys for encrypted repositories.
        BORG_CACHE_DIR : Default to '~/.cache/borg'. This directory contains the local cache and might need a lot
                         of space for dealing with big repositories).

    Building:
        BORG_OPENSSL_PREFIX : Adds given OpenSSL header file directory to the default locations (setup.py).

    General:
        TMPDIR : where temporary files are stored (might need a lot of temporary space for some operations)


Please note:

- be very careful when using the "yes" sayers, the warnings with prompt exist for your / your data's security/safety
- also be very careful when putting your passphrase into a script, make sure it has appropriate file permissions
  (e.g. mode 600, root:root).


Resource Usage
--------------

|project_name| might use a lot of resources depending on the size of the data set it is dealing with.

CPU: it won't go beyond 100% of 1 core as the code is currently single-threaded.

Memory (RAM): the chunks index and the files index are read into memory for performance reasons.

Temporary files: reading data and metadata from a FUSE mounted repository will consume about the same space as the
                 deduplicated chunks used to represent them in the repository.

Cache files: chunks index and files index (plus a compressed collection of single-archive chunk indexes).

Chunks index: proportional to the amount of data chunks in your repo. lots of small chunks in your repo implies a big
              chunks index. you may need to tweak the chunker params (see create options) if you have a lot of data and
              you want to keep the chunks index at some reasonable size.

Files index: proportional to the amount of files in your last backup. can be switched off (see create options), but
             next backup will be much slower if you do.

Network: if your repository is remote, all deduplicated (and optionally compressed/encrypted) data of course has to go
         over the connection (ssh: repo url). if you use a locally mounted network filesystem, additionally some copy
         operations used for transaction support also go over the connection. if you backup multiple sources to one
         target repository, additional traffic happens for cache resynchronization.

In case you are interested in more details, please read the internals documentation.


.. include:: usage/init.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ borg init /mnt/backup

    # Remote repository (accesses a remote borg via ssh)
    $ borg init user@hostname:backup

    # Encrypted remote repository, store the key in the repo
    $ borg init --encryption=repokey user@hostname:backup

    # Encrypted remote repository, store the key your home dir
    $ borg init --encryption=keyfile user@hostname:backup

Important notes about encryption:

Use encryption! Repository encryption protects you e.g. against the case that
an attacker has access to your backup repository.

But be careful with the key / the passphrase:

``--encryption=passphrase`` is DEPRECATED and will be removed in next major release.
This mode has very fundamental, unfixable problems (like you can never change
your passphrase or the pbkdf2 iteration count for an existing repository, because
the encryption / decryption key is directly derived from the passphrase).

If you want "passphrase-only" security, just use the ``repokey`` mode. The key will
be stored inside the repository (in its "config" file). In above mentioned
attack scenario, the attacker will have the key (but not the passphrase).

If you want "passphrase and having-the-key" security, use the ``keyfile`` mode.
The key will be stored in your home directory (in ``.borg/keys``). In the attack
scenario, the attacker who has just access to your repo won't have the key (and
also not the passphrase).

Make a backup copy of the key file (``keyfile`` mode) or repo config file
(``repokey`` mode) and keep it at a safe place, so you still have the key in
case it gets corrupted or lost.
The backup that is encrypted with that key won't help you with that, of course.

Make sure you use a good passphrase. Not too short, not too simple. The real
encryption / decryption key is encrypted with / locked by your passphrase.
If an attacker gets your key, he can't unlock and use it without knowing the
passphrase. In ``repokey`` and ``keyfile`` modes, you can change your passphrase
for existing repos.


.. include:: usage/create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ borg create /mnt/backup::my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ borg create /mnt/backup::my-files   \
        ~/Documents                       \
        ~/src                             \
        --exclude '*.pyc'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    NAME="root-`date +%Y-%m-%d`"
    $ borg create /mnt/backup::$NAME / --do-not-cross-mountpoints

    # Backup huge files with little chunk management overhead
    $ borg create --chunker-params 19,23,21,4095 /mnt/backup::VMs /srv/VMs

    # Backup a raw device (must not be active/in use/mounted at that time)
    $ dd if=/dev/sda bs=10M | borg create /mnt/backup::my-sda -


.. include:: usage/extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ borg extract /mnt/backup::my-files

    # Extract entire archive and list files while processing
    $ borg extract -v /mnt/backup::my-files

    # Extract the "src" directory
    $ borg extract /mnt/backup::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ borg extract /mnt/backup::my-files home/USERNAME/src --exclude '*.o'

Note: currently, extract always writes into the current working directory ("."),
      so make sure you ``cd`` to the right place before calling ``borg extract``.

.. include:: usage/check.rst.inc

.. include:: usage/delete.rst.inc

.. include:: usage/list.rst.inc

Examples
~~~~~~~~
::

    $ borg list /mnt/backup
    my-files            Thu Aug  1 23:33:22 2013
    my-documents        Thu Aug  1 23:35:43 2013
    root-2013-08-01     Thu Aug  1 23:43:55 2013
    root-2013-08-02     Fri Aug  2 15:18:17 2013
    ...

    $ borg list /mnt/backup::root-2013-08-02
    drwxr-xr-x root   root          0 Jun 05 12:06 .
    lrwxrwxrwx root   root          0 May 31 20:40 bin -> usr/bin
    drwxr-xr-x root   root          0 Aug 01 22:08 etc
    drwxr-xr-x root   root          0 Jul 15 22:07 etc/ImageMagick-6
    -rw-r--r-- root   root       1383 May 22 22:25 etc/ImageMagick-6/colors.xml
    ...


.. include:: usage/prune.rst.inc

Examples
~~~~~~~~
::

    # Keep 7 end of day and 4 additional end of week archives:
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4

    # Same as above but only apply to archive names starting with "foo":
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --prefix=foo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --keep-monthly=-1

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-within=10d --keep-weekly=4 --keep-monthly=-1


.. include:: usage/info.rst.inc

Examples
~~~~~~~~
::

    $ borg info /mnt/backup::root-2013-08-02
    Name: root-2013-08-02
    Fingerprint: bc3902e2c79b6d25f5d769b335c5c49331e6537f324d8d3badcb9a0917536dbb
    Hostname: myhostname
    Username: root
    Time: Fri Aug  2 15:18:17 2013
    Command line: /usr/bin/borg create --stats /mnt/backup::root-2013-08-02 / --do-not-cross-mountpoints
    Number of files: 147429
    Original size: 5344169493 (4.98 GB)
    Compressed size: 1748189642 (1.63 GB)
    Unique data: 64805454 (61.80 MB)


.. include:: usage/mount.rst.inc

Examples
~~~~~~~~
::

    $ borg mount /mnt/backup::root-2013-08-02 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc  lib  lib64  mnt  opt  root  sbin  srv  usr  var
    $ fusermount -u /tmp/mymountpoint


.. include:: usage/change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg init --encryption=keyfile /mnt/backup
    Initializing repository at "/mnt/backup"
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again: 
    Key file "/home/USER/.borg/keys/mnt_backup" created.
    Keep this file safe. Your data will be inaccessible without it.

    # Change key file passphrase
    $ borg change-passphrase /mnt/backup
    Enter passphrase for key file /home/USER/.borg/keys/mnt_backup:
    New passphrase: 
    Enter same passphrase again: 
    Key file "/home/USER/.borg/keys/mnt_backup" updated


.. include:: usage/serve.rst.inc

Examples
~~~~~~~~
::

    # Allow an SSH keypair to only run |project_name|, and only have access to /mnt/backup.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /mnt/backup" ssh-rsa AAAAB3[...]

