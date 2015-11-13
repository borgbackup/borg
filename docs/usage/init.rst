.. _borg_init:

borg init
---------

Initialize an empty repository

Synopsis
~~~~~~~~

::

    borg init [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [-e {none,keyfile,repokey,passphrase}]
                     [REPOSITORY]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~

::
      
    
      REPOSITORY            repository to create
    
optional arguments
~~~~~~~~~~~~~~~~~~

::
      
    
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      -e {none,keyfile,repokey,passphrase}, --encryption {none,keyfile,repokey,passphrase}
                            select encryption key mode
    
Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.
Encryption can be enabled at repository init time.
Please note that the 'passphrase' encryption mode is DEPRECATED (instead of it,
consider using 'repokey').

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

