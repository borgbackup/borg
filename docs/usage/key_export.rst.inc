.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_export:

borg key export
---------------
::

    borg key export <options> REPOSITORY PATH

positional arguments
    REPOSITORY

    PATH
        where to store the backup

optional arguments
    ``--paper``
        | Create an export suitable for printing and later type-in

`Common options`_
    |

Description
~~~~~~~~~~~

If repository encryption is used, the repository is inaccessible
without the key. This command allows to backup this essential key.

There are two backup formats. The normal backup format is suitable for
digital storage as a file. The ``--paper`` backup format is optimized
for printing and typing in while importing, with per line checks to
reduce problems with manual input.

For repositories using keyfile encryption the key is saved locally
on the system that is capable of doing backups. To guard against loss
of this key, the key needs to be backed up independently of the main
data backup.

For repositories using the repokey encryption the key is saved in the
repository in the config file. A backup is thus not strictly needed,
but guards against the repository becoming inaccessible if the file
is damaged for some reason.
