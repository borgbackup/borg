.. _borg_init:

borg init
---------
::

    borg init <options> REPOSITORY

positional arguments
    REPOSITORY
        repository to create

optional arguments
    ``-e``, ``--encryption``
        | select encryption key mode (default: "repokey")

`Common options`_
    |

Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.
Encryption can be enabled at repository init time.
