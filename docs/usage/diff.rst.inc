.. _borg_diff:

borg diff
---------
::

    borg diff <options> ARCHIVE1 ARCHIVE2 PATH

positional arguments
    ARCHIVE1
        archive
    ARCHIVE2
        archive to compare with ARCHIVE1 (no repository location)
    PATH
        paths to compare; patterns are supported

optional arguments
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line
    ``--numeric-owner``
        | only consider numeric user and group identifiers
    ``--same-chunker-params``
        | Override check of chunker parameters.
    ``--sort``
        | Sort the output lines by file path.

`Common options`_
    |

Description
~~~~~~~~~~~

This command finds differences in files (contents, user, group, mode) between archives.

Both archives need to be in the same repository, and a repository location may only
be specified for ARCHIVE1.

For archives created with Borg 1.1 or newer diff automatically detects whether
the archives are created with the same chunker params. If so, only chunk IDs
are compared, which is very fast.

For archives prior to Borg 1.1 chunk contents are compared by default.
If you did not create the archives with different chunker params,
pass --same-chunker-params.
Note that the chunker params changed from Borg 0.xx to 1.0.

See the output of the "borg help patterns" command for more help on exclude patterns.
