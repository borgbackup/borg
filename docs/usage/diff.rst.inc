.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_diff:

borg diff
---------
.. code-block:: none

    borg [common options] diff [options] REPO_ARCHIVE1 ARCHIVE2 PATH

positional arguments
    REPO_ARCHIVE1
        repository location and ARCHIVE1 name
    ARCHIVE2
        ARCHIVE2 name (no repository location allowed)
    PATH
        paths of items inside the archives to compare; patterns are supported

optional arguments
    ``--numeric-owner``
        | only consider numeric user and group identifiers
    ``--same-chunker-params``
        | Override check of chunker parameters.
    ``--sort``
        | Sort the output lines by file path.

:ref:`common_options`
    |

Exclusion options
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line
    ``--exclude-caches``
        | exclude directories that contain a CACHEDIR.TAG file (http://www.brynosaurus.com/cachedir/spec.html)
    ``--exclude-if-present NAME``
        | exclude directories that are tagged by containing a filesystem object with the given NAME
    ``--keep-exclude-tags``, ``--keep-tag-files``
        | if tag objects are specified with --exclude-if-present, don't omit the tag objects themselves from the backup archive
    ``--pattern PATTERN``
        | experimental: include/exclude paths matching PATTERN
    ``--patterns-from PATTERNFILE``
        | experimental: read include/exclude patterns from PATTERNFILE, one per line

Description
~~~~~~~~~~~

This command finds differences (file contents, user/group/mode) between archives.

A repository location and an archive name must be specified for REPO_ARCHIVE1.
ARCHIVE2 is just another archive name in same repository (no repository location
allowed).

For archives created with Borg 1.1 or newer diff automatically detects whether
the archives are created with the same chunker params. If so, only chunk IDs
are compared, which is very fast.

For archives prior to Borg 1.1 chunk contents are compared by default.
If you did not create the archives with different chunker params,
pass ``--same-chunker-params``.
Note that the chunker params changed from Borg 0.xx to 1.0.

See the output of the "borg help patterns" command for more help on exclude patterns.