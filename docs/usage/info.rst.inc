.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_info:

borg info
---------
.. code-block:: none

    borg [common options] info [options] REPOSITORY_OR_ARCHIVE

positional arguments
    REPOSITORY_OR_ARCHIVE
        archive or repository to display information about

optional arguments
    ``--json``
        | format output as JSON

:ref:`common_options`
    |

filters
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix.
    ``-a``, ``--glob-archives``
        | only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive.
    ``--sort-by``
        | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
    ``--first N``
        | consider first N archives after other filters were applied
    ``--last N``
        | consider last N archives after other filters were applied

Description
~~~~~~~~~~~

This command displays detailed information about the specified archive or repository.

Please note that the deduplicated sizes of the individual archives do not add
up to the deduplicated size of the repository ("all archives"), because the two
are meaning different things:

This archive / deduplicated size = amount of data stored ONLY for this archive
                                 = unique chunks of this archive.
All archives / deduplicated size = amount of data stored in the repo
                                 = all chunks in the repository.