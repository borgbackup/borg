.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_tag:

borg tag
--------
.. code-block:: none

    borg [common options] tag [options] [NAME]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``NAME``                                     | specify the archive name                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--set TAG``                                | set tags (can be given multiple times)                                                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--clear``                                  | remove all normal tags (keep special tags)                                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--add TAG``                                | add tag (can be given multiple times)                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--remove TAG``                             | remove tag (can be given multiple times)                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                           |
    |                                                                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider the first N archives after other filters are applied                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider the last N archives after other filters are applied                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    NAME
        specify the archive name


    options
        --set TAG     set tags (can be given multiple times)
        --clear       remove all normal tags (keep special tags)
        --add TAG     add tag (can be given multiple times)
        --remove TAG    remove tag (can be given multiple times)


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. See "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider the first N archives after other filters are applied
        --last N                                 consider the last N archives after other filters are applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g., 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.


Description
~~~~~~~~~~~

Manage archive tags.

Borg archives can have a set of tags which can be used for matching archives.

You can set the tags to a specific set of tags or you can add or remove
tags from the current set of tags.

User-defined tags must not start with `@` because such tags are considered
special and users are only allowed to use known special tags:

``@PROT``: protects archives against archive deletion or pruning.

Pre-existing special tags cannot be removed via ``--set``. You can still use
``--set``, but you must also give pre-existing special tags (so they won't be
removed). If they are not given, borg emits a warning and does not set the tags
of that archive.

``--clear`` removes all normal tags, but keeps special tags. Combined with
``--add``, it replaces the normal tags.

To change tags, you must select the archives: give an archive NAME or use archive
filter options like ``--match-archives``. To change the tags of all archives, use
``--match-archives 'sh:*'``.

Each of ``--set``, ``--add`` and ``--remove`` takes exactly one tag. To give
multiple tags, use the option multiple times.

Examples::

    # add the tags "important" and "keep" to the archive with the given ID
    $ borg tag --add important --add keep aid:1ddaae55

    # remove the tag "keep" from all archives named "home"
    $ borg tag --remove keep --match-archives home

    # set the tags of the archive with the given ID to exactly "foo" and "bar"
    $ borg tag --set foo --set bar aid:1ddaae55

    # remove all normal tags (but not special tags like @PROT) from the archive with the given ID
    $ borg tag --clear aid:1ddaae55

    # protect the archive with the given ID against deletion and pruning
    $ borg tag --add @PROT aid:1ddaae55