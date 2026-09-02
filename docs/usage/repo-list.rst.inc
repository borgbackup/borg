.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_repo-list:

borg repo-list
--------------
.. code-block:: none

    borg [common options] repo-list [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--short``                                  | only print the archive IDs, nothing else                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--from-borg1``                             | repository is Borg 1.x                                                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                          | specify format for archive listing (default: "{id:.8}  {time}  {archive:<15}  {tags:<10}  {username:<10}  {hostname:<10}  {comment:.40}{NL}")                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--group-by KEYS``                          | comma-separated list of archive attributes to group the listed archives by; valid keys are: name, host, user, tags; default is to not group                                     |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json``                                   | Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                               |
    |                                                                                                                                                                                                                                                                                                              |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                                                                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp                                                     |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider the first N archives after other filters are applied                                                                                                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider the last N archives after other filters are applied                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g., 7d or 12m.                                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.                                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--deleted``                                | consider only soft-deleted archives.                                                                                                                                            |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --short     only print the archive IDs, nothing else
        --from-borg1    repository is Borg 1.x
        --format FORMAT    specify format for archive listing (default: "{id:.8}  {time}  {archive:<15}  {tags:<10}  {username:<10}  {hostname:<10}  {comment:.40}{NL}")
        --group-by KEYS    comma-separated list of archive attributes to group the listed archives by; valid keys are: name, host, user, tags; default is to not group
        --json      Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.


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
        --deleted                                consider only soft-deleted archives.


Description
~~~~~~~~~~~

This command lists the archives contained in a repository.

Grouping archives
+++++++++++++++++

``--group-by`` lists the archives grouped by the given comma-separated archive
attributes, each group preceded by a header line naming it::

    $ borg repo-list --group-by name,host --format '{archive} {time}{NL}'
    Group (name='home', host='host1'):
    home Thu, 2026-06-04 18:00:00 +0200
    home Wed, 2026-06-03 18:00:00 +0200

    Group (name='home', host='host2'):
    home Thu, 2026-06-04 19:00:00 +0200

Valid keys are ``name``, ``host``, ``user`` and ``tags``; borg's internal tags (starting
with ``@``) do not affect grouping. Archives without ``host`` / ``user`` metadata (e.g.
archives transferred from a borg 1.x repository) form their own group.

These are the same keys and the same grouping that ``borg prune --group-by`` uses, so
this is a way to see which archives a prune run will consider together before running
it. Without ``--group-by``, archives are listed as before, ungrouped.

With ``--json``, no header lines are emitted; each archive gets a ``group`` object
instead.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses Python's `format string syntax
<https://docs.python.org/3.11/library/string.html#formatstrings>`_.

Examples:
::

    $ borg repo-list --format '{archive}{NL}'
    ArchiveFoo
    ArchiveBar
    ...

    # {VAR:NUMBER} - pad to NUMBER columns.
    # Strings are left-aligned, numbers are right-aligned.
    # Note: the time keys (time, start, end) can not be padded - for them, the
    # format spec is a strftime format string, e.g. {time:%Y-%m-%d}.
    $ borg repo-list --format '{archive:36} {time} [{id}]{NL}'
    ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9...3b274]
    ...

The following keys are always available:

- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output
- SPACE: space character
- TAB: tab character
- CR: carriage return character
- LF: line feed character


Keys available only when listing archives in a repository:

- archive: archive name
- name: alias of "archive"
- comment: archive comment
- id: internal ID of the archive
- tags: archive tags

- time: nominal time of the archive
- start: start time of the archive operation
- end: end time of the archive operation
- command_line: command line which was used to create the archive

- hostname: hostname of host on which this archive was created
- username: username of user who created this archive

- size: size of this archive (data plus metadata, not considering compression and deduplication)
- nfiles: count of files in this archive