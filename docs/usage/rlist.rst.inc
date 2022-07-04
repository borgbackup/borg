.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_rlist:

borg rlist
----------
.. code-block:: none

    borg [common options] rlist [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--consider-checkpoints``            | Show checkpoint archives in the repository contents list (default: hidden).                                                                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--short``                           | only print the archive names, nothing else                                                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                   | specify format for archive listing (default: "{archive:<36} {time} [{id}]{NL}")                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json``                            | Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "barchive" key is therefore not available. |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                     |
    |                                                                                                                                                                                                                                                                                                                                                    |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply, see "borg help patterns".                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --consider-checkpoints    Show checkpoint archives in the repository contents list (default: hidden).
        --short     only print the archive names, nothing else
        --format FORMAT    specify format for archive listing (default: "{archive:<36} {time} [{id}]{NL}")
        --json      Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "barchive" key is therefore not available.


    :ref:`common_options`
        |

    Archive filters
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

This command lists the archives contained in a repository.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses python's `format string syntax
<https://docs.python.org/3.9/library/string.html#formatstrings>`_.

Examples:
::

    $ borg rlist --format '{archive}{NL}'
    ArchiveFoo
    ArchiveBar
    ...

    # {VAR:NUMBER} - pad to NUMBER columns.
    # Strings are left-aligned, numbers are right-aligned.
    # Note: time columns except ``isomtime``, ``isoctime`` and ``isoatime`` cannot be padded.
    $ borg rlist --format '{archive:36} {time} [{id}]{NL}' /path/to/repo
    ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9a312bef3f2f6e2d0fc110c196827786c15eba0188738e81697a7fa3b274]
    ...

The following keys are always available:

- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output, see barchive and bpath keys below
- SPACE
- TAB
- CR
- LF

Keys available only when listing archives in a repository:

- archive: archive name interpreted as text (might be missing non-text characters, see barchive)
- name: alias of "archive"
- barchive: verbatim archive name, can contain any character except NUL
- comment: archive comment interpreted as text (might be missing non-text characters, see bcomment)
- bcomment: verbatim archive comment, can contain any character except NUL
- id: internal ID of the archive

- start: time (start) of creation of the archive
- time: alias of "start"
- end: time (end) of creation of the archive
- command_line: command line which was used to create the archive

- hostname: hostname of host on which this archive was created
- username: username of user who created this archive
