.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_list:

borg list
---------
.. code-block:: none

    borg [common options] list [options] REPOSITORY_OR_ARCHIVE PATH

positional arguments
    REPOSITORY_OR_ARCHIVE
        repository/archive to list contents of
    PATH
        paths to list; patterns are supported

optional arguments
    ``--short``
        | only print file/directory names, nothing else
    ``--format``, ``--list-format``
        | specify format for file listing
        |                                 (default: "{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NL}")
    ``--json``
        | Only valid for listing repository contents. Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "barchive" key is therefore not available.
    ``--json-lines``
        | Only valid for listing archive contents. Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "bpath" key is therefore not available.

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

This command lists the contents of a repository or an archive.

See the "borg help patterns" command for more help on exclude patterns.

.. man NOTES

The following keys are available for ``--format``:

- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output, see barchive/bpath
- SPACE
- TAB
- CR
- LF

Keys for listing repository archives:

- archive, name: archive name interpreted as text (might be missing non-text characters, see barchive)
- barchive: verbatim archive name, can contain any character except NUL
- time: time of creation of the archive
- id: internal ID of the archive

Keys for listing archive files:

- type
- mode
- uid
- gid
- user
- group
- path: path interpreted as text (might be missing non-text characters, see bpath)
- bpath: verbatim POSIX path, can contain any character except NUL
- source: link target for links (identical to linktarget)
- linktarget
- flags

- size
- csize: compressed size
- dsize: deduplicated size
- dcsize: deduplicated compressed size
- num_chunks: number of chunks in this file
- unique_chunks: number of unique chunks in this file

- mtime
- ctime
- atime
- isomtime
- isoctime
- isoatime

- md5
- sha1
- sha224
- sha256
- sha384
- sha512

- archiveid
- archivename
- extra: prepends {source} with " -> " for soft links and " link to " for hard links

- health: either "healthy" (file ok) or "broken" (if file has all-zero replacement chunks)
