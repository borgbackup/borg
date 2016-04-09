.. _borg_list:

borg list
---------
::

    borg list <options> REPOSITORY_OR_ARCHIVE PATH

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
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line

`Common options`_
    |

Description
~~~~~~~~~~~

This command lists the contents of a repository or an archive.

See the "borg help patterns" command for more help on exclude patterns.

The following keys are available for --format when listing files:

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

 - size
 - csize: compressed size
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

 - NEWLINE: OS dependent line separator
 - NL: alias of NEWLINE
 - NUL: NUL character for creating print0 / xargs -0 like ouput, see bpath
 - SPACE
 - TAB
 - CR
 - LF
