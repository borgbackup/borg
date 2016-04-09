.. _borg_list:

borg list
---------
::

    usage: borg list [-h] [--critical] [--error] [--warning] [--info] [--debug]
                     [--lock-wait N] [--show-version] [--show-rc]
                     [--no-files-cache] [--umask M] [--remote-path PATH] [--short]
                     [--format FORMAT] [-P PREFIX] [-e PATTERN]
                     [--exclude-from EXCLUDEFILE]
                     [REPOSITORY_OR_ARCHIVE] [PATH [PATH ...]]
    
    List archive or repository contents
    
    positional arguments:
      REPOSITORY_OR_ARCHIVE
                            repository/archive to list contents of
      PATH                  paths to list; patterns are supported
    
    optional arguments:
      -h, --help            show this help message and exit
      --critical            work on log level CRITICAL
      --error               work on log level ERROR
      --warning             work on log level WARNING (default)
      --info, -v, --verbose
                            work on log level INFO
      --debug               work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-version        show/log the borg version
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      --short               only print file/directory names, nothing else
      --format FORMAT, --list-format FORMAT
                            specify format for file listing (default: "{mode}
                            {user:6} {group:6} {size:8d} {isomtime}
                            {path}{extra}{NL}")
      -P PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      --exclude-from EXCLUDEFILE
                            read exclude patterns from EXCLUDEFILE, one per line
    
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
