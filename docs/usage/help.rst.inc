.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_patterns:

borg help patterns
~~~~~~~~~~~~~~~~~~


Exclusion patterns support four separate styles, fnmatch, shell, regular
expressions and path prefixes. By default, fnmatch is used. If followed
by a colon (':') the first two characters of a pattern are used as a
style selector. Explicit style selection is necessary when a
non-default style is desired or when the desired pattern starts with
two alphanumeric characters followed by a colon (i.e. `aa:something/*`).

`Fnmatch <https://docs.python.org/3/library/fnmatch.html>`_, selector `fm:`

    This is the default style.  These patterns use a variant of shell
    pattern syntax, with '*' matching any number of characters, '?'
    matching any single character, '[...]' matching any single
    character specified, including ranges, and '[!...]' matching any
    character not specified. For the purpose of these patterns, the
    path separator ('\' for Windows and '/' on other systems) is not
    treated specially. Wrap meta-characters in brackets for a literal
    match (i.e. `[?]` to match the literal character `?`). For a path
    to match a pattern, it must completely match from start to end, or
    must match from the start to just before a path separator. Except
    for the root path, paths will never end in the path separator when
    matching is attempted.  Thus, if a given pattern ends in a path
    separator, a '*' is appended before matching is attempted.

Shell-style patterns, selector `sh:`

    Like fnmatch patterns these are similar to shell patterns. The difference
    is that the pattern may include `**/` for matching zero or more directory
    levels, `*` for matching zero or more arbitrary characters with the
    exception of any path separator.

Regular expressions, selector `re:`

    Regular expressions similar to those found in Perl are supported. Unlike
    shell patterns regular expressions are not required to match the complete
    path and any substring match is sufficient. It is strongly recommended to
    anchor patterns to the start ('^'), to the end ('$') or both. Path
    separators ('\' for Windows and '/' on other systems) in paths are
    always normalized to a forward slash ('/') before applying a pattern. The
    regular expression syntax is described in the `Python documentation for
    the re module <https://docs.python.org/3/library/re.html>`_.

Prefix path, selector `pp:`

    This pattern style is useful to match whole sub-directories. The pattern
    `pp:/data/bar` matches `/data/bar` and everything therein.

Exclusions can be passed via the command line option `--exclude`. When used
from within a shell the patterns should be quoted to protect them from
expansion.

The `--exclude-from` option permits loading exclusion patterns from a text
file with one pattern per line. Lines empty or starting with the number sign
('#') after removing whitespace on both ends are ignored. The optional style
selector prefix is also supported for patterns loaded from a file. Due to
whitespace removal paths with whitespace at the beginning or end can only be
excluded using regular expressions.

Examples::

    # Exclude '/home/user/file.o' but not '/home/user/file.odt':
    $ borg create -e '*.o' backup /

    # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
    # not '/home/user/importantjunk' or '/etc/junk':
    $ borg create -e '/home/*/junk' backup /

    # Exclude the contents of '/home/user/cache' but not the directory itself:
    $ borg create -e /home/user/cache/ backup /

    # The file '/home/user/cache/important' is *not* backed up:
    $ borg create -e /home/user/cache/ backup / /home/user/cache/important

    # The contents of directories in '/home' are not backed up when their name
    # ends in '.tmp'
    $ borg create --exclude 're:^/home/[^/]+\.tmp/' backup /

    # Load exclusions from file
    $ cat >exclude.txt <<EOF
    # Comment line
    /home/*/junk
    *.tmp
    fm:aa:something/*
    re:^/home/[^/]\.tmp/
    sh:/home/*/.thumbnails
    EOF
    $ borg create --exclude-from exclude.txt backup /

.. _borg_placeholders:

borg help placeholders
~~~~~~~~~~~~~~~~~~~~~~


Repository (or Archive) URLs, --prefix and --remote-path values support these
placeholders:

{hostname}

    The (short) hostname of the machine.

{fqdn}

    The full name of the machine.

{now}

    The current local date and time, by default in ISO-8601 format.
    You can also supply your own `format string <https://docs.python.org/3.4/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {now:%Y-%m-%d_%H:%M:%S}

{utcnow}

    The current UTC date and time, by default in ISO-8601 format.
    You can also supply your own `format string <https://docs.python.org/3.4/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {utcnow:%Y-%m-%d_%H:%M:%S}

{user}

    The user name (or UID, if no name is available) of the user running borg.

{pid}

    The current process ID.

{borgversion}

    The version of borg.

Examples::

    borg create /path/to/repo::{hostname}-{user}-{utcnow} ...
    borg create /path/to/repo::{hostname}-{now:%Y-%m-%d_%H:%M:%S} ...
    borg prune --prefix '{hostname}-' ...

.. _borg_compression:

borg help compression
~~~~~~~~~~~~~~~~~~~~~


Compression is off by default, if you want some, you have to specify what you want.

Valid compression specifiers are:

none

    Do not compress. (default)

lz4

    Use lz4 compression. High speed, low compression.

zlib[,L]

    Use zlib ("gz") compression. Medium speed, medium compression.
    If you do not explicitely give the compression level L (ranging from 0
    to 9), it will use level 6.
    Giving level 0 (means "no compression", but still has zlib protocol
    overhead) is usually pointless, you better use "none" compression.

lzma[,L]

    Use lzma ("xz") compression. Low speed, high compression.
    If you do not explicitely give the compression level L (ranging from 0
    to 9), it will use level 6.
    Giving levels above 6 is pointless and counterproductive because it does
    not compress better due to the buffer size used by borg - but it wastes
    lots of CPU cycles and RAM.

auto,C[,L]

    Use a built-in heuristic to decide per chunk whether to compress or not.
    The heuristic tries with lz4 whether the data is compressible.
    For incompressible data, it will not use compression (uses "none").
    For compressible data, it uses the given C[,L] compression - with C[,L]
    being any valid compression specifier.

The decision about which compression to use is done by borg like this:

1. find a compression specifier (per file):
   match the path/filename against all patterns in all --compression-from
   files (if any). If a pattern matches, use the compression spec given for
   that pattern. If no pattern matches (and also if you do not give any
   --compression-from option), default to the compression spec given by
   --compression. See docs/misc/compression.conf for an example config.

2. if the found compression spec is not "auto", the decision is taken:
   use the found compression spec.

3. if the found compression spec is "auto", test compressibility of each
   chunk using lz4.
   If it is compressible, use the C,[L] compression spec given within the
   "auto" specifier. If it is not compressible, use no compression.

Examples::

    borg create --compression lz4 REPO::ARCHIVE data
    borg create --compression zlib REPO::ARCHIVE data
    borg create --compression zlib,1 REPO::ARCHIVE data
    borg create --compression auto,lzma,6 REPO::ARCHIVE data
    borg create --compression-from compression.conf --compression auto,lzma ...

compression.conf has entries like::

    # example config file for --compression-from option
    #
    # Format of non-comment / non-empty lines:
    # <compression-spec>:<path/filename pattern>
    # compression-spec is same format as for --compression option
    # path/filename pattern is same format as for --exclude option
    none:*.gz
    none:*.zip
    none:*.mp3
    none:*.ogg

General remarks:

It is no problem to mix different compression methods in one repo,
deduplication is done on the source data chunks (not on the compressed
or encrypted data).

If some specific chunk was once compressed and stored into the repo, creating
another backup that also uses this chunk will not change the stored chunk.
So if you use different compression specs for the backups, whichever stores a
chunk first determines its compression. See also borg recreate.

