.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_patterns:

borg help patterns
~~~~~~~~~~~~~~~~~~


When specifying one or more file paths in a Borg command that supports
patterns for the respective option or argument, you can apply the
patterns described here to include only desired files and/or exclude
unwanted ones. Patterns can be used

- for ``--exclude`` option,
- in the file given with ``--exclude-from`` option,
- for ``--pattern`` option,
- in the file given with ``--patterns-from`` option and
- for ``PATH`` arguments that explicitly support them.

Borg always stores all file paths normalized and relative to the
current recursion root. The recursion root is also named ``PATH`` in
Borg commands like `borg create` that do a file discovery, so do not
confuse the root with the ``PATH`` argument of e.g. `borg extract`.

Starting with Borg 1.2, paths that are matched against patterns always
appear relative. If you give ``/absolute/`` as root, the paths going
into the matcher will start with ``absolute/``.
If you give ``../../relative`` as root, the paths will be normalized
as ``relative/``.

Borg supports different pattern styles. To define a non-default
style for a specific pattern, prefix it with two characters followed
by a colon ':' (i.e. ``fm:path/*``, ``sh:path/**``).

`Fnmatch <https://docs.python.org/3/library/fnmatch.html>`_, selector ``fm:``
    This is the default style for ``--exclude`` and ``--exclude-from``.
    These patterns use a variant of shell pattern syntax, with '\*' matching
    any number of characters, '?' matching any single character, '[...]'
    matching any single character specified, including ranges, and '[!...]'
    matching any character not specified. For the purpose of these patterns,
    the path separator (backslash for Windows and '/' on other systems) is not
    treated specially. Wrap meta-characters in brackets for a literal
    match (i.e. ``[?]`` to match the literal character '?'). For a path
    to match a pattern, the full path must match, or it must match
    from the start of the full path to just before a path separator. Except
    for the root path, paths will never end in the path separator when
    matching is attempted.  Thus, if a given pattern ends in a path
    separator, a '\*' is appended before matching is attempted. A leading
    path separator is always removed.

Shell-style patterns, selector ``sh:``
    This is the default style for ``--pattern`` and ``--patterns-from``.
    Like fnmatch patterns these are similar to shell patterns. The difference
    is that the pattern may include ``**/`` for matching zero or more directory
    levels, ``*`` for matching zero or more arbitrary characters with the
    exception of any path separator, ``{}`` containing comma-separated
    alternative patterns. A leading path separator is always removed.

`Regular expressions <https://docs.python.org/3/library/re.html>`_, selector ``re:``
    Unlike shell patterns, regular expressions are not required to match the full
    path and any substring match is sufficient. It is strongly recommended to
    anchor patterns to the start ('^'), to the end ('$') or both. Path
    separators (backslash for Windows and '/' on other systems) in paths are
    always normalized to a forward slash '/' before applying a pattern.

Path prefix, selector ``pp:``
    This pattern style is useful to match whole sub-directories. The pattern
    ``pp:root/somedir`` matches ``root/somedir`` and everything therein.
    A leading path separator is always removed.

Path full-match, selector ``pf:``
    This pattern style is (only) useful to match full paths.
    This is kind of a pseudo pattern as it can not have any variable or
    unspecified parts - the full path must be given. ``pf:root/file.ext``
    matches ``root/file.ext`` only. A leading path separator is always
    removed.

    Implementation note: this is implemented via very time-efficient O(1)
    hashtable lookups (this means you can have huge amounts of such patterns
    without impacting performance much).
    Due to that, this kind of pattern does not respect any context or order.
    If you use such a pattern to include a file, it will always be included
    (if the directory recursion encounters it).
    Other include/exclude patterns that would normally match will be ignored.
    Same logic applies for exclude.

.. note::

    ``re:``, ``sh:`` and ``fm:`` patterns are all implemented on top of
    the Python SRE engine. It is very easy to formulate patterns for each
    of these types which requires an inordinate amount of time to match
    paths. If untrusted users are able to supply patterns, ensure they
    cannot supply ``re:`` patterns. Further, ensure that ``sh:`` and
    ``fm:`` patterns only contain a handful of wildcards at most.

Exclusions can be passed via the command line option ``--exclude``. When used
from within a shell, the patterns should be quoted to protect them from
expansion.

The ``--exclude-from`` option permits loading exclusion patterns from a text
file with one pattern per line. Lines empty or starting with the hash sign
'#' after removing whitespace on both ends are ignored. The optional style
selector prefix is also supported for patterns loaded from a file. Due to
whitespace removal, paths with whitespace at the beginning or end can only be
excluded using regular expressions.

To test your exclusion patterns without performing an actual backup you can
run ``borg create --list --dry-run ...``.

Examples::

    # Exclude '/home/user/file.o' but not '/home/user/file.odt':
    $ borg create -e '*.o' archive /

    # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
    # not '/home/user/importantjunk' or '/etc/junk':
    $ borg create -e 'home/*/junk' archive /

    # Exclude the contents of '/home/user/cache' but not the directory itself:
    $ borg create -e home/user/cache/ archive /

    # The file '/home/user/cache/important' is *not* backed up:
    $ borg create -e home/user/cache/ archive / /home/user/cache/important

    # The contents of directories in '/home' are not backed up when their name
    # ends in '.tmp'
    $ borg create --exclude 're:^home/[^/]+\.tmp/' archive /

    # Load exclusions from file
    $ cat >exclude.txt <<EOF
    # Comment line
    home/*/junk
    *.tmp
    fm:aa:something/*
    re:^home/[^/]+\.tmp/
    sh:home/*/.thumbnails
    # Example with spaces, no need to escape as it is processed by borg
    some file with spaces.txt
    EOF
    $ borg create --exclude-from exclude.txt archive /

A more general and easier to use way to define filename matching patterns
exists with the ``--pattern`` and ``--patterns-from`` options. Using
these, you may specify the backup roots, default pattern styles and
patterns for inclusion and exclusion.

Root path prefix ``R``
    A recursion root path starts with the prefix ``R``, followed by a path
    (a plain path, not a file pattern). Use this prefix to have the root
    paths in the patterns file rather than as command line arguments.

Pattern style prefix ``P``
    To change the default pattern style, use the ``P`` prefix, followed by
    the pattern style abbreviation (``fm``, ``pf``, ``pp``, ``re``, ``sh``).
    All patterns following this line will use this style until another style
    is specified.

Exclude pattern prefix ``-``
    Use the prefix ``-``, followed by a pattern, to define an exclusion.
    This has the same effect as the ``--exclude`` option.

Exclude no-recurse pattern prefix ``!``
    Use the prefix ``!``, followed by a pattern, to define an exclusion
    that does not recurse into subdirectories. This saves time, but
    prevents include patterns to match any files in subdirectories.

Include pattern prefix ``+``
    Use the prefix ``+``, followed by a pattern, to define inclusions.
    This is useful to include paths that are covered in an exclude
    pattern and would otherwise not be backed up.

The first matching pattern is used, so if an include pattern matches
before an exclude pattern, the file is backed up. Note that a no-recurse
exclude stops examination of subdirectories so that potential includes
will not match - use normal excludes for such use cases.

Example::

    # Define the recursion root
    R /
    # Exclude all iso files in any directory
    - **/*.iso
    # Explicitly include all inside etc and root
    + etc/**
    + root/**
    # Exclude a specific directory under each user's home directories
    - home/*/.cache
    # Explicitly include everything in /home
    + home/**
    # Explicitly exclude some directories without recursing into them
    ! re:^(dev|proc|run|sys|tmp)
    # Exclude all other files and directories
    # that are not specifically included earlier.
    - **

**Tip: You can easily test your patterns with --dry-run and  --list**::

    $ borg create --dry-run --list --patterns-from patterns.txt archive

This will list the considered files one per line, prefixed with a
character that indicates the action (e.g. 'x' for excluding, see
**Item flags** in `borg create` usage docs).

.. note::

    It's possible that a sub-directory/file is matched while parent
    directories are not. In that case, parent directories are not backed
    up and thus their user, group, permission, etc. cannot be restored.

Patterns (``--pattern``) and excludes (``--exclude``) from the command line are
considered first (in the order of appearance). Then patterns from ``--patterns-from``
are added. Exclusion patterns from ``--exclude-from`` files are appended last.

Examples::

    # back up pics, but not the ones from 2018, except the good ones:
    # note: using = is essential to avoid cmdline argument parsing issues.
    borg create --pattern=+pics/2018/good --pattern=-pics/2018 archive pics

    # back up only JPG/JPEG files (case insensitive) in all home directories:
    borg create --pattern '+ re:\.jpe?g(?i)$' archive /home

    # back up homes, but exclude big downloads (like .ISO files) or hidden files:
    borg create --exclude 're:\.iso(?i)$' --exclude 'sh:home/**/.*' archive /home

    # use a file with patterns (recursion root '/' via command line):
    borg create --patterns-from patterns.lst archive /

The patterns.lst file could look like that::

    # "sh:" pattern style is the default
    # exclude caches
    - home/*/.cache
    # include susans home
    + home/susan
    # also back up this exact file
    + pf:home/bobby/specialfile.txt
    # don't back up the other home directories
    - home/*
    # don't even look in /dev, /proc, /run, /sys, /tmp (note: would exclude files like /device, too)
    ! re:^(dev|proc|run|sys|tmp)

You can specify recursion roots either on the command line or in a patternfile::

    # these two commands do the same thing
    borg create --exclude home/bobby/junk archive /home/bobby /home/susan
    borg create --patterns-from patternfile.lst archive

patternfile.lst::

    # note that excludes use fm: by default and patternfiles use sh: by default.
    # therefore, we need to specify fm: to have the same exact behavior.
    P fm
    R /home/bobby
    R /home/susan
    - home/bobby/junk

This allows you to share the same patterns between multiple repositories
without needing to specify them on the command line.

.. _borg_match-archives:

borg help match-archives
~~~~~~~~~~~~~~~~~~~~~~~~


The ``--match-archives`` option matches a given pattern against the list of all archives
in the repository. It can be given multiple times.

The patterns can have a prefix of:

- name: pattern match on the archive name (default)
- aid: prefix match on the archive id (only one result allowed)
- user: exact match on the username who created the archive
- host: exact match on the hostname where the archive was created
- tags: match on the archive tags

In case of a name pattern match,
it uses pattern styles similar to the ones described by ``borg help patterns``:

Identical match pattern, selector ``id:`` (default)
    Simple string match, must fully match exactly as given.

Shell-style patterns, selector ``sh:``
    Match like on the shell, wildcards like `*` and `?` work.

`Regular expressions <https://docs.python.org/3/library/re.html>`_, selector ``re:``
    Full regular expression support.
    This is very powerful, but can also get rather complicated.

Examples::

    # name match, id: style
    borg delete --match-archives 'id:archive-with-crap'
    borg delete -a 'id:archive-with-crap'  # same, using short option
    borg delete -a 'archive-with-crap'  # same, because 'id:' is the default

    # name match, sh: style
    borg delete -a 'sh:home-kenny-*'

    # name match, re: style
    borg delete -a 're:pc[123]-home-(user1|user2)-2022-09-.*'

    # archive id prefix match:
    borg delete -a 'aid:d34db33f'

    # host or user match
    borg delete -a 'user:kenny'
    borg delete -a 'host:kenny-pc'

    # tags match
    borg delete -a 'tags:TAG1' -a 'tags:TAG2'

.. _borg_placeholders:

borg help placeholders
~~~~~~~~~~~~~~~~~~~~~~


Repository URLs, ``--name``, ``-a`` / ``--match-archives``, ``--comment``
and ``--remote-path`` values support these placeholders:

{hostname}
    The (short) hostname of the machine.

{fqdn}
    The full name of the machine.

{reverse-fqdn}
    The full name of the machine in reverse domain name notation.

{now}
    The current local date and time, by default in ISO-8601 format.
    You can also supply your own `format string <https://docs.python.org/3.9/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {now:%Y-%m-%d_%H:%M:%S}

{utcnow}
    The current UTC date and time, by default in ISO-8601 format.
    You can also supply your own `format string <https://docs.python.org/3.9/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {utcnow:%Y-%m-%d_%H:%M:%S}

{user}
    The user name (or UID, if no name is available) of the user running borg.

{pid}
    The current process ID.

{borgversion}
    The version of borg, e.g.: 1.0.8rc1

{borgmajor}
    The version of borg, only the major version, e.g.: 1

{borgminor}
    The version of borg, only major and minor version, e.g.: 1.0

{borgpatch}
    The version of borg, only major, minor and patch version, e.g.: 1.0.8

If literal curly braces need to be used, double them for escaping::

    borg create /path/to/repo::{{literal_text}}

Examples::

    borg create /path/to/repo::{hostname}-{user}-{utcnow} ...
    borg create /path/to/repo::{hostname}-{now:%Y-%m-%d_%H:%M:%S%z} ...
    borg prune -a 'sh:{hostname}-*' ...

.. note::
    systemd uses a difficult, non-standard syntax for command lines in unit files (refer to
    the `systemd.unit(5)` manual page).

    When invoking borg from unit files, pay particular attention to escaping,
    especially when using the now/utcnow placeholders, since systemd performs its own
    %-based variable replacement even in quoted text. To avoid interference from systemd,
    double all percent signs (``{hostname}-{now:%Y-%m-%d_%H:%M:%S}``
    becomes ``{hostname}-{now:%%Y-%%m-%%d_%%H:%%M:%%S}``).

.. _borg_compression:

borg help compression
~~~~~~~~~~~~~~~~~~~~~


It is no problem to mix different compression methods in one repo,
deduplication is done on the source data chunks (not on the compressed
or encrypted data).

If some specific chunk was once compressed and stored into the repo, creating
another backup that also uses this chunk will not change the stored chunk.
So if you use different compression specs for the backups, whichever stores a
chunk first determines its compression. See also borg recreate.

Compression is lz4 by default. If you want something else, you have to specify what you want.

Valid compression specifiers are:

none
    Do not compress.

lz4
    Use lz4 compression. Very high speed, very low compression. (default)

zstd[,L]
    Use zstd ("zstandard") compression, a modern wide-range algorithm.
    If you do not explicitly give the compression level L (ranging from 1
    to 22), it will use level 3.

zlib[,L]
    Use zlib ("gz") compression. Medium speed, medium compression.
    If you do not explicitly give the compression level L (ranging from 0
    to 9), it will use level 6.
    Giving level 0 (means "no compression", but still has zlib protocol
    overhead) is usually pointless, you better use "none" compression.

lzma[,L]
    Use lzma ("xz") compression. Low speed, high compression.
    If you do not explicitly give the compression level L (ranging from 0
    to 9), it will use level 6.
    Giving levels above 6 is pointless and counterproductive because it does
    not compress better due to the buffer size used by borg - but it wastes
    lots of CPU cycles and RAM.

auto,C[,L]
    Use a built-in heuristic to decide per chunk whether to compress or not.
    The heuristic tries with lz4 whether the data is compressible.
    For incompressible data, it will not use compression (uses "none").
    For compressible data, it uses the given C[,L] compression - with C[,L]
    being any valid compression specifier. This can be helpful for media files which
    often cannot be compressed much more.

obfuscate,SPEC,C[,L]
    Use compressed-size obfuscation to make fingerprinting attacks based on
    the observable stored chunk size more difficult. Note:

    - You must combine this with encryption, or it won't make any sense.
    - Your repo size will be bigger, of course.
    - A chunk is limited by the constant ``MAX_DATA_SIZE`` (cur. ~20MiB).

    The SPEC value determines how the size obfuscation works:

    *Relative random reciprocal size variation* (multiplicative)

    Size will increase by a factor, relative to the compressed data size.
    Smaller factors are used often, larger factors rarely.

    Available factors::

      1:     0.01 ..        100
      2:     0.1  ..      1,000
      3:     1    ..     10,000
      4:    10    ..    100,000
      5:   100    ..  1,000,000
      6: 1,000    .. 10,000,000

    Example probabilities for SPEC ``1``::

      90   %  0.01 ..   0.1
       9   %  0.1  ..   1
       0.9 %  1    ..  10
       0.09% 10    .. 100

    *Randomly sized padding up to the given size* (additive)

    ::

      110: 1kiB (2 ^ (SPEC - 100))
      ...
      120: 1MiB
      ...
      123: 8MiB (max.)

Examples::

    borg create --compression lz4 REPO::ARCHIVE data
    borg create --compression zstd REPO::ARCHIVE data
    borg create --compression zstd,10 REPO::ARCHIVE data
    borg create --compression zlib REPO::ARCHIVE data
    borg create --compression zlib,1 REPO::ARCHIVE data
    borg create --compression auto,lzma,6 REPO::ARCHIVE data
    borg create --compression auto,lzma ...
    borg create --compression obfuscate,110,none ...
    borg create --compression obfuscate,3,auto,zstd,10 ...
    borg create --compression obfuscate,2,zstd,6 ...

