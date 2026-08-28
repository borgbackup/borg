import textwrap

from ._common import rst_plain_text_references
from ..helpers.argparsing import ArgumentParser
from ..constants import *  # NOQA
from ..helpers.nanorst import rst_to_terminal


class HelpMixIn:
    helptext = {}
    helptext["patterns"] = textwrap.dedent(
        """
        When specifying one or more file paths in a Borg command that supports
        patterns for the respective option or argument, you can apply the
        patterns described here to include only desired files and/or exclude
        unwanted ones. Patterns can be used

        - for ``--exclude`` option,
        - in the file given with ``--exclude-from`` option,
        - for ``--pattern`` option,
        - in the file given with ``--patterns-from`` option and
        - for ``PATH`` arguments that explicitly support them.

        The path/filenames used as input for the pattern matching start with the
        currently active recursion root. You usually give the recursion root(s)
        when invoking borg and these can be either relative or absolute paths.

        Be careful, your patterns must match the archived paths:

        - Archived paths never start with a leading slash ('/'), nor with '.', nor with '..'.

          - When you back up absolute paths like ``/home/user``, the archived
            paths start with ``home/user``.
          - When you back up relative paths like ``./src``, the archived paths
            start with ``src``.
          - When you back up relative paths like ``../../src``, the archived paths
            start with ``src``.
          - On native Windows, archived absolute paths look like ``C/Windows/System32``.

        - When using the slashdot hack, patterns match against the unstripped path,
          i.e., when you back up ``/this/gets/stripped/./this/gets/archived``,
          patterns must match ``this/gets/stripped/this/gets/archived``.

        Borg supports different pattern styles. To define a non-default
        style for a specific pattern, prefix it with two characters followed
        by a colon ':' (i.e. ``fm:path/*``, ``sh:path/**``).

        Note: Windows users must only use forward slashes in patterns, not backslashes.

        The default pattern style for ``--exclude`` differs from ``--pattern``, see below.

        `Fnmatch <https://docs.python.org/3/library/fnmatch.html>`_, selector ``fm:``
            This is the default style for ``--exclude`` and ``--exclude-from``.
            These patterns use a variant of shell pattern syntax, with '\\*' matching
            any number of characters, '?' matching any single character, '[...]'
            matching any single character specified, including ranges, and '[!...]'
            matching any character not specified. For the purpose of these patterns,
            the path separator (forward slash '/') is not treated specially.
            Wrap meta-characters in brackets for a literal
            match (i.e. ``[?]`` to match the literal character '?'). For a path
            to match a pattern, the full path must match, or it must match
            from the start of the full path to just before a path separator. Except
            for the root path, paths will never end in the path separator when
            matching is attempted.  Thus, if a given pattern ends in a path
            separator, a '\\*' is appended before matching is attempted. A leading
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
            anchor patterns to the start ('^'), to the end ('$') or both.

        Path prefix, selector ``pp:``
            This pattern style is useful to match whole subdirectories. The pattern
            ``pp:root/somedir`` matches ``root/somedir`` and everything therein.
            A leading path separator is always removed.

        Path full-match, selector ``pf:``
            This pattern style is (only) useful to match full paths.
            This is kind of a pseudo pattern as it cannot have any variable or
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

        .. note::

            **Windows path handling**: All paths in Borg archives use forward slashes (``/``)
            as path separators, regardless of the platform. When creating archives on Windows,
            backslashes from filesystem paths are automatically converted to forward slashes.

        .. note::

            **Windows reserved characters**: On Windows, when extracting archives created on
            POSIX systems, paths may contain characters that are reserved from being used in
            file or directory names (like: ``< > : " \\ | ? *``).
            These are replaced by characters in the unicode private use area (``U+F0xx``) like
            the CIFS mapchars feature also does it. It won't be pretty, but at least it works.

        Exclusions can be passed via the command line option ``--exclude``. When used
        from within a shell, the patterns should be quoted to protect them from
        expansion.

        Patterns matching special characters, e.g. whitespace, within a shell may
        require adjustments, such as putting quotation marks around the arguments.
        Example:
        Using bash, the following command line option would match and exclude "item name":
        ``--pattern='-path/item name'``
        Note that when patterns are used within a pattern file directly read by borg,
        e.g. when using ``--exclude-from`` or ``--patterns-from``, there is no shell
        involved and thus no quotation marks are required.

        The ``--exclude-from`` option permits loading exclusion patterns from a text
        file with one pattern per line. Lines empty or starting with the hash sign
        '#' after removing whitespace on both ends are ignored. The optional style
        selector prefix is also supported for patterns loaded from a file. Due to
        whitespace removal, paths with whitespace at the beginning or end can only be
        excluded using regular expressions.

        To test your exclusion patterns without performing an actual backup you can
        run ``borg create --list --dry-run ...``.

        Examples::

            # Exclude a directory anywhere in the tree named steamapps/common
            # (and everything below it), regardless of where it appears:
            $ borg create -e 'sh:**/steamapps/common/**' archive /

            # Exclude the contents of /home/user/.cache:
            $ borg create -e 'sh:home/user/.cache/**' archive /home/user
            $ borg create -e home/user/.cache/ archive /home/user

            # The file '/home/user/.cache/important' is *not* backed up:
            $ borg create -e home/user/.cache/ archive / /home/user/.cache/important

            # Exclude '/home/user/file.o' but not '/home/user/file.odt':
            $ borg create -e '*.o' archive /

            # Exclude '/home/user/junk' and '/home/user/subdir/junk' but
            # not '/home/user/importantjunk' or '/etc/junk':
            $ borg create -e 'home/*/junk' archive /

            # The contents of directories in '/home' are not backed up when their name
            # ends in '.tmp'
            $ borg create --exclude 're:^home/[^/]+\\.tmp/' archive /

            # Load exclusions from file
            $ cat >exclude.txt <<EOF
            # Comment line
            home/*/junk
            *.tmp
            fm:aa:something/*
            re:^home/[^/]+\\.tmp/
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

        Pattern style prefix ``P`` (only useful within patterns files)
            To change the default pattern style, use the ``P`` prefix, followed by
            the pattern style abbreviation (``fm``, ``pf``, ``pp``, ``re``, ``sh``).
            All patterns following this line in the same patterns file will use this
            style until another style is specified or the end of the file is reached.
            When the current patterns file is finished, the default pattern style will
            reset.

        Exclude pattern prefix ``-``
            Use the prefix ``-``, followed by a pattern, to define an exclusion.
            Borg still recurses into a directory excluded this way, so a later
            include pattern can still match files below it.

        Exclude no-recurse pattern prefix ``!``
            Use the prefix ``!``, followed by a pattern, to define an exclusion
            that does not recurse into subdirectories. This saves time, but
            prevents include patterns to match any files in subdirectories.
            The ``--exclude`` option and the patterns in an ``--exclude-from``
            file give this kind of exclusion, not the recursing one of ``-``.

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

            It is possible that a subdirectory or file is matched while its parent
            directories are not. In that case, parent directories are not backed
            up and thus their user, group, permission, etc. cannot be restored.

        ``--pattern``, ``--patterns-from``, ``--exclude`` and ``--exclude-from`` all feed the
        same single list of patterns, in the order in which they appear on the command line.
        The patterns of a pattern file resp. exclude file are inserted where the option naming
        that file stands, in the order of the lines in that file.

        Examples::

            # back up pics, but not the ones from 2018, except the good ones:
            # note: using = is essential to avoid cmdline argument parsing issues.
            borg create --pattern=+pics/2018/good --pattern=-pics/2018 archive pics

            # back up only JPG/JPEG files (case insensitive) in all home directories:
            borg create --pattern '+ re:\\.jpe?g(?i)$' archive /home

            # back up homes, but exclude big downloads (like .ISO files) or hidden files:
            borg create --exclude 're:\\.iso(?i)$' --exclude 'sh:home/**/.*' archive /home

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
        without needing to specify them on the command line.\n\n"""
    )
    helptext["match-archives"] = textwrap.dedent(
        """
        The ``--match-archives`` option matches a given pattern against the list of all archives
        in the repository. It can be given multiple times.

        The patterns can have a prefix of:

        - name: pattern match on the archive name (default)
        - aid: prefix match on the archive id (only one result allowed)
        - user: exact match on the username who created the archive
        - host: exact match on the hostname where the archive was created
        - tags: match on the archive tags
        - date: match on the archive creation timestamp

        In case of a name pattern match,
        it uses pattern styles similar to the ones described by ``borg help patterns``:

        Identical match pattern, selector ``id:`` (default)
            Simple string match, must fully match exactly as given.

        Shell-style patterns, selector ``sh:``
            Match like on the shell, wildcards like `*` and `?` work.

        `Regular expressions <https://docs.python.org/3/library/re.html>`_, selector ``re:``
            Full regular expression support.
            This is very powerful, but can also get rather complicated.

        Date patterns, selector ``date:``
            Match archives by creation timestamp. You can either match a single archive by
            passing its exact creation time, or all archives created within a given time
            interval.

            To match a single archive by its exact creation time, use the forms:

            - ``YYYY-MM-DDTHH:MM:SS.ffffff``: ISO-8601-like date-time string
            - ``@1735732800.123456``: UNIX timestamp

            To match a single archive, the pattern must specify the archive's complete
            creation timestamp, including any fractional seconds. Fractional-second
            patterns accept 1 to 6 digits.

            To match all archives created within a given time interval, use the forms:

            - ``YYYY``: match all archives created within the given year
            - ``YYYY-MM``: within the given month
            - ``YYYY-MM-DD``: on the given day
            - ``YYYY-MM-DDTHH``: in the given hour
            - ``YYYY-MM-DDTHH:MM``: in the given minute
            - ``YYYY-MM-DDTHH:MM:SS``: in the given second
            - ``@1735732800``: within the 1 second interval from the given UNIX timestamp

            The ``T`` date-time separator may also be written as a space, e.g.
            ``date:2025-01-01 14:30``.

            Date and time patterns match the interval implied by their precision, including
            the start and excluding the end. For example, ``date:2026-06`` matches archives
            created on or after ``2026-06-01T00:00:00`` and before ``2026-07-01T00:00:00``.

            Date and time patterns may include a timezone suffix: ``Z`` (UTC), ``+HH:MM``,
            ``-HH:MM``, or ``[Region/City]``. Patterns without a timezone are interpreted
            in the local timezone. Unix timestamps are always UTC and do not accept a timezone suffix.

            Be wary of Daylight Saving Time (DST) transitions, as they can make time intervals
            ambiguous or nonexistent. For example, named zones such as ``[Europe/Berlin]`` track DST,
            but the equivalent (winter) UTC offset of ``+01:00`` does not. Use UTC to avoid such issues.

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

            # archive creation date match
            borg delete -a 'date:2025-01'
            borg delete -a 'date:2025-01-01T14:30Z'
            borg delete -a 'date:2025-01-01T09:30[America/New_York]'\n\n"""
    )
    helptext["placeholders"] = textwrap.dedent(
        """
        Repository URLs, the archive name arguments (``NAME``, ``OLDNAME``, ``NEWNAME``,
        ``ARCHIVE1``, ``ARCHIVE2``), ``-a`` / ``--match-archives``, ``--comment`` and
        ``BORG_REMOTE_PATH`` values support these placeholders:

        {hostname}
            The (short) hostname of the machine.

        {fqdn}
            The full name of the machine.

        {reverse-fqdn}
            The full name of the machine in reverse domain name notation.

        {now}
            The current local date and time, by default in ISO-8601 format.
            You can also supply your own `format string <https://docs.python.org/3.11/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {now:%Y-%m-%d_%H:%M:%S}

        {utcnow}
            The current UTC date and time, by default in ISO-8601 format.
            You can also supply your own `format string <https://docs.python.org/3.11/library/datetime.html#strftime-and-strptime-behavior>`_, e.g. {utcnow:%Y-%m-%d_%H:%M:%S}

        {unixtime}
            The current time as a UNIX timestamp, i.e. whole seconds since the epoch,
            e.g.: 1735732800

        {user}
            The user name (or UID, if no name is available) of the user running borg.

        {pid}
            The current process ID.

        {uuid4}
            A random UUID (version 4), freshly generated each time placeholders are replaced.

        {borgversion}
            The version of borg, e.g.: 1.0.8rc1

        {borgmajor}
            The version of borg, only the major version, e.g.: 1

        {borgminor}
            The version of borg, only major and minor version, e.g.: 1.0

        {borgpatch}
            The version of borg, only major, minor and patch version, e.g.: 1.0.8

        If literal curly braces need to be used, double them for escaping::

            borg create --repo /path/to/repo {{literal_text}}

        Examples::

            borg create --repo /path/to/repo {hostname}-{user}-{utcnow} ...
            borg create --repo /path/to/repo {hostname}-{now:%Y-%m-%d_%H:%M:%S%z} ...
            borg prune -a 'sh:{hostname}-*' ...

        .. note::
            systemd uses a difficult, non-standard syntax for command lines in unit files (refer to
            the `systemd.unit(5)` manual page).

            When invoking borg from unit files, pay particular attention to escaping,
            especially when using the now/utcnow placeholders, since systemd performs its own
            %-based variable replacement even in quoted text. To avoid interference from systemd,
            double all percent signs (``{hostname}-{now:%Y-%m-%d_%H:%M:%S}``
            becomes ``{hostname}-{now:%%Y-%%m-%%d_%%H:%%M:%%S}``).\n\n"""
    )
    helptext["compression"] = textwrap.dedent(
        """
        It is no problem to mix different compression methods in one repository,
        deduplication is done on the source data chunks (not on the compressed
        or encrypted data).

        If some specific chunk was once compressed and stored into the repository, creating
        another backup that also uses this chunk will not change the stored chunk.
        So if you use different compression specs for the backups, whichever stores a
        chunk first determines its compression. See also ``borg recreate``.

        Compression is lz4 by default. If you want something else, you have to specify what you want.

        Valid compression specifiers are:

        none
            Do not compress.

        lz4
            Use lz4 compression. Very high speed, very low compression. (default)

        zstd[,L]
            Use zstd ("zstandard") compression, a modern wide-range algorithm.
            If you do not explicitly give the compression level L (ranging from -128
            to 22), it will use level 3.
            Negative levels are zstd's "fast" levels (level -N is what the zstd command
            line tool calls --fast=N): they give up compression ratio for speed.
            -1 to -10 is the useful range for general data; going lower only pays off for
            data with long repeats (disk/VM images, database files), where it stays fast
            while still finding the big matches.
            Level 0 selects zstd's default level (3) - for zstd it does not mean
            "no compression" (use "none" for that), unlike for zlib below.

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
            being any valid compression specifier. This can be helpful for media files
            which often cannot be compressed much more.

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

            *Padmé padding* (deterministic)

            ::

              250: pads to sums of powers of 2, max 12% overhead

            Uses the Padmé algorithm to deterministically pad the compressed size to a sum of
            powers of 2, limiting overhead to 12%. See https://lbarman.ch/blog/padme/ for details.

        Examples::

            borg create --compression lz4 --repo REPO ARCHIVE data
            borg create --compression zstd --repo REPO ARCHIVE data
            borg create --compression zstd,10 --repo REPO ARCHIVE data
            borg create --compression zlib --repo REPO ARCHIVE data
            borg create --compression zlib,1 --repo REPO ARCHIVE data
            borg create --compression auto,lzma,6 --repo REPO ARCHIVE data
            borg create --compression auto,lzma ...
            borg create --compression obfuscate,110,none ...
            borg create --compression obfuscate,3,auto,zstd,10 ...
            borg create --compression obfuscate,2,zstd,6 ...
            borg create --compression obfuscate,250,zstd,3 ...\n\n"""
    )
    helptext["environment"] = textwrap.dedent(
        """
        Borg uses some environment variables for automation:

        General:
            BORG_REPO
                When set, use the value to give the default repository location.
                Use this so you do not need to type ``--repo /path/to/my/repo`` all the time.
            BORG_OTHER_REPO
                Similar to BORG_REPO, but gives the default for ``--other-repo``.
            BORG_PASSPHRASE (and BORG_OTHER_PASSPHRASE)
                When set, use the value to answer the passphrase question for encrypted repositories.
                It is used when a passphrase is needed to access an encrypted repo as well as when a new
                passphrase should be initially set when initializing an encrypted repo.
                BORG_PASSPHRASE, BORG_PASSCOMMAND and BORG_PASSPHRASE_FD are mutually exclusive:
                if more than one of them is set, borg refuses to guess and aborts with
                "More than one passphrase environment variable is set". The same applies to the
                ``BORG_OTHER_*`` variants (which are a separate, independent group).
                See also BORG_NEW_PASSPHRASE.
            BORG_PASSCOMMAND (and BORG_OTHER_PASSCOMMAND)
                When set, use the standard output of the command (trailing newlines are stripped) to answer the
                passphrase question for encrypted repositories.
                It is used when a passphrase is needed to access an encrypted repo as well as when a new
                passphrase should be initially set when initializing an encrypted repo. Note that the command
                is executed without a shell. So variables, like ``$HOME`` will work, but ``~`` won't.
                Mutually exclusive with BORG_PASSPHRASE and BORG_PASSPHRASE_FD, see there.
                See also BORG_NEW_PASSPHRASE.
            BORG_PASSPHRASE_FD (and BORG_OTHER_PASSPHRASE_FD)
                When set, specifies a file descriptor to read a passphrase
                from. Programs starting borg may choose to open an anonymous pipe
                and use it to pass a passphrase. This is safer than passing via
                BORG_PASSPHRASE, because on some systems (e.g. Linux) environment
                can be examined by other processes.
                Mutually exclusive with BORG_PASSPHRASE and BORG_PASSCOMMAND, see there.
            BORG_NEW_PASSPHRASE
                When set, use the value to answer the passphrase question when a **new** passphrase is asked for.
                This variable is checked first. If it is not set, BORG_PASSPHRASE, BORG_PASSCOMMAND and
                BORG_PASSPHRASE_FD are checked (in that order).
                Main use case for this is to fully automate ``borg key change-passphrase``.
            BORG_DISPLAY_PASSPHRASE
                When set, use the value to answer the "display the passphrase for verification" question when defining a new passphrase for encrypted repositories.
            BORG_DEBUG_PASSPHRASE
                When set to YES, display debugging information that includes passphrases used and passphrase related env vars set.
            BORG_EXIT_CODES
                When set to "modern", the borg process will return more specific exit codes (rc).
                When set to "legacy", the borg process will return rc 2 for all errors, 1 for all warnings, 0 for success.
                Default is "modern".
            BORG_HOST_ID
                Borg usually computes a host id from the FQDN plus the results of ``uuid.getnode()`` (which usually returns
                a unique id based on the MAC address of the network interface. Except if that MAC happens to be all-zero - in
                that case it returns a random value, which is not what we want (because it kills automatic stale lock removal).
                So, if you have an all-zero MAC address or other reasons to better control the host id externally, just set this
                environment variable to a unique value. If all your FQDNs are unique, you can just use the FQDN. If not,
                use FQDN@uniqueid.
            BORG_HOSTNAME
                When set, use this value as the hostname (instead of the auto-detected one), e.g. to run borg
                on one host, but impersonate another host. This affects the hostname stored in newly created
                archives as well as the ``{hostname}`` placeholder.
            BORG_USERNAME
                When set, use this value as the username (instead of the auto-detected one), e.g. to run borg
                as one user, but impersonate another user. This affects the username stored in newly created
                archives as well as the ``{user}`` placeholder.
            BORG_LOCK_WAIT
                You can set the default value for the ``--lock-wait`` option with this, so
                you do not need to give it as a command line option.
            BORG_LOGGING_CONF
                When set, use the given filename as INI-style logging configuration (see
                https://docs.python.org/3/library/logging.config.html#configuration-file-format).
                A basic example conf can be found at ``docs/misc/logging.conf``.
            BORG_RSH
                When set, use this command instead of ``ssh``. This can be used to specify ssh options, such as
                a custom identity file ``ssh -i /path/to/private/key``. See ``man ssh`` for other options.
                This is the replacement for the removed ``--rsh CMD`` command line option.
                borg also gives this to borgstore as ``BORGSTORE_RSH``, except if that is already set.
            BORG_REMOTE_PATH
                When set, use the given path as borg executable on the remote (defaults to "borg" if unset).
                This is the replacement for the removed ``--remote-path PATH`` command line option.
            BORG_UNITS
                Determines how borg formats sizes in its human-readable output:

                - ``si`` (default): decimal units, e.g. ``1.23 MB`` (1kB = 1000B)
                - ``iec``: binary units, e.g. ``1.18 MiB`` (1KiB = 1024B)
                - ``raw``: exact byte counts, e.g. ``1234567 B``

                Use ``raw`` if you want to parse sizes with scripts (e.g. for monitoring),
                so you do not have to deal with scaled values and different units.
                Alternatively, use a command's ``--json`` output or, for the commands
                supporting ``--format``, the size related format keys - sizes are given
                as byte counts there anyway.

                ``BORG_UNITS=iec`` is the replacement for the removed ``BORG_IEC`` environment
                variable (and for the ``--iec`` command line option removed before that).
            BORG_PROGRESS_FPS
                How often the ``--progress`` output is updated at most, in updates per
                second (default: 5). Fractional values are allowed, e.g.
                ``BORG_PROGRESS_FPS=0.1`` limits it to one update every 10 seconds.
                Lower values are useful when the output goes into a logfile rather than
                to an interactive terminal.
            BORG_SPINNER
                Controls the spinner borg animates on a terminal while doing work of unknown
                duration:

                - unset (default): animate, using Unicode frames if the terminal can display them
                - ``ascii``: animate, but only use ASCII frames (``|/-\\``)
                - ``off``: do not animate, only output the messages next to the spinner

                The spinner is animated only on an interactive terminal anyway (and never
                with ``--log-json``), and its colour follows the usual ``NO_COLOR`` and
                ``COLORTERM`` conventions. See also ``BORG_PROGRESS_FPS``: it also gives
                the spinner its frame rate.
            BORG_DEBUG_PROFILE
                When set to a filename, write an execution profile in Borg format into that file
                (see :ref:`debugging`). If the filename ends with ``.pyprof``, a Python-compatible
                profile is written instead.
                This is the replacement for the removed ``--debug-profile`` command line option.
                Note: every borg invocation writes the profile, so unset it again when you are done.
            BORG_REPO_PERMISSIONS
                Set repository permissions, see also: :ref:`borg_serve`
            BORG_FILES_CACHE_SUFFIX
                When set to a value at least one character long, instructs borg to use a specifically named
                (based on the suffix) alternative files cache. This can be used to avoid loading and saving
                cache entries for backup sources other than the current sources.
            BORG_FILES_CACHE_TTL
                When set to a numeric value, this determines the maximum "time to live" for the files cache
                entries (default: 2). The files cache is used to determine quickly whether a file is unchanged.
            BORG_STORE_CACHE
                When set, borg keeps a local writethrough cache of the repository's ``packs/``
                namespace: on a cache miss the whole pack is fetched once and later reads of the
                objects inside that pack are served from the cache. Use this for slow or
                high-latency repositories.
                Set it to ``1`` to use ``$BORG_CACHE_DIR/storecache``, or to a directory path to
                use that directory (it is created if it does not exist). Packs are named by
                content hash, so one cache directory can safely hold packs of multiple repositories.
                If it is not set, no such caching happens.
            BORG_PACK_CACHE_SIZE
                When set to a numeric value, limit the pack cache to that many bytes.
                Only has an effect if BORG_STORE_CACHE is set.
            BORG_PACK_MAX_SIZE
                When set to a numeric value, cap packs (the repository objects that batch up many
                chunks, see the internals documentation about pack files) at that many bytes
                instead of the default of 50000000.
                Smaller packs mean more (but smaller) repository objects and more
                fine-grained uploads; bigger packs mean fewer objects and fewer stores.
            BORG_PACK_MAX_COUNT
                When set to a numeric value, cap packs at that many objects per pack.
                If BORG_PACK_MAX_SIZE is not also set, packs are then bound by count only.
            BORG_PACK_ASYNC
                When set to ``no``, disable the background thread that stores a finished pack
                while the next one is being assembled, and store packs synchronously instead.
                This is mainly a debugging aid.
            BORG_PACK_TRACE
                When set to ``yes``, print one-character lifecycle markers of the background
                pack store-thread to stderr (``<`` thread started, ``H`` hashing starts,
                ``S`` storing starts, ``>`` thread finished). This is a debugging aid to
                visualize how pack stores overlap with the assembly of the next pack.
            BORG_ASSERT_ID
                Comma-separated list of the places where borg shall verify that a chunk's content matches
                its chunk id (``chunkid == id_hash(content)``) after decrypting and decompressing it.
                Verifying costs a full hash pass over everything that is read at such a place.

                Default (variable not set)::

                    BORG_ASSERT_ID=repair,transfer,rechunk

                These are the place names that can be listed:

                read
                    Every read that decompresses a chunk: ``borg extract``, ``borg mount``,
                    ``borg export-tar``, ``borg diff``, ... This is by far the most data borg reads, so
                    this place is **not** in the default, see the explanation below.
                repair
                    ``borg check --repair``. It rebuilds archives from the item metadata stream it reads,
                    re-packing it into new chunks with freshly computed ids, and it recreates manifest and
                    archives directory entries from what it reads.
                transfer
                    ``borg transfer``, for everything it reads from the source repository. Transferring
                    re-anchors the content in another repository, which is a trust boundary.
                rechunk
                    ``borg recreate --chunker-params ...``, i.e. re-chunking reads. Re-chunking computes
                    new chunk ids from the content it reads, so a violation would not be noticeable any
                    more afterwards. (Re-chunking in ``borg transfer`` is covered by ``transfer``.)

                An unknown place name is an error. An empty value (``BORG_ASSERT_ID=``) verifies at none of
                these places, but still where borg always verifies (see below).

                Why ``read`` is not in the default: for encrypted repositories (all the AEAD ciphersuites),
                the chunk id is part of the AEAD additional authenticated data, so a successful decryption
                already proves that a holder of the repository key deliberately stored exactly this
                ciphertext for exactly this chunk id. A malicious or buggy **repository** can therefore not
                swap, splice or substitute objects, whether the id is verified on read or not. What the id
                check adds is the detection of chunks whose content does not match their id, which only a
                malicious or compromised **borg client that had your borg key** could have written (e.g. to
                poison future deduplication). If that is in your threat model - e.g. because some machines
                writing into the repository are not fully trusted - add ``read`` to the list::

                    BORG_ASSERT_ID=read,repair,transfer,rechunk

                Otherwise, running ``borg check --verify-data`` periodically is recommended: it is the
                audit that re-certifies the invariant for all chunks in the background, instead of on
                every read.

                Independent of this variable, borg always verifies the chunk id:

                - in ``borg check --verify-data``. That audit is what makes not verifying elsewhere
                  defensible, so it is not configurable (there is no ``verify_data`` place name).
                - for ``authenticated`` and ``none`` mode repositories: there is no AEAD there, so the id
                  check *is* the read path's integrity check and switching it off would remove it
                  completely. Same for reading borg 1.x repositories (``borg transfer``).
            BORG_BLAKE3_MT_THRESHOLD
                When set to a numeric value, chunks of at least that many KiB get their id computed by
                multi-threaded BLAKE3, smaller ones single-threaded (default: 256, i.e. 256KiB).
                Only relevant for repositories using ``--id-hash blake3``.
                Multi-threading only pays off for big enough chunks and the break-even point depends on
                the machine's core count, so the default is deliberately conservative.
                Run ``scripts/blake3-optimize-mt-threshold.py`` to measure the best value for your
                machine - it sweeps input sizes, prints the recommended threshold and the command to
                set it, and can optionally show a chart of the measurements in your browser
                (``--html --open``).
                0 means "always multi-threaded", a very large value effectively disables multi-threading.
            BORG_ZSTD_MT_WORKERS
                When set to a numeric value, use that many threads to zstd-compress a single chunk
                (default: the cpu count, but at most 4). 0 or 1 means single-threaded compression.
                Only relevant when compressing with ``zstd``.
                Chunks below 768KiB are always compressed single-threaded: libzstd will not use a
                compression job smaller than 512KiB, so a small chunk gets split very unevenly and
                multi-threading it would be slower than not doing it at all.
                The default is capped at 4 because a chunk of the size the default chunker aims at
                (2MiB) splits into just 4 such jobs: threads beyond that get (nearly) no work, but
                the whole thread pool is created again for every chunk. Measured on a 12-core
                machine, 4 threads beat 12 on every test corpus at the default ``zstd,-4``
                (+13% .. +37%). Raising the value only pays off if you configured the chunker
                for much bigger chunks. ``borg export-tar`` compresses one long stream instead of
                separate chunks and always defaults to the cpu count.
                Multi-threading trades a little compression ratio for speed (measured at ``zstd,3``:
                +0.05% archive size for 1MiB chunks, +0.64% for 8MiB ones, more at higher levels), and
                it uses more cpu time in total to reduce the wallclock time. Set it to 1 if you would
                rather have the smaller archive, or if borg has to share the cpu with other work.
                Single-threaded can even be faster on data zstd races through anyway, e.g.
                already-compressed/incompressible data or long-repeat data like VM images.
            BORG_FASTCDC_KERNEL / BORG_BUZHASH64_KERNEL
                Select the scan kernel the ``fastcdc`` / ``buzhash64`` chunker uses. Accepted values
                are ``avx512``, ``avx2``, ``neon``, ``blockwise`` and ``scalar``.
                The default is whichever benchmarked fastest for the architecture: ``neon`` on
                aarch64, and ``scalar`` (the plain sequential loop) on x86-64, where the compiler
                folds the rolling hash update into a single instruction and thereby beats the vector
                kernels. Other architectures get ``blockwise``, the portable multi-lane C kernel.
                All kernels chunk identically - same cut points, same chunk ids - and differ only in
                speed, so this is safe to change at any time, also for an existing repository.
                Which kernel is fastest is not predictable from the instruction set: it depends on the
                cpu and on the compiler that built borg, and the sequential loop wins on some machines.
                Measure on your own hardware with ``borg benchmark cpu --chunking`` before overriding
                the default.
                ``avx512`` and ``avx2`` exist only on x86-64, ``neon`` only on aarch64, and only if the
                compiler that built borg supported them; ``scalar`` and ``blockwise`` are portable C
                and always available.
                Requesting a kernel that this build or this cpu cannot run is an error rather than a
                silent fallback, so a benchmark can not accidentally measure a different kernel.
                ``borg create --debug`` logs the chunker and the kernel it was created with.
            BORG_AES_CHUNKER_KERNEL
                Select the scan kernel used by the AES based chunkers - one variable for all three of
                ``toeplitz-aes``, ``rabin-aes`` and ``goldilocks-aes``. Accepted values are ``vaes``,
                ``aes-ni``, ``aes-arm64`` and ``evp``.
                Unlike the chunker kernels above, wider is simply faster here, so the default is the
                best path this build and cpu offer: ``vaes``, else ``aes-ni`` on x86-64, ``aes-arm64``
                on aarch64, and ``evp`` (the portable OpenSSL path) where there is no AES hardware
                path.
                As with the chunker kernels above, all of them chunk identically and differ only in
                speed, and a kernel that can not run here is an error rather than a silent fallback.
                ``vaes`` and ``aes-ni`` exist only on x86-64, ``aes-arm64`` only on aarch64.
                ``vaes`` additionally needs a compiler that knows it (gcc >= 11 / clang >= 14), so a
                cpu supporting VAES is not by itself enough to have that kernel available.
            BORG_SHOW_SYSINFO
                When set to no (default: yes), system information (like OS, Python version, ...) in
                exceptions is not shown.
                Please only use for good reasons as it makes issues harder to analyze.
            BORG_MSGPACK_VERSION_CHECK
                Controls whether Borg checks the ``msgpack`` version.
                The default is ``yes`` (strict check). Set to ``no`` to disable the version check and
                allow any installed ``msgpack`` version. Use this at your own risk; malfunctioning or
                incompatible ``msgpack`` versions may cause subtle bugs or repository data corruption.
            BORG_FUSE_IMPL
                Choose the low-level FUSE implementation borg shall use for ``borg mount``.
                This is a comma-separated list of implementation names, they are tried in the
                given order, e.g.:

                - ``mfusepy,pyfuse3,llfuse``: default, first try to load mfusepy, then pyfuse3, then llfuse.
                - ``llfuse,pyfuse3``: first try to load llfuse, then try to load pyfuse3.
                - ``mfusepy``: only try to load mfusepy
                - ``pyfuse3``: only try to load pyfuse3
                - ``llfuse``: only try to load llfuse
                - ``none``: do not try to load an implementation
            BORG_MOUNT_DATA_CACHE_ENTRIES
                Number of decrypted file content chunks ``borg mount`` and ``borg webdav`` keep
                in an in-memory cache, so that the many small, sequential reads a mounted file
                system does for a big file do not re-fetch and re-decrypt the same chunk over and
                over (default: the cpu count). Additional memory usage can be up to the chunk size
                times this number.
            BORG_SELFTEST
                This can be used to influence borg's built-in self-tests. The default is to execute the tests
                at the beginning of each borg command invocation.

                BORG_SELFTEST=disabled can be used to switch off the tests and rather save some time.
                Disabling is not recommended for normal borg users, but large scale borg storage providers can
                use this to optimize production servers after at least doing a one-time test borg (with
                self-tests not disabled) when installing or upgrading machines/OS/Borg.
            BORG_WORKAROUNDS
                A list of comma-separated strings that trigger workarounds in borg,
                e.g. to work around bugs in other software.

                Currently known strings are:

                basesyncfile
                    Use the more simple BaseSyncFile code to avoid issues with sync_file_range.
                    You might need this to run borg on WSL (Windows Subsystem for Linux) or
                    in systemd.nspawn containers on some architectures (e.g. ARM).
                    Using this does not affect data safety, but might result in a more bursty
                    write-to-disk behavior (not continuously streaming to disk).

                retry_erofs
                    Retry opening a file without O_NOATIME if opening a file with O_NOATIME
                    caused EROFS. You will need this to make archives from volume shadow copies
                    in WSL1 (Windows Subsystem for Linux 1).

                authenticated_no_key
                    Work around a lost passphrase or a lost borg key for an ``authenticated-*``
                    mode repository (these are only authenticated, but not encrypted).
                    If a borg key is found - an object below ``keys/`` in the repository (repokey)
                    resp. a key file in the keys directory (keyfile) - it is not unlocked, so the
                    passphrase does not matter. If no borg key is found at all, borg proceeds
                    anyway, without any key material.

                    Without the key, borg can not verify anything that needs it: neither the
                    authentication tag of the repository objects nor the chunk ids. It therefore
                    reads the repository **unverified** - a corrupted or tampered repository will
                    not be detected. (This only concerns the ``authenticated-*`` modes; the
                    ``none-*`` modes need no key and keep verifying their checksums.)

                    This workaround is **only** for emergencies and **only** to extract data
                    from an affected repository (read-only access)::

                        BORG_WORKAROUNDS=authenticated_no_key borg extract --repo repo archive

                    After you have extracted all data you need, you MUST delete the repository::

                        BORG_WORKAROUNDS=authenticated_no_key borg repo-delete --repo repo

                    Now you can create a fresh repository with ``borg repo-create``. Make sure you
                    do not use the workaround any more.

        Output formatting:
            BORG_CHECK_FORMAT
                Giving the default value for ``borg check --format=X``.
            BORG_DIFF_FORMAT
                Giving the default value for ``borg diff --format=X``.
                Note: ``borg diff --content-only`` uses its own format and ignores this.
            BORG_FIND_FORMAT
                Giving the default value for ``borg find --format=X``.
            BORG_LIST_FORMAT
                Giving the default value for ``borg list --format=X``.
            BORG_REPO_LIST_FORMAT
                Giving the default value for ``borg repo-list --format=X``.
            BORG_PRUNE_FORMAT
                Giving the default value for ``borg prune --format=X``.
            BORG_MOUNT_ARCHIVE_DIR_FORMAT
                Giving the format of the archive directory names when ``borg mount`` or
                ``borg webdav`` show a whole repository, default: ``{name}``. The placeholders
                are the ones of ``borg repo-list --format``; names that are not unique get
                ``-{id:.8}`` appended. See ``borg mount --help``.
            BORG_JSON_INDENT
                Indentation of the ``--json`` output (default: ``4``).
                A number gives that many spaces per nesting level (``0`` still puts every item on
                its own line), ``none`` gives compact single-line JSON, and any other value is used
                as the literal indent string (e.g. a tab or the empty string).

        Some automatic "answerers" (if set, they automatically answer confirmation questions):
            BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no (or =yes)
                For "Warning: Attempting to access a previously unknown unencrypted repository"
            BORG_RELOCATED_REPO_ACCESS_IS_OK=no (or =yes)
                For "Warning: The repository at location ... was previously located at ..."
            BORG_CHECK_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
                For "This is a potentially dangerous function..." (check --repair)
            BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
                For "You requested to DELETE the repository completely *including* all archives it contains:"

            Note: answers are case sensitive. setting an invalid answer value might either give the default
            answer or ask you interactively, depending on whether retries are allowed (they by default are
            allowed). So please test your scripts interactively before making them a non-interactive script.

        Directories and files:
            Borg 2 uses the platformdirs library (https://pypi.org/project/platformdirs/) to determine
            default directory locations. This means that default paths are **platform-specific**:

            - Linux: XDG Base Directory Specification paths are used (e.g. ``~/.config/borg``,
              ``~/.cache/borg``, ``~/.local/share/borg``). ``XDG_*`` environment variables are
              honoured (see https://specifications.freedesktop.org/basedir/latest/).
            - macOS: native macOS directories are used by default (e.g. ``~/Library/Application Support/borg``,
              ``~/Library/Caches/borg``). ``XDG_*`` environment variables are honoured if set.
            - Windows: Windows AppData directories are used (e.g. ``C:\\Users\\<user>\\AppData\\Roaming\\borg``,
              ``C:\\Users\\<user>\\AppData\\Local\\borg``). ``XDG_*`` environment variables are **not** honoured.

            On all platforms, you can override each directory individually using the specific environment
            variables described below. You can also set ``BORG_BASE_DIR`` to force borg to use
            ``BORG_BASE_DIR/.config/borg``, ``BORG_BASE_DIR/.cache/borg``, etc., regardless of the platform.

            Default directory locations by platform (when no ``BORG_*`` environment variables are set)::

                Directory  Linux                 macOS                                 Windows
                Config     ~/.config/borg        ~/Library/Application Support/borg    %APPDATA%\\borg
                Cache      ~/.cache/borg         ~/Library/Caches/borg                 %LOCALAPPDATA%\\borg\\Cache
                Data       ~/.local/share/borg   ~/Library/Application Support/borg    %LOCALAPPDATA%\\borg
                Runtime    /run/user/<uid>/borg  ~/Library/Caches/TemporaryItems/borg  %TEMP%\\borg
                Keys       <config_dir>/keys     <config_dir>/keys                     <config_dir>\\keys
                Security   <data_dir>/security   <data_dir>/security                   <data_dir>\\security

            BORG_BASE_DIR
                Not set by default - then the platform-specific directories shown in the table above
                are used.
                If you want to move all borg-specific folders to a custom path at once, all you need to do is
                to modify ``BORG_BASE_DIR``: the other paths for cache, config etc. will adapt accordingly
                (assuming you didn't set them to a different custom value).
            BORG_CACHE_DIR
                Defaults to the platform-specific cache directory (see table above).
                If ``BORG_BASE_DIR`` is set, defaults to ``$BORG_BASE_DIR/.cache/borg``.
                On Linux and macOS, ``XDG_CACHE_HOME`` is also honoured if ``BORG_BASE_DIR`` is not set.
                This directory contains the local cache and might need a lot
                of space for dealing with big repositories. Make sure you're aware of the associated
                security aspects of the cache location: :ref:`cache_security`
            BORG_CONFIG_DIR
                Defaults to the platform-specific config directory (see table above).
                If ``BORG_BASE_DIR`` is set, defaults to ``$BORG_BASE_DIR/.config/borg``.
                On Linux and macOS, ``XDG_CONFIG_HOME`` is also honoured if ``BORG_BASE_DIR`` is not set.
                This directory contains all borg configuration directories, see the FAQ
                for a security advisory about the data in this directory: :ref:`home_config_borg`
            BORG_DATA_DIR
                Defaults to the platform-specific data directory (see table above).
                If ``BORG_BASE_DIR`` is set, defaults to ``$BORG_BASE_DIR/.local/share/borg``.
                On Linux and macOS, ``XDG_DATA_HOME`` is also honoured if ``BORG_BASE_DIR`` is not set.
                This directory contains all borg data directories, see the FAQ
                for a security advisory about the data in this directory: :ref:`home_data_borg`
            BORG_RUNTIME_DIR
                Defaults to the platform-specific runtime directory (see table above).
                If ``BORG_BASE_DIR`` is set, defaults to ``$BORG_BASE_DIR/.cache/borg``.
                On Linux and macOS, ``XDG_RUNTIME_DIR`` is also honoured if ``BORG_BASE_DIR`` is not set.
                This directory contains borg runtime files, like e.g. the socket file.
            BORG_SECURITY_DIR
                Defaults to ``$BORG_DATA_DIR/security``.
                This directory contains security relevant data.
            BORG_KEYS_DIR
                Defaults to ``$BORG_CONFIG_DIR/keys``.
                This directory contains keys for encrypted repositories.
            BORG_KEY_FILE
                When set, use the given path as repository key file. Please note that this is only
                for rather special applications that externally fully manage the key files:

                - this setting only applies to the keyfile modes (not to the repokey modes).
                - using a full, absolute path to the key file is recommended.
                - all directories in the given path must exist.
                - this setting forces borg to use the key file at the given location.
                - the key file must either exist (for most commands) or will be created (``borg repo-create``).
                - you need to give a different path for different repositories.
                - you need to point to the correct key file matching the repository the command will operate on.
            TMPDIR
                This is where temporary files are stored (might need a lot of temporary space for some
                operations), see https://docs.python.org/3/library/tempfile.html#tempfile.gettempdir
                for details.

        Building:
            These are only read by ``setup.py`` while building borg's C extensions. Each
            ``BORG_*_PREFIX`` variable names the install prefix of a library that borg links
            against: if it is set, ``$PREFIX/include`` and ``$PREFIX/lib`` are used unconditionally.
            If it is not set, the library is located via pkg-config, and if that does not find it
            either, the build fails - there is no bundled fallback implementation.

            BORG_OPENSSL_PREFIX
                Prefix of the OpenSSL installation to build libcrypto against.
                On Windows, the libraries are expected in ``$PREFIX`` itself rather than in
                ``$PREFIX/lib``. On OpenBSD, this defaults to ``/usr/local``, pkg-config is not
                used and libcrypto is linked statically (borg needs AES-OCB via the EVP API, which
                LibreSSL does not have).
            BORG_OPENSSL_NAME
                OpenBSD only: the OpenSSL flavour to use, i.e. the ``include/`` and ``lib/``
                subdirectory name below ``BORG_OPENSSL_PREFIX`` (default: ``eopenssl35``).
            BORG_LIBLZ4_PREFIX
                Prefix of the liblz4 installation to build against.
            BORG_LIBACL_PREFIX
                Linux only: prefix of the libacl installation to build against.

        Automatic option environment variables:
            Borg uses jsonargparse (https://jsonargparse.readthedocs.io/) with ``default_env=True``,
            which means that every command-line option can also be set via an environment variable.

            The environment variable name is derived from the program name (``borg``),
            the subcommand (if any), and the option name, all converted to uppercase
            with dashes replaced by underscores.

            For **top-level options** (not specific to a subcommand), the pattern is::

                BORG_<OPTION>

            For example, ``--lock-wait`` can be set via ``BORG_LOCK_WAIT``.

            For **subcommand options**, the subcommand and option are separated by a
            double underscore::

                BORG_<SUBCOMMAND>__<OPTION>

            For example, ``borg create --comment`` can be set via ``BORG_CREATE__COMMENT``.

        Please note:

        - Be very careful when using the "yes" sayers, the warnings with prompt exist for your / your data's security/safety.
        - Also be very careful when putting your passphrase into a script, make sure it has appropriate file permissions (e.g.
          mode 600, root:root).\n\n"""
    )
    helptext_aliases = {"env": "environment"}

    def do_help(self, parser, args):
        commands = getattr(parser, "_subcommands_action", None)
        commands = commands._name_parser_map if commands else {}
        topic = self.helptext_aliases.get(args.topic, args.topic)

        if not args.topic:
            parser.print_help()
        elif topic in self.helptext:
            print(rst_to_terminal(self.helptext[topic], rst_plain_text_references))
        elif args.topic in commands:
            if args.epilog_only:
                print(commands[args.topic].epilog)
            elif args.usage_only:
                commands[args.topic].epilog = None
                commands[args.topic].print_help()
            else:
                commands[args.topic].print_help()
        else:
            msg_lines = []
            msg_lines += ["No help available on %s." % args.topic]
            msg_lines += ["Try one of the following:"]
            msg_lines += ["    Commands: %s" % ", ".join(sorted(commands.keys()))]
            msg_lines += ["    Topics: %s" % ", ".join(sorted(self.helptext.keys()))]
            parser.error("\n".join(msg_lines))

    def do_subcommand_help(self, parser, args):
        """display infos about subcommand"""
        parser.print_help()

    do_maincommand_help = do_subcommand_help

    def build_parser_help(self, subparsers, common_parser, mid_common_parser, parser):
        subparser = ArgumentParser(parents=[common_parser], description="Extra help")
        subparsers.add_subcommand("help", subparser, help="Extra help")
        subparser.add_argument("--epilog-only", dest="epilog_only", action="store_true")
        subparser.add_argument("--usage-only", dest="usage_only", action="store_true")
        subparser.add_argument("topic", metavar="TOPIC", type=str, nargs="?", help="additional help on TOPIC")
