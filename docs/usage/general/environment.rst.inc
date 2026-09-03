Environment Variables
~~~~~~~~~~~~~~~~~~~~~

.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

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
        - ``ascii``: animate, but only use ASCII frames (``|/-\``)
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

        Why ``read`` is not in the default: in the keyed modes, the envelope already authenticates
        every read - the AEAD tag for the encrypted ciphersuites, the MAC for the (unencrypted)
        ``authenticated-*`` modes - and the chunk id is part of what that tag is computed over. So
        a successful decryption resp. tag check already proves that a holder of the borg key
        deliberately stored exactly this payload for exactly this chunk id, and a malicious or
        buggy **repository** can not swap, splice or substitute objects, whether the id is
        verified on read or not. What the id check adds is the detection of chunks whose content
        does not match their id, which only a malicious or compromised **borg client that had
        your borg key** could have written (e.g. to poison future deduplication). If that is in
        your threat model - e.g. because some machines writing into the repository are not fully
        trusted - add ``read`` to the list::

            BORG_ASSERT_ID=read,repair,transfer,rechunk

        Otherwise, running ``borg check --verify-data`` periodically is recommended: it is the
        audit that re-certifies the invariant for all chunks in the background, instead of on
        every read.

        Independent of this variable, borg always verifies the chunk id:

        - in ``borg check --verify-data``. That audit is what makes not verifying elsewhere
          defensible, so it is not configurable (there is no ``verify_data`` place name).
        - for ``none-*`` mode repositories: they have no key, so nothing authenticates a read
          there and their unkeyed checksums only detect accidental corruption. The id check is
          therefore not optional there: it happens at every place, whatever this variable says.
          Same for reading borg 1.x repositories (``borg transfer``).
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
        (default: the cpu count, but at most 4). If it is unset or empty, the default is
        used. 0 or 1 means single-threaded compression.
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
        The default is whichever benchmarked fastest for the architecture: ``scalar`` (the
        plain sequential loop) on x86-64, where the compiler folds the rolling hash update
        into one or two instructions and thereby beats the vector kernels; on aarch64
        ``neon`` for ``fastcdc`` and ``blockwise`` for ``buzhash64``, whose NEON kernel
        loses to the portable multi-lane C kernel there. Other architectures get
        ``blockwise``.
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
    - Windows: native Windows AppData directories are used. The configuration (including
      the keys) is stored in the roaming profile (``C:\Users\<user>\AppData\Roaming\borg``),
      so it follows the user in domain environments. Machine-specific data, cache and runtime
      files stay in the local (non-roaming) AppData (``C:\Users\<user>\AppData\Local\borg``).
      ``XDG_*`` environment variables are **not** honoured.

    On all platforms, you can override each directory individually using the specific environment
    variables described below. You can also set ``BORG_BASE_DIR`` to force borg to use
    ``BORG_BASE_DIR/.config/borg``, ``BORG_BASE_DIR/.cache/borg``, etc., regardless of the platform.

    Default directory locations by platform (when no ``BORG_*`` environment variables are set)::

        Directory  Linux                 macOS                                 Windows
        Config     ~/.config/borg        ~/Library/Application Support/borg    %APPDATA%\borg
        Cache      ~/.cache/borg         ~/Library/Caches/borg                 %LOCALAPPDATA%\borg\Cache
        Data       ~/.local/share/borg   ~/Library/Application Support/borg    %LOCALAPPDATA%\borg
        Runtime    /run/user/<uid>/borg  ~/Library/Caches/TemporaryItems/borg  %LOCALAPPDATA%\Temp\borg
        Keys       <config_dir>/keys     <config_dir>/keys                     <config_dir>\keys
        Security   <data_dir>/security   <data_dir>/security                   <data_dir>\security

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
  mode 600, root:root).

