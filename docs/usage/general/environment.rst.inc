Environment Variables
~~~~~~~~~~~~~~~~~~~~~

Borg uses some environment variables for automation:

General:
    BORG_REPO
        When set, use the value to give the default repository location. If a command needs an archive
        parameter, you can abbreviate as ``::archive``. If a command needs a repository parameter, you
        can either leave it away or abbreviate as ``::``, if a positional parameter is required.
    BORG_PASSPHRASE
        When set, use the value to answer the passphrase question for encrypted repositories.
        It is used when a passphrase is needed to access an encrypted repo as well as when a new
        passphrase should be initially set when initializing an encrypted repo.
        See also BORG_NEW_PASSPHRASE.
    BORG_PASSCOMMAND
        When set, use the standard output of the command (trailing newlines are stripped) to answer the
        passphrase question for encrypted repositories.
        It is used when a passphrase is needed to access an encrypted repo as well as when a new
        passphrase should be initially set when initializing an encrypted repo. Note that the command
        is executed without a shell. So variables, like ``$HOME`` will work, but ``~`` won't.
        If BORG_PASSPHRASE is also set, it takes precedence.
        See also BORG_NEW_PASSPHRASE.
    BORG_PASSPHRASE_FD
        When set, specifies a file descriptor to read a passphrase
        from. Programs starting borg may choose to open an anonymous pipe
        and use it to pass a passphrase. This is safer than passing via
        BORG_PASSPHRASE, because on some systems (e.g. Linux) environment
        can be examined by other processes.
        If BORG_PASSPHRASE or BORG_PASSCOMMAND are also set, they take precedence.
    BORG_NEW_PASSPHRASE
        When set, use the value to answer the passphrase question when a **new** passphrase is asked for.
        This variable is checked first. If it is not set, BORG_PASSPHRASE and BORG_PASSCOMMAND will also
        be checked.
        Main usecase for this is to fully automate ``borg change-passphrase``.
    BORG_DISPLAY_PASSPHRASE
        When set, use the value to answer the "display the passphrase for verification" question when defining a new passphrase for encrypted repositories.
    BORG_HOSTNAME_IS_UNIQUE=no
        Borg assumes that it can derive a unique hostname / identity (see ``borg debug info``).
        If this is not the case or you do not want Borg to automatically remove stale locks,
        set this to *no*.
    BORG_HOST_ID
        Borg usually computes a host id from the FQDN plus the results of ``uuid.getnode()`` (which usually returns
        a unique id based on the MAC address of the network interface. Except if that MAC happens to be all-zero - in
        that case it returns a random value, which is not what we want (because it kills automatic stale lock removal).
        So, if you have a all-zero MAC address or other reasons to better externally control the host id, just set this
        environment variable to a unique value. If all your FQDNs are unique, you can just use the FQDN. If not,
        use fqdn@uniqueid.
    BORG_LOGGING_CONF
        When set, use the given filename as INI_-style logging configuration.
        A basic example conf can be found at ``docs/misc/logging.conf``.
    BORG_RSH
        When set, use this command instead of ``ssh``. This can be used to specify ssh options, such as
        a custom identity file ``ssh -i /path/to/private/key``. See ``man ssh`` for other options. Using
        the ``--rsh CMD`` commandline option overrides the environment variable.
    BORG_REMOTE_PATH
        When set, use the given path as borg executable on the remote (defaults to "borg" if unset).
        Using ``--remote-path PATH`` commandline option overrides the environment variable.
    BORG_FILES_CACHE_SUFFIX
        When set to a value at least one character long, instructs borg to use a specifically named
        (based on the suffix) alternative files cache. This can be used to avoid loading and saving
        cache entries for backup sources other than the current sources.
    BORG_FILES_CACHE_TTL
        When set to a numeric value, this determines the maximum "time to live" for the files cache
        entries (default: 20). The files cache is used to quickly determine whether a file is unchanged.
        The FAQ explains this more detailed in: :ref:`always_chunking`
    BORG_SHOW_SYSINFO
        When set to no (default: yes), system information (like OS, Python version, ...) in
        exceptions is not shown.
        Please only use for good reasons as it makes issues harder to analyze.
    BORG_LIBC
        borg uses ``ctypes.util.find_library`` to locate the 'c' library (aka libc).
        find_library needs a shell and will invoke some tools like ldconfig, gcc/cc or objdump.
        If a shell or these tools are not available, you can give the name of your libc via
        BORG_LIBC=libc.so.6 (for example) and borg will not try the ``find_library`` call.
    BORG_SELFTEST
        This can be used to influence borg's builtin self-tests. The default is to execute the tests
        at the beginning of each borg command invocation.

        BORG_SELFTEST=disabled can be used to switch off the tests and rather save some time.
        Disabling is not recommended for normal borg users, but large scale borg storage providers can
        use this to optimize production servers after at least doing a one-time test borg (with
        selftests not disabled) when installing or upgrading machines / OS / borg.
    BORG_WORKAROUNDS
        A list of comma separated strings that trigger workarounds in borg,
        e.g. to work around bugs in other software.

        Currently known strings are:

        basesyncfile
            Use the more simple BaseSyncFile code to avoid issues with sync_file_range.
            You might need this to run borg on WSL (Windows Subsystem for Linux) or
            in systemd.nspawn containers on some architectures (e.g. ARM).
            Using this does not affect data safety, but might result in a more bursty
            write to disk behaviour (not continuously streaming to disk).

Some automatic "answerers" (if set, they automatically answer confirmation questions):
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no (or =yes)
        For "Warning: Attempting to access a previously unknown unencrypted repository"
    BORG_RELOCATED_REPO_ACCESS_IS_OK=no (or =yes)
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
        For "This is a potentially dangerous function..." (check --repair)
    BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=NO (or =YES)
        For "You requested to completely DELETE the repository *including* all archives it contains:"

    Note: answers are case sensitive. setting an invalid answer value might either give the default
    answer or ask you interactively, depending on whether retries are allowed (they by default are
    allowed). So please test your scripts interactively before making them a non-interactive script.

.. _XDG env var: https://specifications.freedesktop.org/basedir-spec/0.6/ar01s03.html

Directories and files:
    BORG_BASE_DIR
        Defaults to ``$HOME`` or ``~$USER`` or ``~`` (in that order).
        If you want to move all borg-specific folders to a custom path at once, all you need to do is
        to modify ``BORG_BASE_DIR``: the other paths for cache, config etc. will adapt accordingly
        (assuming you didn't set them to a different custom value).
    BORG_CACHE_DIR
        Defaults to ``$BORG_BASE_DIR/.cache/borg``. If ``BORG_BASE_DIR`` is not explicitly set while
        `XDG env var`_ ``XDG_CACHE_HOME`` is set, then ``$XDG_CACHE_HOME/borg`` is being used instead.
        This directory contains the local cache and might need a lot
        of space for dealing with big repositories. Make sure you're aware of the associated
        security aspects of the cache location: :ref:`cache_security`
    BORG_CONFIG_DIR
        Defaults to ``$BORG_BASE_DIR/.config/borg``. If ``BORG_BASE_DIR`` is not explicitly set while
        `XDG env var`_ ``XDG_CONFIG_HOME`` is set, then ``$XDG_CONFIG_HOME/borg`` is being used instead.
        This directory contains all borg configuration directories, see the FAQ
        for a security advisory about the data in this directory: :ref:`home_config_borg`
    BORG_SECURITY_DIR
        Defaults to ``$BORG_CONFIG_DIR/security``.
        This directory contains information borg uses to track its usage of NONCES ("numbers used
        once" - usually in encryption context) and other security relevant data.
    BORG_KEYS_DIR
        Defaults to ``$BORG_CONFIG_DIR/keys``.
        This directory contains keys for encrypted repositories.
    BORG_KEY_FILE
        When set, use the given filename as repository key file.
    TMPDIR
        This is where temporary files are stored (might need a lot of temporary space for some
        operations), see tempfile_ for details.

Building:
    BORG_OPENSSL_PREFIX
        Adds given OpenSSL header file directory to the default locations (setup.py).
    BORG_LIBLZ4_PREFIX
        Adds given prefix directory to the default locations. If a 'include/lz4.h' is found Borg
        will be linked against the system liblz4 instead of a bundled implementation. (setup.py)
    BORG_LIBB2_PREFIX
        Adds given prefix directory to the default locations. If a 'include/blake2.h' is found Borg
        will be linked against the system libb2 instead of a bundled implementation. (setup.py)
    BORG_LIBZSTD_PREFIX
        Adds given prefix directory to the default locations. If a 'include/zstd.h' is found Borg
        will be linked against the system libzstd instead of a bundled implementation. (setup.py)

Please note:

- Be very careful when using the "yes" sayers, the warnings with prompt exist for your / your data's security/safety.
- Also be very careful when putting your passphrase into a script, make sure it has appropriate file permissions (e.g.
  mode 600, root:root).

.. _INI: https://docs.python.org/3/library/logging.config.html#configuration-file-format

.. _tempfile: https://docs.python.org/3/library/tempfile.html#tempfile.gettempdir
