Configuration files
~~~~~~~~~~~~~~~~~~~

Borg supports reading options from YAML configuration files.  This is
implemented via `jsonargparse <https://jsonargparse.readthedocs.io/>`_
and works for all options that can also be set on the command line.

Default configuration file
    ``$BORG_CONFIG_DIR/default.yaml`` is loaded automatically on every Borg
    invocation if it exists. You do not need to pass ``--config`` explicitly
    for this file.

``--config PATH``
    Load additional options from the YAML file at *PATH*.
    Options in this file take precedence over the default config file but are
    overridden by explicit command-line arguments. This option can be used
    multiple times, with later files overriding earlier ones.

``--print_config``
    Print the current effective configuration (all options in YAML format) to
    stdout and exit. This reflects the merged result of the default config
    file, any ``--config`` file, environment variables, and command-line
    arguments given before ``--print_config``. The output can be used as a
    starting point for a config file.

File format
    Config files are YAML documents. Top-level keys are option names
    (without leading ``--`` and with ``-`` replaced by ``_``).
    Nested keys correspond to subcommands.

    Example ``default.yaml``::

        # apply to all borg commands:
        log_level: info
        show_rc: true

        # options specific to "borg create":
        create:
            compression: zstd,3
            stats: true

    The top-level keys set options that are common to all commands (equivalent
    to placing them before the subcommand on the command line).  Keys nested
    under a subcommand name (e.g. ``create:``) are only applied when that
    subcommand is invoked.

Precedence (lowest to highest)
    1. Default config file (``$BORG_CONFIG_DIR/default.yaml``)
    2. ``--config`` file(s) (in the order given)
    3. Environment variables (e.g. ``BORG_REPO``)
    4. Command-line arguments

.. note::
    ``--print_config`` shows the merged effective configuration and is a
    convenient way to check what values Borg will actually use, and to
    generate contents for your borg config file(s)::

        borg --repo /backup/main create --compression zstd,3 --print_config
