Logging
~~~~~~~

Borg writes all log output to stderr by default. But please note that something
showing up on stderr does *not* indicate an error condition just because it is
on stderr. Please check the log levels of the messages and the return code of
borg for determining error, warning or success conditions.

If you want to capture the log output to a file, just redirect it:

::

    borg create repo::archive myfiles 2>> logfile


Custom logging configurations can be implemented via BORG_LOGGING_CONF.

The log level of the builtin logging configuration defaults to WARNING.
This is because we want Borg to be mostly silent and only output
warnings, errors and critical messages, unless output has been requested
by supplying an option that implies output (e.g. ``--list`` or ``--progress``).

Log levels: DEBUG < INFO < WARNING < ERROR < CRITICAL

Use ``--debug`` to set DEBUG log level -
to get debug, info, warning, error and critical level output.

Use ``--info`` (or ``-v`` or ``--verbose``) to set INFO log level -
to get info, warning, error and critical level output.

Use ``--warning`` (default) to set WARNING log level -
to get warning, error and critical level output.

Use ``--error`` to set ERROR log level -
to get error and critical level output.

Use ``--critical`` to set CRITICAL log level -
to get critical level output.

While you can set misc. log levels, do not expect that every command will
give different output on different log levels - it's just a possibility.

.. warning:: Options ``--critical`` and ``--error`` are provided for completeness,
             their usage is not recommended as you might miss important information.
