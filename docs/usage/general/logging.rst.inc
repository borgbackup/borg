Logging
~~~~~~~

Borg writes all log output to stderr by default. However, output on stderr does
not necessarily indicate an error. Check the log levels of the messages and the
return code of borg to determine error, warning, or success conditions.

If you want to capture the log output to a file, just redirect it:

::

    borg create --repo repo archive myfiles 2>> logfile


Custom logging configurations can be implemented via BORG_LOGGING_CONF.

The log level of the built-in logging configuration defaults to WARNING.
This is because we want Borg to be mostly silent and only output
warnings, errors, and critical messages unless output has been requested
by supplying an option that implies output (e.g., ``--list`` or ``--progress``).

Log levels: DEBUG < INFO < WARNING < ERROR < CRITICAL

Use ``--debug`` to set the DEBUG log level —
this prints debug, info, warning, error, and critical messages.

Use ``--info`` (or ``-v`` or ``--verbose``) to set the INFO log level —
this prints info, warning, error, and critical messages.

Use ``--warning`` (default) to set the WARNING log level —
this prints warning, error, and critical messages.

Use ``--error`` to set the ERROR log level —
this prints error and critical messages.

Use ``--critical`` to set the CRITICAL log level —
this prints only critical messages.

While you can set miscellaneous log levels, do not expect every command to
produce different output at different log levels — it's merely a possibility.

.. warning:: Options ``--critical`` and ``--error`` are provided for completeness,
             their usage is not recommended as you might miss important information.
