.. highlight:: none
.. _cockpit:

Cockpit
-------

The cockpit is a full-screen terminal user interface showing what a borg command does
while it runs: its progress, its statistics, the file list and the log messages, all
updated live. To use it, put ``--cockpit`` in front of the command::

    $ borg --cockpit -r /path/to/repo create --list my-files ~/Documents
    $ borg --cockpit -r /path/to/repo extract --list my-files
    $ borg --cockpit -r /path/to/repo check --repair

The cockpit needs the ``textual`` package: ``pip install borgbackup[cockpit]`` installs
it, the binary releases include it (see :ref:`installation`). It needs a terminal of at
least 80x24 characters, a taller terminal gives the log more room. It does not start if
stdin, stdout or stderr is not a terminal (e.g. when run by cron or with redirected
output): it is an interactive display and stays on the screen until you quit it.

How it works
~~~~~~~~~~~~

The cockpit runs the borg command as a subprocess with ``--log-json`` and ``--progress``
added, and builds its display from the JSON output borg produces for frontends, see
:ref:`json_output`. Apart from that, the command runs exactly like it does without
``--cockpit``, with the options you gave it.

.. note::

    ``--progress`` makes ``extract`` and ``export-tar`` read the archive metadata once
    more before they start, to determine the total amount of data for the progress bar,
    so they start a bit later than usual, see :ref:`borg_extract`.

The lower part of the screen is the log: borg's messages, warnings and errors, the file
list if you gave ``--list``, and everything else borg outputs. Control characters (a file
name can contain them, e.g. an ESC starting a terminal escape sequence) are shown as the
replacement character (U+FFFD) everywhere in the cockpit, so they can not affect the
terminal. The panel in the upper right depends on the command:

``create``, ``import-tar``, ``recreate``, ``transfer``
    The statistics of the archive being created: the number of files, the original and
    the deduplicated size, the counts of added, modified and unchanged files, the path
    being processed and the throughput in files and bytes per second, with a history
    graph. For ``create`` and ``import-tar``, the exact final statistics of the new
    archive (what ``--stats`` prints) are shown in the panel and in the log when borg
    has finished.

    These numbers are the statistics borg reports. They do not depend on ``--list`` and
    ``--filter``, which only determine what the log shows. A ``-`` means that borg does
    not report that number: ``transfer`` has no counts by status, and a ``--dry-run``
    reports the number of files and the original size when it has finished (and nothing
    else).

``extract``, ``export-tar``
    A progress bar with the percentage and the estimated remaining time, the amount of
    data extracted so far, the throughput and the counts of the ``--list`` lines.

All other commands
    The phases of the operation borg reports progress for, e.g. "Checking index" and
    "Checking archives" for ``check``, each with a progress bar. For ``prune``, also the
    numbers of kept and pruned archives.

Every panel also shows the elapsed time, the number of warnings and errors and, when
borg has finished, its exit code. The cockpit stays on the screen until you press ``q``,
so you can have a look at the log and the numbers. It then exits with the exit code of
the borg command, see :ref:`return_codes`.

Prompts and passphrases
~~~~~~~~~~~~~~~~~~~~~~~

When borg asks a yes/no question (e.g. ``check --repair`` asks whether you know what you
are doing), the cockpit shows a dialog: answer with the YES or NO button, or type another
answer into the input field.

The cockpit can not enter a passphrase. Give it to borg via the environment, e.g. by
setting ``BORG_PASSPHRASE`` or ``BORG_PASSCOMMAND`` (see :ref:`env_vars`). Otherwise the
cockpit shows a hint that borg is waiting for a passphrase, and you have to quit and try
again.

Commands the cockpit can not run
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The cockpit uses the terminal and borg's stdin is connected to the cockpit (that is how
the answers to prompts get to borg). Thus, the cockpit refuses to run:

- commands reading from stdin: ``create`` with ``-`` as a path or with
  ``--paths-from-stdin``, ``import-tar`` reading from ``-``, ``key import`` reading from
  ``-`` or with ``--paper``, and ``serve``.
- commands writing their data to stdout: ``extract --stdout`` and ``export-tar`` writing
  to ``-``.

Keys
~~~~

``q`` (or Ctrl-C)
    Quit. If borg is still running, quitting means terminating it, so the cockpit asks
    for confirmation first: ``y`` terminates borg (SIGTERM), waits until it has exited and
    quits; ``n``, Escape or Enter continue. When the cockpit gets a SIGTERM, SIGHUP or
    SIGINT signal (e.g. because its terminal window gets closed), it terminates borg,
    waits and exits without asking.

``t``
    Toggle the universal translator: the labels are shown in Borg speak. Resistance is
    futile.
