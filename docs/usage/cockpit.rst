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
least 80x24 characters, a taller terminal gives the log more room.

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
list if you gave ``--list``, and everything else borg outputs. The panel in the upper
right depends on the command:

``create``, ``import-tar``, ``recreate``, ``transfer``
    The statistics of the archive being created: the number of files, the original and
    the deduplicated size, the counts of added, modified and unchanged files, the path
    being processed and the throughput in files and bytes per second, with a history
    graph. For ``create`` and ``import-tar``, the exact final statistics of the new
    archive (what ``--stats`` prints) are shown in the panel and in the log when borg
    has finished.

``extract``, ``export-tar``
    A progress bar with the percentage and the estimated remaining time, the amount of
    data extracted so far, the throughput and the counts of the ``--list`` lines.

All other commands
    The phases of the operation borg reports progress for, e.g. "Checking index" and
    "Checking archives" for ``check``, each with a progress bar.

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

Keys
~~~~

``q`` (or Ctrl-C)
    Quit. If borg is still running, it is asked to terminate (SIGTERM) and the cockpit
    waits until it has exited.

``t``
    Toggle the universal translator: the labels are shown in Borg speak. Resistance is
    futile.
