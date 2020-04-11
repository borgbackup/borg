General
-------

Borg consists of a number of commands. Each command accepts
a number of arguments and options and interprets various environment variables.
The following sections will describe each command in detail.

Commands, options, parameters, paths and such are ``set in fixed-width``.
Option values are `underlined`. Borg has few options accepting a fixed set
of values (e.g. ``--encryption`` of :ref:`borg_init`).

.. container:: experimental

   Experimental features are marked with red stripes on the sides, like this paragraph.

   Experimental features are not stable, which means that they may be changed in incompatible
   ways or even removed entirely without prior notice in following releases.

.. include:: usage_general.rst.inc

In case you are interested in more details (like formulas), please see
:ref:`internals`. For details on the available JSON output, refer to
:ref:`json_output`.

.. _common_options:

Common options
~~~~~~~~~~~~~~

All Borg commands share these options:

.. include:: common-options.rst.inc

Option ``--bypass-lock`` allows you to access the repository while bypassing
borg's locking mechanism. This is necessary if your repository is on a read-only
storage where you don't have write permissions or capabilities and therefore
cannot create a lock. Examples are repositories stored on a Bluray disc or a
read-only network storage. Avoid this option if you are able to use locks as
that is the safer way; see the warning below.

.. warning::

    If you do use ``--bypass-lock``, you are responsible to ensure that no other
    borg instances have write access to the repository. Otherwise, you might
    experience errors and read broken data if changes to that repository are
    being made at the same time.

Examples
~~~~~~~~
::

    # Create an archive and log: borg version, files list, return code
    $ borg create --show-version --list --show-rc /path/to/repo::my-files files

