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

.. include:: ../usage_general.rst.inc

In case you are interested in more details (like formulas), please see
:ref:`internals`. For details on the available JSON output, refer to
:ref:`json_output`.

.. _common_options:

Common options
~~~~~~~~~~~~~~

All Borg commands share these options:

.. include:: common-options.rst.inc
