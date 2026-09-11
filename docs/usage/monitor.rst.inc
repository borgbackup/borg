.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_monitor:

borg monitor
------------
.. code-block:: none

    borg [common options] monitor [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                   |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--key``             | derive and print BORG_MONITORING_KEY for this repository (needs the borg key)                 |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--name SERIES``     | only report on the given archive series (e.g. the name used with borg create)                 |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--command COMMAND`` | only report on the given command, e.g. create or prune (default: all commands)                |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--host HOSTNAME``   | only report on backups made from the given host                                               |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--user USERNAME``   | only report on backups made by the given user                                                 |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--max-age SECONDS`` | freshness window in seconds; older reports count as stale (default: 90000)                    |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--keep N``          | after reading, delete all but the N newest report objects (0 = do not clean up; default: 500) |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--json``            | format output as JSON                                                                         |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                |
    |                                                                                                                                                                               |
    | :ref:`common_options`                                                                                                                                                         |
    +-------------------------------------------------------+-----------------------+-----------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --key               derive and print BORG_MONITORING_KEY for this repository (needs the borg key)
        --name SERIES       only report on the given archive series (e.g. the name used with borg create)
        --command COMMAND    only report on the given command, e.g. create or prune (default: all commands)
        --host HOSTNAME     only report on backups made from the given host
        --user USERNAME     only report on backups made by the given user
        --max-age SECONDS    freshness window in seconds; older reports count as stale (default: 90000)
        --keep N            after reading, delete all but the N newest report objects (0 = do not clean up; default: 500)
        --json              format output as JSON


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Read trusted monitoring state of a repository.

Borg client commands publish a signed-and-encrypted state report into the
repository after each run. Only borg monitor can read these reports using
the monitoring key.

Setup (once, on a host that has the borg key)::

    borg monitor --key  # this outputs the monitoring key

Then, on the monitoring host::

    BORG_MONITORING_KEY=<that key> borg monitor

This verifies and decrypts the reports and prints, for each distinct backup job
(host, user, command, archive series), the latest status and its age. It exits with
a non-zero code (warning or error) if any job is missing, stale (older than
--max-age), unsigned, or did not indicate success - so it can drive alerting like a
dead man's switch. Use --name, --command, --host and --user to restrict the output.
Reports accumulate over time; --keep=N (default 500) deletes all but the N newest
after reading.