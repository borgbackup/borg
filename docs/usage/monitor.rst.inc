.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_monitor:

borg monitor
------------
.. code-block:: none

    borg [common options] monitor [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                            |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--key``             | derive and print BORG_MONITORING_KEY for this repository (needs the borg key)                                          |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--name SERIES``     | only report on the given archive series (e.g. the name used with borg create)                                          |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--command COMMAND`` | only report on the given command, e.g. create or prune (default: all commands)                                         |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--max-age SECONDS`` | freshness window in seconds; older reports count as stale (default: 90000)                                             |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--keep N``          | after reading, delete all but the N newest report objects (needs delete permission; 0 = do not clean up; default: 500) |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json``            | format output as JSON                                                                                                  |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                         |
    |                                                                                                                                                                                                        |
    | :ref:`common_options`                                                                                                                                                                                  |
    +-------------------------------------------------------+-----------------------+------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --key             derive and print BORG_MONITORING_KEY for this repository (needs the borg key)
        --name SERIES     only report on the given archive series (e.g. the name used with borg create)
        --command COMMAND    only report on the given command, e.g. create or prune (default: all commands)
        --max-age SECONDS    freshness window in seconds; older reports count as stale (default: 90000)
        --keep N          after reading, delete all but the N newest report objects (needs delete permission; 0 = do not clean up; default: 500)
        --json            format output as JSON


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Read or export trusted monitoring state of a repository.

Backup-side commands publish a small signed-and-encrypted state report into the
repository after each run. Because each report is signed with a key derived from
the borg key, the (untrusted) repository server can neither forge nor read it - it
can only relay it. A monitoring system can therefore pull and verify the reports
from the same server without the repository passphrase.

Setup (once, on a host that has the borg key)::

    BORG_MONITORING_KEY=$(borg monitor --key)

Then, on the monitoring host, with that value exported as BORG_MONITORING_KEY::

    borg monitor

This verifies and decrypts the reports and prints, per archive series (and per
maintenance command), the latest status and its age. It exits with a non-zero code
(warning or error) if any series is missing, stale (older than --max-age), unsigned,
or did not indicate success - so it can drive alerting like a dead man's switch.
Reports accumulate over time; --keep=N (default 500) deletes all but the N newest
after reading.