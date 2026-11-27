.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_known-repos:

borg known-repos
----------------
.. code-block:: none

    borg [common options] known-repos [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------+-----------------------+
    | **options**                                                                                |
    +-------------------------------------------------------+------------+-----------------------+
    |                                                       | ``--json`` | format output as JSON |
    +-------------------------------------------------------+------------+-----------------------+
    | .. class:: borg-common-opt-ref                                                             |
    |                                                                                            |
    | :ref:`common_options`                                                                      |
    +-------------------------------------------------------+------------+-----------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --json     format output as JSON


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Lists the repositories this local Borg installation currently has state for -
security info (key type, last known location), a local repository cache, and/or key
files - without accessing any repository itself (-r/--repo has no effect). "Layout"
is which state was found in (not the on-disk repository format, see "borg repo-info"
for that) - a security-only repo gets "unknown" when $BORG_SECURITY_DIR makes the
borg2 and legacy security roots coincide.

"Last written" is a best-effort last-used proxy, not an exact timestamp and not a
staleness check on its own. It is the newest mtime found among the repository's
security info file (which records the repository's last known location) and, if a
local cache exists, any regular file in that cache - whichever of the two is more
recent.
A mismatch between a legacy repo's known location and its cache's last location is
flagged. A key file's presence does not by itself mean the repository is still
openable. Use --json for a machine-readable version.