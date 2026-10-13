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
for that); "Last written" is the cache config's mtime, a best-effort last-used proxy,
not an exact timestamp and not a staleness check on its own; a mismatch between a
legacy repo's known location and its cache's last location is flagged; a key file's
presence does not by itself mean the repository is still openable. Use --json for a
machine-readable version, including the full repository id.