.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_version:

borg version
------------
.. code-block:: none

    borg [common options] version [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------------+------------------------+
    | **options**                                                                                       |
    +-------------------------------------------------------+------------------+------------------------+
    |                                                       | ``--json``       | format output as JSON  |
    +-------------------------------------------------------+------------------+------------------------+
    |                                                       | ``--from-borg1`` | repository is Borg 1.x |
    +-------------------------------------------------------+------------------+------------------------+
    | .. class:: borg-common-opt-ref                                                                    |
    |                                                                                                   |
    | :ref:`common_options`                                                                             |
    +-------------------------------------------------------+------------------+------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --json     format output as JSON
        --from-borg1    repository is Borg 1.x


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command displays the Borg client and server versions.

For current repositories the client code directly accesses the repository (also for
rest:// repositories), so the client version is shown as the server version, too.

If a legacy (borg 1.x / v1) repository is given via ssh: together with --from-borg1,
the remote Borg is queried, and its version is displayed as the server version.

Examples::

    # local repository
    $ borg -r /mnt/backup version
    2.0.0 / 2.0.0

    # legacy remote repository (client uses 2.0.0, server uses 1.4.5 release)
    $ borg -r ssh://borg@borgbackup/repo version --from-borg1
    2.0.0 / 1.4.5

Due to the version tuple format used in Borg client/server negotiation, only
a simplified version is displayed (as provided by borg.version.format_version).

You can also use ``borg --version`` to display a potentially more precise client version.