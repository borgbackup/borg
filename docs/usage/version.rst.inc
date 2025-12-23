.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_version:

borg version
------------
.. code-block:: none

    borg [common options] version [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+
    | .. class:: borg-common-opt-ref                        |
    |                                                       |
    | :ref:`common_options`                                 |
    +-------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command displays the Borg client and server versions.

If a local repository is given, the client code directly accesses the repository,
so the client version is also shown as the server version.

If a remote repository is given (e.g., ssh:), the remote Borg is queried, and
its version is displayed as the server version.

Examples::

    # local repository (client uses 1.4.0 alpha version)
    $ borg version /mnt/backup
    1.4.0a / 1.4.0a

    # remote repository (client uses 1.4.0 alpha, server uses 1.2.7 release)
    $ borg version ssh://borg@borgbackup:repo
    1.4.0a / 1.2.7

Due to the version tuple format used in Borg client/server negotiation, only
a simplified version is displayed (as provided by borg.version.format_version).

You can also use ``borg --version`` to display a potentially more precise client version.