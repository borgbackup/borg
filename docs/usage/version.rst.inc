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

This command displays the borg client version / borg server version.

If a local repo is given, the client code directly accesses the repository,
thus we show the client version also as the server version.

If a remote repo is given (e.g. ssh:), the remote borg is queried and
its version is displayed as the server version.

Examples::

    # local repo (client uses 1.4.0 alpha version)
    $ borg version /mnt/backup
    1.4.0a / 1.4.0a

    # remote repo (client uses 1.4.0 alpha, server uses 1.2.7 release)
    $ borg version ssh://borg@borgbackup:repo
    1.4.0a / 1.2.7

Due to the version tuple format used in borg client/server negotiation, only
a simplified version is displayed (as provided by borg.version.format_version).

There is also borg --version to display a potentially more precise client version.