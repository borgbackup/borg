.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_transfer:

borg transfer
-------------
.. code-block:: none

    borg [common options] transfer [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                 | do not change repository, just check                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--other-repo SRC_REPOSITORY``       | transfer archives from the other repository                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--upgrader UPGRADER``               | use the upgrader to convert transferred data (default: no conversion)                            |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                         |
    |                                                                                                                                                                                                                        |
    | :ref:`common_options`                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply, see "borg help patterns".        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        -n, --dry-run     do not change repository, just check
        --other-repo SRC_REPOSITORY    transfer archives from the other repository
        --upgrader UPGRADER    use the upgrader to convert transferred data (default: no conversion)


    :ref:`common_options`
        |

    Archive filters
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

This command transfers archives from one repository to another repository.
Optionally, it can also upgrade the transferred data.

Suggested use for general purpose archive transfer (not repo upgrades)::

    # create a related DST_REPO (reusing key material from SRC_REPO), so that
    # chunking and chunk id generation will work in the same way as before.
    borg --repo=DST_REPO rcreate --other-repo=SRC_REPO --encryption=DST_ENC

    # transfer archives from SRC_REPO to DST_REPO
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check what it would do
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO            # do it!
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check! anything left?

The default is to transfer all archives, including checkpoint archives.

You could use the misc. archive filter options to limit which archives it will
transfer, e.g. using the -a option. This is recommended for big
repositories with multiple data sets to keep the runtime per invocation lower.

For repository upgrades (e.g. from a borg 1.2 repo to a related borg 2.0 repo), usage is
quite similar to the above::

    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --upgrader=From12To20

