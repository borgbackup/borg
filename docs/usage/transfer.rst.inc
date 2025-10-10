.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_transfer:

borg transfer
-------------
.. code-block:: none

    borg [common options] transfer [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                             | do not change repository, just check                                                                                                                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--other-repo SRC_REPOSITORY``                   | transfer archives from the other repository                                                                                                                                                                                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--from-borg1``                                  | other repository is borg 1.x                                                                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--upgrader UPGRADER``                           | use the upgrader to convert transferred data (default: no conversion)                                                                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details.                                                                                                                                                                                                                          |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--recompress MODE``                             | recompress data chunks according to `MODE` and ``--compression``. Possible modes are `always`: recompress unconditionally; and `never`: do not recompress (faster: re-uses compressed data chunks w/o change).If no MODE is given, `always` will be used. Not passing --recompress is equivalent to "--recompress never". |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--chunker-params PARAMS``                       | rechunk using given chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the chunker defaults. default: do not rechunk                                                                                                                                           |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                                                                                                              |
    |                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN``      | only consider archives matching all patterns. see "borg help match-archives".                                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                                | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp                                                                                                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                     | consider first N archives after other filters were applied                                                                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                      | consider last N archives after other filters were applied                                                                                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                             | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.                                                                                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                             | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.                                                                                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                              | consider archives older than (now - TIMESPAN), e.g. 7d or 12m.                                                                                                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                              | consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.                                                                                                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        -n, --dry-run     do not change repository, just check
        --other-repo SRC_REPOSITORY    transfer archives from the other repository
        --from-borg1      other repository is borg 1.x
        --upgrader UPGRADER    use the upgrader to convert transferred data (default: no conversion)
        -C COMPRESSION, --compression COMPRESSION    select compression algorithm, see the output of the "borg help compression" command for details.
        --recompress MODE    recompress data chunks according to `MODE` and ``--compression``. Possible modes are `always`: recompress unconditionally; and `never`: do not recompress (faster: re-uses compressed data chunks w/o change).If no MODE is given, `always` will be used. Not passing --recompress is equivalent to "--recompress never".
        --chunker-params PARAMS    rechunk using given chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the chunker defaults. default: do not rechunk


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. see "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider first N archives after other filters were applied
        --last N                                 consider last N archives after other filters were applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g. 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.


Description
~~~~~~~~~~~

This command transfers archives from one repository to another repository.
Optionally, it can also upgrade the transferred data.
Optionally, it can also recompress the transferred data.
Optionally, it can also re-chunk the transferred data using different chunker parameters.

It is easiest (and fastest) to give ``--compression=COMPRESSION --recompress=never`` using
the same COMPRESSION mode as in the SRC_REPO - borg will use that COMPRESSION for metadata (in
any case) and keep data compressed "as is" (saves time as no data compression is needed).

If you want to globally change compression while transferring archives to the DST_REPO,
give ``--compress=WANTED_COMPRESSION --recompress=always``.

The default is to transfer all archives.

You could use the misc. archive filter options to limit which archives it will
transfer, e.g. using the ``-a`` option. This is recommended for big
repositories with multiple data sets to keep the runtime per invocation lower.

General purpose archive transfer
++++++++++++++++++++++++++++++++

Transfer borg2 archives into a related other borg2 repository::

    # create a related DST_REPO (reusing key material from SRC_REPO), so that
    # chunking and chunk id generation will work in the same way as before.
    borg --repo=DST_REPO repo-create --encryption=DST_ENC --other-repo=SRC_REPO

    # transfer archives from SRC_REPO to DST_REPO
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check what it would do
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO            # do it!
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check! anything left?


Data migration / upgrade from borg 1.x
++++++++++++++++++++++++++++++++++++++

To migrate your borg 1.x archives into a related, new borg2 repository, usage is quite similar
to the above, but you need the ``--from-borg1`` option::

    borg --repo=DST_REPO repocreate --encryption=DST_ENC --other-repo=SRC_REPO --from-borg1

    # to continue using lz4 compression as you did in SRC_REPO:
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --from-borg1 \
         --compress=lz4 --recompress=never

    # alternatively, to recompress everything to zstd,3:
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO --from-borg1 \
         --compress=zstd,3 --recompress=always

    # to re-chunk using different chunker parameters:
    borg --repo=DST_REPO transfer --other-repo=SRC_REPO \
         --chunker-params=buzhash,19,23,21,4095

