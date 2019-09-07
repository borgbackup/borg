.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_benchmark_crud:

borg benchmark crud
-------------------
.. code-block:: none

    borg [common options] benchmark crud [options] REPOSITORY PATH

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+----------------+----------------------------------------------+
    | **positional arguments**                                                                                              |
    +-------------------------------------------------------+----------------+----------------------------------------------+
    |                                                       | ``REPOSITORY`` | repository to use for benchmark (must exist) |
    +-------------------------------------------------------+----------------+----------------------------------------------+
    |                                                       | ``PATH``       | path were to create benchmark input data     |
    +-------------------------------------------------------+----------------+----------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                        |
    |                                                                                                                       |
    | :ref:`common_options`                                                                                                 |
    +-------------------------------------------------------+----------------+----------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY
        repository to use for benchmark (must exist)
    PATH
        path were to create benchmark input data


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command benchmarks borg CRUD (create, read, update, delete) operations.

It creates input data below the given PATH and backups this data into the given REPO.
The REPO must already exist (it could be a fresh empty repo or an existing repo, the
command will create / read / update / delete some archives named borg-benchmark-crud\* there.

Make sure you have free space there, you'll need about 1GB each (+ overhead).

If your repository is encrypted and borg needs a passphrase to unlock the key, use::

    BORG_PASSPHRASE=mysecret borg benchmark crud REPO PATH

Measurements are done with different input file sizes and counts.
The file contents are very artificial (either all zero or all random),
thus the measurement results do not necessarily reflect performance with real data.
Also, due to the kind of content used, no compression is used in these benchmarks.

C- == borg create (1st archive creation, no compression, do not use files cache)
      C-Z- == all-zero files. full dedup, this is primarily measuring reader/chunker/hasher.
      C-R- == random files. no dedup, measuring throughput through all processing stages.

R- == borg extract (extract archive, dry-run, do everything, but do not write files to disk)
      R-Z- == all zero files. Measuring heavily duplicated files.
      R-R- == random files. No duplication here, measuring throughput through all processing
      stages, except writing to disk.

U- == borg create (2nd archive creation of unchanged input files, measure files cache speed)
      The throughput value is kind of virtual here, it does not actually read the file.
      U-Z- == needs to check the 2 all-zero chunks' existence in the repo.
      U-R- == needs to check existence of a lot of different chunks in the repo.

D- == borg delete archive (delete last remaining archive, measure deletion + compaction)
      D-Z- == few chunks to delete / few segments to compact/remove.
      D-R- == many chunks to delete / many segments to compact/remove.

Please note that there might be quite some variance in these measurements.
Try multiple measurements and having a otherwise idle machine (and network, if you use it).