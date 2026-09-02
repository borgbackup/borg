.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_benchmark_cpu:

borg benchmark cpu
------------------
.. code-block:: none

    borg [common options] benchmark cpu [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                               |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--json``        | format output as JSON                                                                         |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--chunking``    | benchmark the chunkers                                                                        |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--hashing``     | benchmark the hashes / MACs                                                                   |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--encrypting``  | benchmark the encryption modes                                                                |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--compressing`` | benchmark the compressors                                                                     |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--data PATH``   | benchmark the compressors with the data from this file or directory (default: synthetic data) |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    |                                                       | ``--msgpacking``  | benchmark msgpack item packing                                                                |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                            |
    |                                                                                                                                                                           |
    | :ref:`common_options`                                                                                                                                                     |
    +-------------------------------------------------------+-------------------+-----------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --json           format output as JSON
        --chunking       benchmark the chunkers
        --hashing        benchmark the hashes / MACs
        --encrypting     benchmark the encryption modes
        --compressing    benchmark the compressors
        --data PATH      benchmark the compressors with the data from this file or directory (default: synthetic data)
        --msgpacking     benchmark msgpack item packing


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command benchmarks miscellaneous CPU-bound Borg operations.

It creates input data in memory, runs the operation and then displays throughput.
To reduce outside influence on the timings, please make sure to run this with:

- an otherwise as idle as possible machine
- enough free memory so there will be no slow down due to paging activity

By default all benchmarks run. Give one or more of --chunking, --hashing,
--encrypting, --compressing, --msgpacking to run only those.

Some algorithms use multiple threads only above a size threshold, so the
hashes and the compressors are measured at more than one buffer size: the
hashes at 64MiB (roughly pack-sized) and 2MiB (a typical borg chunk), both above
blake3's threshold, the compressors at 2MiB and 128kiB, which is below
zstd's. Within a section every row processes the same total number of
bytes - 1 GiB, or 10 MiB for the compressors (the complete given data
when using --data) - so the throughput column is comparable between rows.

By default, the compressors work on synthetic text-like data that compresses
about 4x at zstd,3. Random data would be the worst possible input: no codec
can compress it, so all of them would take their incompressible fast path
and the levels would barely differ.

Synthetic data can still behave differently from your real data, so the
compression benchmarks can instead run on data you provide with
``--data PATH``: PATH is a file or a directory (all files below it are
read and concatenated, up to 1 GiB). The complete data is compressed:
it is cut into consecutive buffers of the measured sizes (a partial
buffer at the end is skipped), so ratios and throughput reflect all of
it, and the runtime scales with its size. Public benchmark corpora,
e.g. the Silesia corpus or the Canterbury corpus, make good
reproducible inputs that resemble real-world data (download and unpack
them first, then point ``--data`` at the result).

The compression rows also show the achieved compression ratio
(uncompressed size / compressed size, higher is better).