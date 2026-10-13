.. include:: analyze.rst.inc

Examples
~~~~~~~~

The examples below use a repository with three archive series: ``home`` (a home
directory), ``projects`` (a subdirectory of that home directory, so it shares most
of its data with ``home``) and ``etc``. The oldest ``home`` archive was deleted
with ``borg delete``, but ``borg compact`` has not been run yet.

Which series uses how much space, and what would deleting a whole series free?

::

    $ borg analyze --group-by name

    Repository decomposition by name
    =================================================================================
    8 archive(s) in 3 group(s)

    group                           archives        source        stored  compression
    name='home'                            3      45.41 MB      43.01 MB         0.95
    name='projects'                        3     175.57 kB     127.78 kB         0.73
    name='etc'                             2     633.63 kB      46.62 kB         0.07
    (shared by 2+ groups)                          5.33 MB       2.15 MB         0.40
    (unreferenced)                                     n/a      52.23 kB          n/a
    ---------------------------------------------------------------------------------
    total (deduplicated)                   8      51.55 MB      45.33 MB         0.88

    Unreferenced: 4 of 749 chunks in the repository index.

    Each chunk is counted in exactly one row, so the rows add up to the total.
    A group row shows what is exclusive to it: no archive of another group references these
    chunks, so deleting all archives of that group would free them. Chunks used by several
    groups are counted in the shared row, not against any single group.

    source       = uncompressed source data size (each chunk counted once)
    stored       = deduplicated size as stored in the repository (compressed)
    compression  = stored / source (1.00 = not compressible)
    unreferenced = referenced by no non-deleted archive; borg compact could free
                   these. Their source size (n/a) is not known: it is only recorded
                   in the archives referencing a chunk. Chunks of soft-deleted
                   archives count as unreferenced (borg compact keeps them if the
                   repository is damaged).

Deleting all ``projects`` archives would free only 127.78 kB: almost all of their
data is also referenced by the ``home`` archives, so it is counted in the shared
row. The 52.23 kB of unreferenced chunks belong to the deleted ``home`` archive;
``borg compact`` would free them.

In a repository shared by multiple machines that may use the same archive names,
use ``--group-by name,host`` instead.

Size of one series and its hot spots::

    $ borg analyze --match-archives home

    Deduplicated size of the 3 considered archive(s)
    ===================================================================
    Considered archives: 3 (of 8 in the repository)

                                      source        stored  compression
    Deduplicated size of set:       50.74 MB      45.16 MB         0.89
    Exclusive size of set:          45.41 MB      43.01 MB         0.95
    Unreferenced chunks:                 n/a      52.23 kB          n/a

    Unreferenced: 4 of 749 chunks in the repository index.

    source       = uncompressed source data size (chunks shared within the set counted once)
    stored       = deduplicated size as stored in the repository (compressed)
    compression  = stored / source (1.00 = not compressible)
    exclusive    = chunks referenced only by this set; would be freed by deleting the set
    unreferenced = chunks referenced by no non-deleted archive; borg compact could free
                   these. Their source size (n/a) is not known: it is only recorded in
                   the archives referencing a chunk. Chunks of soft-deleted archives
                   count as unreferenced (borg compact keeps them if the repo is damaged).

    chunks added or removed by directory path
    =========================================
    home/user/Downloads: 30000000
    home/user/.cache/thumbnails: 10357664
    home/user/Documents/borg-docs: 200842
    home/user/projects/borg: 141462

The exclusive size is smaller than the deduplicated size of the set because the
``projects`` archives also reference some of the ``home`` data.

The hot spots list the summed source size (in bytes) of the chunks added or removed
between consecutive considered archives, per directory: here, a deleted 30 MB
download and a thumbnail cache that changes all the time (a candidate for
``borg create --exclude``).

As the hot spot analysis compares each considered archive with the previous one,
select a single series (as above): comparing archives of different series would
report most of their content as changed.

The usual archive filters select a subset of a series, e.g. its two most recent
archives::

    $ borg analyze --match-archives home --last 2

Use ``--json`` to process the numbers (raw byte values) further, e.g. with ``jq``::

    $ borg analyze --group-by name --json | jq -r '.by_group.groups[] | "\(.group.name): \(.stored_size)"'
    home: 43013626
    projects: 127775
    etc: 46621
