.. include:: prune.rst.inc

Examples
~~~~~~~~

Be careful, prune is a potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using ``--prefix``.
When using ``--prefix``, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run ``prune -v --list --dry-run ...``
first so you will see what it would do without it actually doing anything.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune -v --list --dry-run --keep-daily=7 --keep-weekly=4 /path/to/repo

    # Same as above but only apply to archive names starting with the hostname
    # of the machine followed by a "-" character:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --prefix='{hostname}-' /path/to/repo
    # actually free disk space:
    $ borg compact /path/to/repo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --keep-monthly=-1 /path/to/repo

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-within=10d --keep-weekly=4 --keep-monthly=-1 /path/to/repo

A session using ``--keep-stdio`` might look as follows:

::

    # Lines borg outputs on stdout are prefixed with >
    # Lines input to borg on stdin are prefixed with <
    # Lines without prefix are output on stderr
    $ borg prune --keep-stdio --list
    > {
    >     "archives": [
    >         {
    >             "archive": "archive_3",
    >             "barchive": "archive_3",
    >             "id": "e6e08836ae5e15b11b528ead254d0f46cd5172b6b3d4311a73275b5182d9a4c0",
    >             "name": "archive_3",
    >             "start": "2022-02-13T11:44:49.000000",
    >             "time": "2022-02-13T11:44:49.000000"
    >         },
    >         {
    >             "archive": "archive_2",
    >             "barchive": "archive_2",
    >             "id": "abcca3c8808b703b87ac25d3a329e275bf13a7d0d1108f83881ff4bb4c389cc9",
    >             "name": "archive_2",
    >             "start": "2022-02-13T11:44:44.000000",
    >             "time": "2022-02-13T11:44:44.000000"
    >         },
    >         {
    >             "archive": "archive_1",
    >             "barchive": "archive_1",
    >             "id": "4ed9fa060f7a37bde7408c3cc1c32f1371afaf49c478379c46ca13d3e0b86db4",
    >             "name": "archive_1",
    >             "start": "2022-02-13T11:44:37.000000",
    >             "time": "2022-02-13T11:44:37.000000"
    >         }
    >     ],
    >     "encryption": {
    >         "mode": "none"
    >     },
    >     "repository": {
    >         "id": "4a5a24f317ac4d9bdcf3ac277fba6c506fd17f1afb1cdb01ac98108dd5d6f34c",
    >         "last_modified": "2022-02-13T11:44:51.000000",
    >         "location": "/tmp/tmp.ncyjKaLKtk"
    >     }
    > }
    < [
    <   {"id": "e6e08836ae5e15b11b528ead254d0f46cd5172b6b3d4311a73275b5182d9a4c0"},
    <   {"barchive": "archive_1"}
    < ]
    Keeping archive (rule: stdio #1):        archive_3                            Sun, 2022-02-13 11:44:49 [e6e08836ae5e15b11b528ead254d0f46cd5172b6b3d4311a73275b5182d9a4c0]
    Pruning archive (1/2):                   archive_2                            Sun, 2022-02-13 11:44:44 [abcca3c8808b703b87ac25d3a329e275bf13a7d0d1108f83881ff4bb4c389cc9]
    Keeping archive (rule: stdio #2):        archive_1                            Sun, 2022-02-13 11:44:37 [4ed9fa060f7a37bde7408c3cc1c32f1371afaf49c478379c46ca13d3e0b86db4]
    Pruning archive (2/2):                   archive_1.checkpoint                 Sun, 2022-02-13 11:44:17 [92662ffd369b20c00168bf9eff821a6c00efe6e622cf1e7bce13e6f20fda5643]

It is up to the user to generate the stdin from borgs output.
Usually `borg prune --keep-stdio` would be run as a subprocess from a custom script.

There is also a visualized prune example in ``docs/misc/prune-example.txt``:

.. highlight:: none
.. include:: ../misc/prune-example.txt
    :literal:
