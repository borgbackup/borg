.. include:: prune-stdio.rst.inc

Examples
~~~~~~~~

A session using ``prune-stdio`` might look as follows:

::

    # Lines borg outputs on stdout are prefixed with >
    # Lines input to borg on stdin are prefixed with <
    # Lines without prefix are output on stderr
    $ borg prune-stdio --json --list /tmp/tmp.ncyjKaLKtk
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
Usually `borg prune-stdio` would be run as a subprocess from a custom script.
