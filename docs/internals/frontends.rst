.. include:: ../global.rst.inc
.. highlight:: none

.. _json_output:

All about JSON: How to develop frontends
========================================

Borg does not have a public API on the Python level. That does not keep you from writing :code:`import borg`,
but does mean that there are no release-to-release guarantees on what you might find in that package, not
even for point releases (2.0.x), and there is no documentation beyond the code and the internals documents.

Borg does on the other hand provide an API on a command-line level. In other words, a frontend should
(for example) create a backup archive by invoking :ref:`borg_create`, provide command-line parameters/options
as needed, and parse JSON output from Borg.

Important: JSON output is expected to be UTF-8, but currently borg depends on the locale being configured
for that (must be a UTF-8 locale and *not* "C" or "ascii"), so that Python will choose to encode to UTF-8.
The same applies to any inputs read by borg, they are expected to be UTF-8 encoded also.

On POSIX systems, you can usually set environment vars to choose a UTF-8 locale:

::

    export LANG=en_US.UTF-8
    export LC_CTYPE=en_US.UTF-8


Another way to get Python's stdin/stdout/stderr streams to use UTF-8 encoding (without having
a UTF-8 locale / LANG / LC_CTYPE) is:

::

    export PYTHONIOENCODING=utf-8


See :issue:`2273` for more details.


Dealing with non-unicode byte sequences and JSON limitations
------------------------------------------------------------

Paths on POSIX systems can have arbitrary bytes in them (except 0x00 which is used as string terminator in C).

Nowadays, UTF-8 encoded paths (which decode to valid unicode) are the usual thing, but a lot of systems
still have paths from the past, when other, non-unicode codings were used. Especially old Samba shares often
have wild mixtures of misc. encodings, sometimes even very broken stuff.

borg deals with such non-unicode paths ("with funny/broken characters") by decoding such byte sequences using
UTF-8 coding and "surrogateescape" error handling mode, which maps invalid bytes to special unicode code points
(surrogate escapes). When encoding such a unicode string back to a byte sequence, the original byte sequence
will be reproduced exactly.

JSON should only contain valid unicode text without any surrogate escapes, so we can't just directly have a
surrogate-escaped path in JSON ("path" is only one example, this also affects other text-like content).

Borg deals with this situation like this (since borg 2.0):

For a valid unicode path (no surrogate escapes), the JSON will only have "path": path.

For a non-unicode path (with surrogate escapes), the JSON will have 2 entries:

- "path": path_approximation (pure valid unicode, all invalid bytes will show up as "?")
- "path_b64": path_bytes_base64_encoded (if you decode the base64, you get the original path byte string)

JSON users need to pick whatever suits their needs best. The suggested procedure (shown for "path") is:

- check if there is a "path_b64" key.
- if it is there, you will know that the original bytes path did not cleanly UTF-8-decode into unicode (has
  some invalid bytes) and that the string given by the "path" key is only an approximation, but not the precise
  path. if you need precision, you must base64-decode the value of "path_b64" and deal with the arbitrary byte
  string you'll get. if an approximation is fine, use the value of the "path" key.
- if it is not there, the value of the "path" key is all you need (the original bytes path is its UTF-8 encoding).


Logging
-------

Especially for graphical frontends it is important to be able to convey and reformat progress information
in meaningful ways. The ``--log-json`` option turns the stderr stream of Borg into a stream of JSON lines,
where each line is a JSON object. The *type* key of the object determines its other contents.

.. warning:: JSON logging requires successful argument parsing. Even with ``--log-json`` specified, a
    parsing error will be printed in plain text, because logging set-up happens after all arguments are
    parsed.

The following types are in use. Progress information is governed by the usual rules for progress information,
it is not produced unless ``--progress`` is specified.

archive_progress
    Output during operations creating archives (:ref:`borg_create`, :ref:`borg_import-tar`,
    :ref:`borg_recreate` and :ref:`borg_transfer`).
    The following keys exist, each represents the current progress.

    original_size
        Original size of the data processed so far (before compression and deduplication)
    nfiles
        Number of (regular) files processed so far
    hashing_time
        Seconds spent hashing file contents so far (float)
    chunking_time
        Seconds spent chunking file contents so far (float)
    files_stats
        Object mapping the single-character file status (as used by ``--list``) to the number of
        files that got that status so far, e.g. ``{"A": 3, "d": 3}``
    store_stats
        Object with the storage backend statistics. It is empty here, it is only filled in for the
        final :ref:`borg_create` ``--json`` output on *stdout*, see `Archive formats`_.
    path
        Current path (absent if there is no current item)
    time
        Unix timestamp (float)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*. That last object has no keys besides *time*, *type*
        and *finished*.

progress_message
    A message-based progress information with no concrete progress information, just a message
    saying what is currently being worked on.

    operation
        unique, opaque integer ID of the operation
    :ref:`msgid <msgid>`
        Message ID of the operation (may be *null*)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*.
    message
        current progress message (empty string for finished == true)
    time
        Unix timestamp (float)

progress_percent
    Absolute progress information with defined end/total and current value.

    operation
        unique, opaque integer ID of the operation
    :ref:`msgid <msgid>`
        Message ID of the operation (may be *null*)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*.
    message
        A formatted progress message, this will include the percentage and perhaps other information
        (empty string for finished == true)
    current
        Current value (usually less-or-equal to *total*, absent for finished == true)
    info
        Array that describes the current item, may be *null*, contents depend on *msgid*
        (absent for finished == true)
    total
        Total value (absent for finished == true)
    time
        Unix timestamp (float)

file_status
    This is only output by :ref:`borg_create`, :ref:`borg_import-tar` and :ref:`borg_recreate` if
    ``--list`` is specified. The usual rules for the file listing applies, including the
    ``--filter`` option.

    status
        Single-character status as for regular list output
    path
        Path of the file system object

log_message
    Any regular log output invokes this type. Regular log options and filtering applies to these as well.

    time
        Unix timestamp (float)
    levelname
        Upper-case log level name (also called severity). Defined levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    name
        Name of the emitting entity
    message
        Formatted log message
    :ref:`msgid <msgid>`
        Message ID, may be *null* or absent

See Prompts_ for the types used by prompts.

.. rubric:: Examples (reformatted, each object would be on exactly one line)
.. highlight:: json

:ref:`borg_extract` progress::

    {"message": " 20.0% Extracting: src/linux/baz/file3", "current": 50012, "total": 250012,
     "info": ["src/linux/baz/file3"], "operation": 1, "msgid": "extract",
     "type": "progress_percent", "finished": false, "time": 1787900399.5558112}
    {"message": " 20.0% Extracting: src/linux/file1", "current": 250012, "total": 250012,
     "info": ["src/linux/file1"], "operation": 1, "msgid": "extract",
     "type": "progress_percent", "finished": false, "time": 1787900399.5561972}
    {"message": "", "operation": 1, "msgid": "extract", "type": "progress_percent",
     "finished": true, "time": 1787900399.556339}

:ref:`borg_create` file listing with progress::

    {"original_size": 0, "nfiles": 0, "hashing_time": 0.0, "chunking_time": 0.0, "files_stats": {},
     "store_stats": {}, "path": "src", "time": 1787900398.684961, "type": "archive_progress", "finished": false}
    {"type": "file_status", "status": "A", "path": "src/linux/baz/file2"}
    {"type": "file_status", "status": "A", "path": "src/linux/baz/file3"}
    {"type": "file_status", "status": "d", "path": "src/linux/baz"}
    {"type": "file_status", "status": "A", "path": "src/linux/file1"}
    {"type": "file_status", "status": "d", "path": "src/linux"}
    {"type": "file_status", "status": "d", "path": "src"}
    {"time": 1787900398.686938, "type": "archive_progress", "finished": true}

Saving the local cache at the end of :ref:`borg_create`::

    {"message": "Saving files cache", "operation": 1, "msgid": "cache.close", "type": "progress_message", "finished": false, "time": 1787900398.719723}
    {"message": "Saving index", "operation": 1, "msgid": "cache.close", "type": "progress_message", "finished": false, "time": 1787900398.728792}
    {"message": "Saving cache config", "operation": 1, "msgid": "cache.close", "type": "progress_message", "finished": false, "time": 1787900398.7294679}
    {"message": "", "operation": 1, "msgid": "cache.close", "type": "progress_message", "finished": true, "time": 1787900398.739775}

A debug log message::

    {"type": "log_message", "time": 1787900399.0667, "message": "19 self-tests completed in 0.02 seconds",
     "levelname": "DEBUG", "name": "borg.archiver"}

An error log message, carrying a msgid_::

    {"type": "log_message", "time": 1787900383.5105972,
     "message": "Repository proto='file', ... does not exist.",
     "levelname": "ERROR", "name": "borg.archiver", "msgid": "Repository.DoesNotExist"}

Prompts
-------

Borg asks a few yes/no questions interactively; the "Prompts" list at the end of `Message IDs`_
enumerates them. Answers are read verbatim from *stdin*. The questions and the messages about
their processing are written to *stderr*: as plain text by default, or as JSON objects (one per
line, like log messages) when ``--log-json`` is given.

Prompts use the *question_prompt* and *question_prompt_retry* types for the prompt itself,
and *question_invalid_answer*, *question_accepted_default*, *question_accepted_true*,
*question_accepted_false* and *question_env_answer* types for information about
prompt processing.

The *message* property contains the same string displayed regularly in the same situation,
while the *msgid* property contains a msgid_, the name of the environment variable that can
be used to override the prompt. It is the same for all JSON messages pertaining to the same
prompt. *question_env_answer* messages additionally have an *env_var* property with the name
of the environment variable the answer was taken from.

A frontend should not try to answer these prompts interactively. Every prompt has an
environment variable that overrides it (the variable name is the prompt's msgid_): if it is set,
its value is used as if it had been typed in, and borg never waits for input. For example, with
``BORG_CHECK_I_KNOW_WHAT_I_AM_DOING=NO`` in the environment, ``borg check --repair`` prints the
question, answers it with *NO* and fails with the *CancelledByUser* msgid_ (rc 3).

.. rubric:: Examples (reformatted, each object would be on exactly one line)
.. highlight:: none

Providing an invalid answer::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "This is a potentially dangerous function.\n... Type 'YES' if you understand this and want to continue: "}
    incorrect answer  # input on stdin
    {"type": "question_invalid_answer", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "Invalid answer, aborting."}

Providing a false (negative) answer via the environment variable::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "This is a potentially dangerous function.\n... Type 'YES' if you understand this and want to continue: "}
    {"env_var": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "type": "question_env_answer",
     "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "NO (from BORG_CHECK_I_KNOW_WHAT_I_AM_DOING)"}
    {"type": "question_accepted_false", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "Aborting."}

Providing a true (affirmative) answer::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "This is a potentially dangerous function.\n... Type 'YES' if you understand this and want to continue: "}
    YES  # input on stdin
    # no further output, just like the prompt without --log-json

Passphrase prompts
------------------

Passphrase prompts should be handled differently. Use the environment variables *BORG_PASSPHRASE*
and *BORG_NEW_PASSPHRASE* (see :ref:`env_vars` for reference) to pass passphrases to Borg, don't
use the interactive passphrase prompts.

When setting a new passphrase (:ref:`borg_repo-create`, :ref:`borg_key_change-passphrase`) normally
Borg prompts whether it should display the passphrase. This can be suppressed by setting
the environment variable *BORG_DISPLAY_PASSPHRASE* to *no*.

When "confronted" with an unknown repository, where the application does not know whether
the repository is encrypted, the following algorithm can be followed to detect encryption:

1. Set *BORG_PASSPHRASE* to gibberish (for example a freshly generated UUID4, which cannot
   possibly be the passphrase)
2. Invoke ``borg repo-list -r repository ...``
3. If this fails, due the repository being encrypted and the passphrase obviously being
   wrong, you'll get an error with the *PassphraseWrong* msgid.

   The repository is encrypted, for further access the application will need the passphrase.

4. If this does not fail, then the repository is not encrypted.

Standard output
---------------

*stdout* is different and more command-dependent than logging. Commands like :ref:`borg_repo-info`,
:ref:`borg_repo-list`, :ref:`borg_info`, :ref:`borg_create` and :ref:`borg_analyze` implement a
``--json`` option which turns their regular output into a single JSON object.

Some commands, like :ref:`borg_list` and :ref:`borg_diff`, can produce *a lot* of JSON. Since many JSON implementations
don't support a streaming mode of operation, which is pretty much required to deal with this amount of JSON, these
commands implement a ``--json-lines`` option which generates output in the `JSON lines <https://jsonlines.org/>`_ format,
which is simply a number of JSON objects separated by new lines.

Dates are formatted according to ISO 8601 in the local time zone of the borg client, including the
UTC offset, e.g. ``2026-08-28T08:59:56.761172+02:00``. Repository and archive timestamps and the
item timestamps of :ref:`borg_list` have microsecond precision (6 fraction digits). The item
timestamps of :ref:`borg_diff` have nanosecond precision (9 fraction digits), because that is how
borg stores them.

The root object of '--json' output will contain at least a *repository* key with an object containing:

id
    The ID of the repository, normally 64 hex characters
location
    Canonicalized repository path, thus this may be different from what is specified on the command line
last_modified
    Date when the repository was last modified by the Borg client

The *encryption* key, if present, contains:

encryption
    Textual cipher / AE algorithm name (same as :ref:`borg_repo-create` ``--encryption`` names)
id_hash
    Textual id hash function name (same as :ref:`borg_repo-create` ``--id-hash`` names)
keyfile
    Path to the local key file used for access. Depending on the key location this may be absent.

The *cache* key, if present, contains:

path
    Path to the local repository cache

:ref:`borg_repo-info` additionally emits a *security_dir* key with the path of the local security
directory of the repository.

.. highlight: json

Example ``borg repo-info --json`` output::

    {
        "cache": {
            "path": "/home/user/.cache/borg/65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94"
        },
        "encryption": {
            "encryption": "aes256-ocb",
            "id_hash": "sha256"
        },
        "repository": {
            "id": "65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94",
            "last_modified": "2026-08-28T08:59:55.908686+02:00",
            "location": "/home/user/repository"
        },
        "security_dir": "/home/user/.local/share/borg/security/65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94"
    }

Archive formats
+++++++++++++++

:ref:`borg_info` uses an extended format for archives, which is more expensive to retrieve, while
:ref:`borg_repo-list` uses a simpler format that is faster to retrieve. Either return archives in an
array under the *archives* key, while :ref:`borg_create` and :ref:`borg_import-tar` return a single
archive object under the *archive* key.

:ref:`borg_create` with ``--dry-run`` does not create an archive, so there is no *archive* key.
Instead, it returns *dry_run* (true) and a reduced *stats* object with *nfiles* and *original_size*,
both computed from file system metadata without reading the file contents.

Both formats always contain a *name* key with the archive name, the *id* key with the hexadecimal
archive ID and the *time* key with the nominal archive timestamp. The *borg repo-list* format
additionally always has an *archive* key, an alias of *name*.

*borg info*, *borg create* and *borg import-tar* further have:

start
    Start timestamp of the archive creation
end
    End timestamp of the archive creation
duration
    Duration in seconds between start and end (float)
command_line
    The command line that created the archive, as one shell-quoted string.

    The note about paths from above applies here as well.
stats
    Archive statistics:

    original_size
        Size of the file contents and the metadata in this archive, before compression and
        deduplication
    nfiles
        Number of regular files in the archive
    hashing_time
        Seconds spent hashing file contents (float)
    chunking_time
        Seconds spent chunking file contents (float)
    files_stats
        Object mapping the single-character file status to the number of files with that status
    store_stats
        Object with the statistics of the storage backend (call counts, transferred volumes,
        times, cache hits/misses, ...)

    *borg create* fills all of these in for the archive it has just created. *borg info* only reads
    *original_size* and *nfiles* from the archive metadata; *hashing_time*, *chunking_time*,
    *files_stats* and *store_stats* are 0 or empty there.

    Compressed and deduplicated sizes are not given: computing them per archive is expensive.
    Use :ref:`borg_analyze` for the deduplicated size of a set of archives and
    ``borg compact --stats`` for the repository-wide numbers.

:ref:`borg_info` further has:

hostname
    Hostname of the creating host
username
    Name of the creating user
cwd
    Working directory the archive was created in
comment
    Archive comment, if any
tags
    Array of the archive's tags
chunker_params
    The chunker parameters the archive has been created with.

Some keys/values are more expensive to compute than others (e.g. because it requires opening the
archive, not just the archives directory). To optimize for speed, `borg repo-list` does not determine
these values except when they are requested. The `--format` option is used for that (for normal mode
as well as for `--json` mode), so, to have the comment included in the json output, you will need:

.. code-block:: none

    borg repo-list --format "{name}{comment}" --json

Note that the default `--format` of `borg repo-list` already requests *tags*, *username*, *hostname*
and *comment*, so these show up unless you give a `--format` without them.


Example of a simple archive listing (``borg repo-list --format "{name}{comment}" --json``)::

    {
        "archives": [
            {
                "archive": "src-2026-08-28",
                "comment": "",
                "id": "b0f88c1245506d1f8ba283908c2d7d42d50bb7c7e4120134eafe16c5f0cde192",
                "name": "src-2026-08-28",
                "time": "2026-08-28T08:59:56.761172+02:00"
            }
        ],
        "encryption": {
            "encryption": "aes256-ocb",
            "id_hash": "sha256"
        },
        "repository": {
            "id": "65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94",
            "last_modified": "2026-08-28T08:59:56.764587+02:00",
            "location": "/home/user/repository"
        }
    }

The same archive with more information (``borg info --last 1 --json``)::

    {
        "archives": [
            {
                "chunker_params": [
                    "fastcdc",
                    19,
                    23,
                    21,
                    2
                ],
                "command_line": "/home/user/.local/bin/borg create --json src-2026-08-28 src",
                "comment": "",
                "cwd": "/home/user",
                "duration": 0.002238,
                "end": "2026-08-28T08:59:56.763410+02:00",
                "hostname": "host",
                "id": "b0f88c1245506d1f8ba283908c2d7d42d50bb7c7e4120134eafe16c5f0cde192",
                "name": "src-2026-08-28",
                "start": "2026-08-28T08:59:56.761172+02:00",
                "stats": {
                    "chunking_time": 0.0,
                    "files_stats": {},
                    "hashing_time": 0.0,
                    "nfiles": 3,
                    "original_size": 250047,
                    "store_stats": {}
                },
                "tags": [],
                "time": "2026-08-28T08:59:56.761172+02:00",
                "username": "user"
            }
        ],
        "cache": {
            "path": "/home/user/.cache/borg/65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94"
        },
        "encryption": {
            "encryption": "aes256-ocb",
            "id_hash": "sha256"
        },
        "repository": {
            "id": "65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94",
            "last_modified": "2026-08-28T08:59:56.764587+02:00",
            "location": "/home/user/repository"
        }
    }

The archive :ref:`borg_create` has just created (``borg create --json``), with the statistics it
collected while running::

    {
        "archive": {
            "command_line": "/home/user/.local/bin/borg create --json src-2026-08-28 src",
            "duration": 0.002238,
            "end": "2026-08-28T08:59:56.763410+02:00",
            "id": "b0f88c1245506d1f8ba283908c2d7d42d50bb7c7e4120134eafe16c5f0cde192",
            "name": "src-2026-08-28",
            "start": "2026-08-28T08:59:56.761172+02:00",
            "stats": {
                "chunking_time": 7.81649723649025e-05,
                "files_stats": {
                    "A": 3,
                    "d": 3
                },
                "hashing_time": 0.00010525097604840994,
                "nfiles": 3,
                "original_size": 250510,
                "store_stats": {
                    "backend_load_calls": 8,
                    "backend_load_volume": 2298,
                    "backend_store_calls": 6,
                    "backend_store_volume": 253555,
                    "load_calls": 8,
                    "load_throughput": 8997087.104958186,
                    "load_time": 0.000255416,
                    "load_volume": 2298,
                    "store_calls": 6,
                    "store_throughput": 120882023.28345428,
                    "store_time": 0.002097541,
                    "store_volume": 253555
                }
            },
            "time": "2026-08-28T08:59:56.761172+02:00"
        },
        "cache": {
            "path": "/home/user/.cache/borg/65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94"
        },
        "encryption": {
            "encryption": "aes256-ocb",
            "id_hash": "sha256"
        },
        "repository": {
            "id": "65d7898e2142485f44506fb11c0fcd6d7dfd0341716385246068584a62632a94",
            "last_modified": "2026-08-28T08:59:56.764587+02:00",
            "location": "/home/user/repository"
        }
    }

The *store_stats* object above is shortened; borg reports more keys there, e.g. the counters and
times of the other storage operations and of the pack cache.

File listings
+++++++++++++

Each archive item (file, directory, ...) is described by one object in the :ref:`borg_list` output.
Refer to the *borg list* documentation for the available keys and their meaning.

The keys *path*, *target*, *hlid*, *type*, *mode*, *uid*, *gid*, *user*, *group*, *flags* and
*inode* are always present; *flags* and *inode* are *null* if the source file system did not
provide them. The keys used in ``--format`` are added to that; the default format contributes
*size* and *mtime*.

Example (excerpt) of ``borg list --json-lines``::

    {"flags": 0, "gid": 0, "group": "wheel", "hlid": "", "inode": 714338381, "mode": "drwxr-xr-x", "mtime": "2026-08-28T08:59:55.543471+02:00", "path": "src/linux/baz", "size": 0, "target": "", "type": "d", "uid": 501, "user": "user"}
    {"flags": 0, "gid": 0, "group": "wheel", "hlid": "", "inode": 714338384, "mode": "-rw-r--r--", "mtime": "2026-08-28T08:59:55.543551+02:00", "path": "src/linux/baz/file3", "size": 12, "target": "", "type": "-", "uid": 501, "user": "user"}


Archive Differencing
++++++++++++++++++++

Each archive difference item (file contents, user/group/mode) output by :ref:`borg_diff` is represented by an *ItemDiff* object.
The properties of an *ItemDiff* object are:

path:
    The filename/path of the *Item* (file, directory, symlink).

changes:
    A list of *Change* objects describing the changes made to the item in the two archives. For example,
    there will be two changes if the contents of a file are changed, and its ownership are changed.

The *Change* object can contain a number of properties depending on the type of change that occurred.
If a 'property' is not required for the type of change, it is not output.
The possible properties of a *Change* object are:

type:
  The **type** property is always present. It identifies the type of change and will be one of these values:

  - *modified* - the file contents changed.
  - *added* - the file was added.
  - *removed* - the file was removed.
  - *added directory* / *removed directory* - the directory was added / removed.
  - *added link* / *removed link* - the symlink was added / removed.
  - *changed link* - the symlink target was changed.
  - *added blkdev* / *removed blkdev* - the block device was added / removed.
  - *added chrdev* / *removed chrdev* - the character device was added / removed.
  - *added fifo* / *removed fifo* - the fifo was added / removed.
  - *changed mode* - the mode (file type and permission bits) was changed.
  - *changed type* - the file type was changed, e.g. a file was replaced by a directory of the
    same name. This always comes together with a *changed mode* change.
  - *changed owner* - user and/or group ownership changed.
  - *changed user* - user ownership changed. Only emitted together with *changed owner*.
  - *changed group* - group ownership changed. Only emitted together with *changed owner*.
  - *ctime* - the ctime of the item changed.
  - *mtime* - the mtime of the item changed.

added:
    If **type** is '*modified*', '*added*' or '*removed*', **added** and **removed** give the
    amount of data (in bytes) added and removed. For '*added*', **removed** is 0; for '*removed*',
    **added** is 0. If the chunk ids can not be compared (the archives were created with different
    ``--chunker-params``), a '*modified*' change has neither property and the only information
    available is that the file contents were modified.

removed:
    See **added** property.

item1:
    The value in ARCHIVE1. It is present for '*changed mode*', '*changed type*',
    '*changed owner*', '*changed user*', '*changed group*', '*ctime*' and '*mtime*':

    - for '*changed mode*' the mode string as ``ls -l`` prints it,
    - for '*changed type*' the first character of that mode string,
    - for '*changed owner*' a two-element array of user and group,
    - for '*changed user*' / '*changed group*' the user / the group,
    - for '*ctime*' / '*mtime*' an ISO 8601 timestamp.

    User and group are given by name; with ``--numeric-ids``, the numeric uid and gid are given
    instead (as JSON numbers instead of strings).

item2:
    The corresponding value in ARCHIVE2, see **item1**.

``--content-only`` suppresses the metadata changes, i.e. the *changed mode*, *changed type*,
*changed owner*, *changed user*, *changed group*, *ctime* and *mtime* changes. Items that have
only such changes are then not printed at all.


Example of ``borg diff --json-lines --sort-by path ARCHIVE1 ARCHIVE2``::

    {"changes": [{"item1": "2026-08-28T09:00:12.822775921+02:00", "item2": "2026-08-28T09:00:14.334539472+02:00", "type": "ctime"}, {"item1": "2026-08-28T09:00:12.822775921+02:00", "item2": "2026-08-28T09:00:14.334539472+02:00", "type": "mtime"}], "path": "data"}
    {"changes": [{"type": "removed directory"}], "path": "data/dir1"}
    {"changes": [{"type": "added directory"}], "path": "data/dir2"}
    {"changes": [{"type": "removed fifo"}], "path": "data/fifo1"}
    {"changes": [{"item1": ["user", "staff"], "item2": ["user", "admin"], "type": "changed owner"}, {"item1": "staff", "item2": "admin", "type": "changed group"}, {"item1": "-rwxr-xr-x", "item2": "-rw-r--r--", "type": "changed mode"}, {"item1": "2026-08-28T09:00:12.829163282+02:00", "item2": "2026-08-28T09:00:14.321948295+02:00", "type": "ctime"}], "path": "data/file1"}
    {"changes": [{"added": 0, "removed": 4, "type": "removed"}], "path": "data/file2"}
    {"changes": [{"added": 8, "removed": 0, "type": "added"}], "path": "data/file3"}
    {"changes": [{"added": 8, "removed": 4, "type": "modified"}, {"item1": "2026-08-28T09:00:12.816498270+02:00", "item2": "2026-08-28T09:00:14.334788977+02:00", "type": "ctime"}, {"item1": "2026-08-28T09:00:12.816498270+02:00", "item2": "2026-08-28T09:00:14.334788977+02:00", "type": "mtime"}], "path": "data/file5"}
    {"changes": [{"type": "changed link"}, {"item1": "2026-08-28T09:00:12.820243127+02:00", "item2": "2026-08-28T09:00:14.332850526+02:00", "type": "ctime"}, {"item1": "2026-08-28T09:00:12.820210210+02:00", "item2": "2026-08-28T09:00:14.332821942+02:00", "type": "mtime"}], "path": "data/link1"}


Archive Analysis
++++++++++++++++

:ref:`borg_analyze` ``--json`` emits the numbers of its text report as one object. All sizes are
byte values; the compression factor the text report shows is ``stored_size / source_size``.

Without ``--group-by``, the *dedup_size* and *hotspots* keys are present.

*dedup_size* describes the considered set of archives:

considered_archives
    Number of archives matching the archive filters
total_archives
    Number of non-deleted archives in the repository
whole_repository
    True if no archive was left over by the filters, so the considered set is the whole
    repository. Every referenced chunk is then trivially exclusive to the set, and the
    *exclusive* key is absent.
deduplicated
    Object with *source_size* and *stored_size*: the summed size of the union of chunks the
    considered archives reference, chunks shared within the set counted once
exclusive
    Object with *source_size* and *stored_size*: the chunks referenced only by the considered
    set, i.e. what deleting the whole set would free. Absent if *whole_repository* is true.
unreferenced
    Object with *stored_size* and *chunks*: the chunks no non-deleted archive references, which
    ``borg compact`` could free. Their source size is not known, as it is only recorded in the
    archives referencing a chunk.
total_chunks
    Number of chunks in the repository chunk index
missing_chunks
    Number of chunks referenced by an archive but absent from the repository chunk index

*hotspots* is a list of objects with *path* (directory path) and *size* (bytes of chunks added or
removed in that directory between consecutive archives), busiest directory first. It is ``null``
if fewer than two archives matched, as hot spots need at least two archives to compare.

With ``--group-by``, the *by_group* key is present instead, decomposing the whole repository:

archives
    Number of non-deleted archives in the repository
group_by
    List of the archive attributes the archives were grouped by, as given to ``--group-by``
groups
    List of objects with *group*, *archives* (number of archives in that group), *source_size*
    and *stored_size*. *group* is an object mapping each *group_by* attribute to this group's
    value for it, e.g. ``{"name": "home", "host": "host1"}``. The sizes are what is exclusive to
    that group: no archive of another group references those chunks. Biggest *stored_size* first.
shared
    Object with *source_size* and *stored_size*: the chunks referenced by two or more groups
unreferenced
    As above
total
    Object with *archives*, *source_size* and *stored_size*. Each chunk is counted in exactly one
    of *groups*, *shared* and *unreferenced*, so the *groups* and *shared* sizes add up to *total*.
total_chunks, missing_chunks
    As above

Example of ``borg analyze -a 'sh:userA-*' --json``::

    {
        "dedup_size": {
            "considered_archives": 2,
            "deduplicated": {"source_size": 3000, "stored_size": 3536},
            "exclusive": {"source_size": 2000, "stored_size": 3338},
            "missing_chunks": 0,
            "total_archives": 3,
            "total_chunks": 13,
            "unreferenced": {"chunks": 0, "stored_size": 0},
            "whole_repository": false
        },
        "encryption": {"encryption": "aes256-ocb", "id_hash": "sha256"},
        "hotspots": [{"path": "home/user/src", "size": 1000}],
        "repository": {
            "id": "06e4027d32f8eae8333f8fe06b1c2c46bf12f22ad10bd4d04a0f30751a26d77b",
            "last_modified": "2026-08-01T22:46:05.886533",
            "location": "/home/user/repository"
        }
    }


.. _msgid:

Message IDs
-----------

Message IDs are strings that essentially give a log message or operation a name, without actually using the
full text, since texts change more frequently. Message IDs are unambiguous and reduce the need to parse
log messages.

Assigned message IDs and related error RCs (exit codes) are:

.. See scripts/errorlist.py; this is slightly edited.

Errors
    Error rc: 2 traceback: no
        Error: {}
    ErrorWithTraceback rc: 2 traceback: yes
        Error: {}

    Buffer.MemoryLimitExceeded rc: 2 traceback: no
        Requested buffer size {} is above the limit of {}.
    EfficientCollectionQueue.SizeUnderflow rc: 2 traceback: no
        Could not pop the first {} elements; collection only has {} elements.
    RTError rc: 2 traceback: no
        Runtime error: {}

    CancelledByUser rc: 3 traceback: no
        Cancelled by user.

    CommandError rc: 4 traceback: no
        Command error: {}
    PlaceholderError rc: 5 traceback: no
        Formatting Error: "{}".format({}): {}({})
    InvalidPlaceholder rc: 6 traceback: no
        Invalid placeholder "{}" in string: {}

    Repository.AlreadyExists rc: 10 traceback: no
        A repository already exists at {}.
    Repository.CheckNeeded rc: 12 traceback: yes
        Inconsistency detected. Please run "borg check {}".
    Repository.DoesNotExist rc: 13 traceback: no
        Repository {} does not exist.
    Repository.InsufficientFreeSpaceError rc: 14 traceback: no
        Insufficient free space to complete the transaction (required: {}, available: {}).
    Repository.InvalidRepository rc: 15 traceback: no
        {} is not a valid repository. Check the repository config.
    Repository.InvalidRepositoryConfig rc: 16 traceback: no
        {} does not have a valid config. Check the repository config [{}].
    Repository.ObjectNotFound rc: 17 traceback: yes
        Object with key {} not found in repository {}.
    Repository.ParentPathDoesNotExist rc: 18 traceback: no
        The parent path of the repository directory [{}] does not exist.
    Repository.PathAlreadyExists rc: 19 traceback: no
        There is already something at {}.
    Repository.PathPermissionDenied rc: 21 traceback: no
        Permission denied to {}.
    Repository.PackLocationUnknown rc: 22 traceback: yes
        Object with key {} is indexed but its pack location is unresolved in repository {}.
    Repository.PackNotFound rc: 23 traceback: yes
        Object with key {} is indexed to pack {}, but that whole pack is missing from repository {}.
    Repository.PermissionDenied rc: 24 traceback: no
        Repository permission denied: {}

    MandatoryFeatureUnsupported rc: 25 traceback: no
        Unsupported repository feature(s) {}. A newer version of Borg is required to access this repository.
    NoManifestError rc: 26 traceback: no
        Repository has no manifest.
    UnsupportedManifestError rc: 27 traceback: no
        Unsupported manifest envelope. A newer version is required to access this repository.

    Archive.AlreadyExists rc: 30 traceback: no
        Archive {} already exists
    Archive.DoesNotExist rc: 31 traceback: no
        Archive {} does not exist
    Archive.IncompatibleFilesystemEncodingError rc: 32 traceback: no
        Failed to encode filename "{}" into file system encoding "{}". Consider configuring the LANG environment variable.

    KeyfileInvalidError rc: 40 traceback: no
        Invalid key data for repository {} found in {}.
    KeyfileMismatchError rc: 41 traceback: no
        Mismatch between repository {} and key file {}.
    KeyfileNotFoundError rc: 42 traceback: no
        No key file for repository {} found in {}.
    NotABorgKeyFile rc: 43 traceback: no
        This file is not a Borg key backup, aborting.
    RepoKeyNotFoundError rc: 44 traceback: no
        No key found in repository {}.
    RepoIdMismatch rc: 45 traceback: no
        This key backup seems to be for a different backup repository, aborting.
    UnencryptedRepo rc: 46 traceback: no
        Key management not available for unencrypted repositories.
    UnknownKeyType rc: 47 traceback: no
        Key type {0} is unknown.
    UnsupportedPayloadError rc: 48 traceback: no
        Unsupported payload type {}. A newer version is required to access this repository.
    UnsupportedKeyFormatError rc: 49 traceback: no
        Your Borg key is stored in an unsupported format. Try using a newer version of Borg.


    NoPassphraseFailure rc: 50 traceback: no
        Cannot acquire a passphrase: {}.
    PasscommandFailure rc: 51 traceback: no
        Passcommand supplied in BORG_PASSCOMMAND failed: {}.
    PassphraseWrong rc: 52 traceback: no
        Passphrase supplied in BORG_PASSPHRASE, by BORG_PASSCOMMAND, or via BORG_PASSPHRASE_FD is incorrect.
    PasswordRetriesExceeded rc: 53 traceback: no
        Exceeded the maximum password retries.

    CacheInitAbortedError rc: 60 traceback: no
        Cache initialization aborted
    EncryptionMethodMismatch rc: 61 traceback: no
        Repository encryption method changed since last access, refusing to continue
    RepositoryAccessAborted rc: 62 traceback: no
        Repository access aborted
    RepositoryIDNotUnique rc: 63 traceback: no
        Cache is newer than repository - do you have multiple, independently updated repos with same ID?
    RepositoryReplay rc: 64 traceback: no
        Cache, or information obtained from the security directory is newer than repository - this is either an attack or unsafe (multiple repos with same ID)

    LockError rc: 70 traceback: no
        Failed to acquire the lock {}.
    LockErrorT rc: 71 traceback: yes
        Failed to acquire the lock {}.
    LockFailed rc: 72 traceback: yes
        Failed to create/acquire the lock {} ({}).
    LockTimeout rc: 73 traceback: no
        Failed to create/acquire the lock {} (timeout). {}
    NotLocked rc: 74 traceback: yes
        Failed to release the lock {} (was not locked).
    NotMyLock rc: 75 traceback: yes
        Failed to release the lock {} (was/is locked, but not by me).

    These six msgids are shared by the repository lock (``storelocking``) and the filesystem lock
    (``fslocking``), which only the legacy borg 1.x repository code uses (e.g. during
    ``borg transfer --from-borg1``). The messages are the same except for *LockTimeout*, which the
    ``fslocking`` variant emits without the trailing hint.

    ConnectionClosed rc: 80 traceback: no
        Connection closed by remote host.
    ConnectionClosedWithHint rc: 81 traceback: no
        Connection closed by remote host. {}
    InvalidRPCMethod rc: 82 traceback: no
        RPC method {} is not valid.
    PathNotAllowed rc: 83 traceback: no
        Repository path not allowed: {}.
    LegacyRemoteRepository.RPCServerOutdated rc: 84 traceback: no
        Borg server is too old for {}. Required version {}
    UnexpectedRPCDataFormatFromClient rc: 85 traceback: no
        Borg {}: Got unexpected RPC data format from client.
    UnexpectedRPCDataFormatFromServer rc: 86 traceback: no
        Got unexpected RPC data format from server:
        {}
    ConnectionBrokenWithHint rc: 87 traceback: no
        Connection to remote host is broken. {}

    IntegrityError rc: 90 traceback: yes
        Data integrity error: {}
    FileIntegrityError rc: 91 traceback: yes
        File failed integrity check: {}
    DecompressionError rc: 92 traceback: yes
        Decompression error: {}

    Reading a legacy borg 1.x repository (e.g. ``borg transfer --from-borg1``) raises the
    ``LegacyRepository.*`` and ``LegacyRemoteRepository.*`` variants of the repository and RPC
    errors above. They use the same RCs as their non-legacy counterparts.

Warnings
    BorgWarning rc: 1
        Warning: {}
    BackupWarning rc: 1
        {}: {}

    FileChangedWarning rc: 100
        {}: file changed while we backed it up.
    IncludePatternNeverMatchedWarning rc: 101
        Include pattern '{}' never matched.
    BackupError rc: 102
        {}: backup error
    BackupRaceConditionError rc: 103
        {}: file type or inode changed while we backed it up (race condition, skipped file)
    BackupOSError rc: 104
        {}: {}
    BackupPermissionError rc: 105
        {}: {}
    BackupIOError rc: 106
        {}: {}
    BackupFileNotFoundError rc: 107
        {}: {}
    BackupSymlinkParentError rc: 108
        {}: not extracted, a parent directory is a symlink (malicious or corrupted archive)
    BackupPathTraversalError rc: 109
        {}: not extracted, path contains "../" (malicious or corrupted archive)
    BackupHardlinkSourceError rc: 110
        {}: not extracted, hardlink source path is unsafe (malicious or corrupted archive)
    BackupTimeoutError rc: 111
        {}: {}
    BackupBrokenSymlinkError rc: 112
        {}: {}

Operations
    - cache.close

      Saving the local cache (files cache, chunks index, cache config) at the end of a command.
    - cache.build_chunkindex_from_repo

      Rebuilding the chunk index by reading all pack file headers from the repository, e.g. when
      it cannot be built from the stored index fragments or when ``borg check --repair`` rebuilds
      a corrupt index.
    - check.index
    - check.packs
    - check.verify_data
    - check.rebuild_archives
    - check.rebuild_archives_directory
    - repository.merge_packs
    - compact.analyze_archives
    - compact.compact_packs
    - repo_compress.recompress
    - analyze.dedup_size
    - analyze.analyze_archives
    - extract

      Used by :ref:`borg_extract` and :ref:`borg_export-tar`. *info* is one string element,
      the name of the path currently extracted.
    - extract.permissions
    - prune

Prompts
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK
        For "Warning: Attempting to access a previously unknown unencrypted repository!"
    BORG_RELOCATED_REPO_ACCESS_IS_OK
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING
        For "This is a potentially dangerous function..." (check --repair)
    BORG_DELETE_I_KNOW_WHAT_I_AM_DOING
        For "You requested to DELETE the following repository completely *including* ... archives
        it contains:" (repo-delete)
    BORG_DISPLAY_PASSPHRASE
        For "Do you want your passphrase to be displayed for verification? [yN]:" (interactive
        entry of a new passphrase)
