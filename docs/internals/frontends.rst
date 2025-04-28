.. include:: ../global.rst.inc
.. highlight:: none

.. _json_output:

All about JSON: How to develop frontends
========================================

Borg does not have a public API on the Python level. That does not keep you from writing :code:`import borg`,
but does mean that there are no release-to-release guarantees on what you might find in that package, not
even for point releases (1.1.x), and there is no documentation beyond the code and the internals documents.

Borg does on the other hand provide an API on a command-line level. In other words, a frontend should
(for example) create a backup archive just invoke :ref:`borg_create`, give commandline parameters/options
as needed and parse JSON output from borg.

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
    Output during operations creating archives (:ref:`borg_create` and :ref:`borg_recreate`).
    The following keys exist, each represents the current progress.

    original_size
        Original size of data processed so far (before compression and deduplication, may be empty/absent)
    compressed_size
        Compressed size (may be empty/absent)
    deduplicated_size
        Deduplicated size (may be empty/absent)
    nfiles
        Number of (regular) files processed so far (may be empty/absent)
    path
        Current path (may be empty/absent)
    time
        Unix timestamp (float)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*.

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
        current progress message (may be empty/absent)
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
        (absent for finished == true)
    current
        Current value (always less-or-equal to *total*, absent for finished == true)
    info
        Array that describes the current item, may be *null*, contents depend on *msgid*
        (absent for finished == true)
    total
        Total value (absent for finished == true)
    time
        Unix timestamp (float)

file_status
    This is only output by :ref:`borg_create` and :ref:`borg_recreate` if ``--list`` is specified. The usual
    rules for the file listing applies, including the ``--filter`` option.

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

    {"message": "100.0% Extracting: src/borgbackup.egg-info/entry_points.txt",
     "current": 13000228, "total": 13004993, "info": ["src/borgbackup.egg-info/entry_points.txt"],
     "operation": 1, "msgid": "extract", "type": "progress_percent", "finished": false}
    {"message": "100.0% Extracting: src/borgbackup.egg-info/SOURCES.txt",
     "current": 13004993, "total": 13004993, "info": ["src/borgbackup.egg-info/SOURCES.txt"],
     "operation": 1, "msgid": "extract", "type": "progress_percent", "finished": false}
    {"operation": 1, "msgid": "extract", "type": "progress_percent", "finished": true}

:ref:`borg_create` file listing with progress::

    {"original_size": 0, "compressed_size": 0, "deduplicated_size": 0, "nfiles": 0, "type": "archive_progress", "path": "src"}
    {"type": "file_status", "status": "U", "path": "src/borgbackup.egg-info/entry_points.txt"}
    {"type": "file_status", "status": "U", "path": "src/borgbackup.egg-info/SOURCES.txt"}
    {"type": "file_status", "status": "d", "path": "src/borgbackup.egg-info"}
    {"type": "file_status", "status": "d", "path": "src"}
    {"original_size": 13176040, "compressed_size": 11386863, "deduplicated_size": 503, "nfiles": 277, "type": "archive_progress", "path": ""}

Internal transaction progress::

    {"message": "Saving files cache", "operation": 2, "msgid": "cache.commit", "type": "progress_message", "finished": false}
    {"message": "Saving cache config", "operation": 2, "msgid": "cache.commit", "type": "progress_message", "finished": false}
    {"message": "Saving chunks cache", "operation": 2, "msgid": "cache.commit", "type": "progress_message", "finished": false}
    {"operation": 2, "msgid": "cache.commit", "type": "progress_message", "finished": true}

A debug log message::

    {"message": "35 self tests completed in 0.08 seconds",
     "type": "log_message", "created": 1488278449.5575905, "levelname": "DEBUG", "name": "borg.archiver"}

Prompts
-------

Prompts assume a JSON form as well when the ``--log-json`` option is specified. Responses
are still read verbatim from *stdin*, while prompts are JSON messages printed to *stderr*,
just like log messages.

Prompts use the *question_prompt* and *question_prompt_retry* types for the prompt itself,
and *question_invalid_answer*, *question_accepted_default*, *question_accepted_true*,
*question_accepted_false* and *question_env_answer* types for information about
prompt processing.

The *message* property contains the same string displayed regularly in the same situation,
while the *msgid* property may contain a msgid_, typically the name of the
environment variable that can be used to override the prompt. It is the same for all JSON
messages pertaining to the same prompt.

.. rubric:: Examples (reformatted, each object would be on exactly one line)
.. highlight:: none

Providing an invalid answer::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "... Type 'YES' if you understand this and want to continue: "}
    incorrect answer  # input on stdin
    {"type": "question_invalid_answer", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "is_prompt": false,
     "message": "Invalid answer, aborting."}

Providing a false (negative) answer::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "... Type 'YES' if you understand this and want to continue: "}
    NO  # input on stdin
    {"type": "question_accepted_false", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "Aborting.", "is_prompt": false}

Providing a true (affirmative) answer::

    {"type": "question_prompt", "msgid": "BORG_CHECK_I_KNOW_WHAT_I_AM_DOING",
     "message": "... Type 'YES' if you understand this and want to continue: "}
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
2. Invoke ``borg list repository ...``
3. If this fails, due the repository being encrypted and the passphrase obviously being
   wrong, you'll get an error with the *PassphraseWrong* msgid.

   The repository is encrypted, for further access the application will need the passphrase.

4. If this does not fail, then the repository is not encrypted.

Standard output
---------------

*stdout* is different and more command-dependent than logging. Commands like :ref:`borg_info`, :ref:`borg_create`
and :ref:`borg_list` implement a ``--json`` option which turns their regular output into a single JSON object.

Some commands, like :ref:`borg_list` and :ref:`borg_diff`, can produce *a lot* of JSON. Since many JSON implementations
don't support a streaming mode of operation, which is pretty much required to deal with this amount of JSON, these
commands implement a ``--json-lines`` option which generates output in the `JSON lines <http://jsonlines.org/>`_ format,
which is simply a number of JSON objects separated by new lines.

Dates are formatted according to ISO 8601 in local time. No explicit time zone is specified *at this time*
(subject to change). The equivalent strftime format string is '%Y-%m-%dT%H:%M:%S.%f',
e.g. ``2017-08-07T12:27:20.123456``.

The root object of '--json' output will contain at least a *repository* key with an object containing:

id
    The ID of the repository, normally 64 hex characters
location
    Canonicalized repository path, thus this may be different from what is specified on the command line
last_modified
    Date when the repository was last modified by the Borg client

The *encryption* key, if present, contains:

mode
    Textual encryption mode name (same as :ref:`borg_repo-create` ``--encryption`` names)
keyfile
    Path to the local key file used for access. Depending on *mode* this key may be absent.

The *cache* key, if present, contains:

path
    Path to the local repository cache
stats
    Object containing cache stats:

    total_chunks
        Number of chunks
    total_unique_chunks
        Number of unique chunks
    total_size
        Total uncompressed size of all chunks multiplied with their reference counts
    unique_size
        Uncompressed size of all chunks

.. highlight: json

Example *borg info* output::

    {
        "cache": {
            "path": "/home/user/.cache/borg/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "stats": {
                "total_chunks": 511533,
                "total_size": 22635749792,
                "total_unique_chunks": 54892,
                "unique_size": 2449675468
            }
        },
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "2017-08-07T12:27:20.789123",
            "location": "/home/user/testrepo"
        },
        "security_dir": "/home/user/.config/borg/security/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
        "archives": []
    }

Archive formats
+++++++++++++++

:ref:`borg_info` uses an extended format for archives, which is more expensive to retrieve, while
:ref:`borg_list` uses a simpler format that is faster to retrieve. Either return archives in an
array under the *archives* key, while :ref:`borg_create` returns a single archive object under the
*archive* key.

Both formats contain a *name* key with the archive name, the *id* key with the hexadecimal archive ID,
and the *start* key with the start timestamp.

*borg info* and *borg create* further have:

end
    End timestamp
duration
    Duration in seconds between start and end in seconds (float)
stats
    Archive statistics (freshly calculated, this is what makes "info" more expensive)

    original_size
        Size of files and metadata before compression
    compressed_size
        Size after compression
    deduplicated_size
        Deduplicated size (against the current repository, not when the archive was created)
    nfiles
        Number of regular files in the archive
command_line
    Array of strings of the command line that created the archive

    The note about paths from above applies here as well.
chunker_params
    The chunker parameters the archive has been created with.

:ref:`borg_info` further has:

hostname
    Hostname of the creating host
username
    Name of the creating user
comment
    Archive comment, if any

Some keys/values are more expensive to compute than others (e.g. because it requires opening the archive,
not just the manifest). To optimize for speed, `borg list repo` does not determine these values except
when they are requested. The `--format` option is used for that (for normal mode as well as for `--json`
mode), so, to have the comment included in the json output, you will need:

::

    borg list repo --format "{name}{comment}" --json`


Example of a simple archive listing (``borg list --last 1 --json``)::

    {
        "archives": [
            {
                "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                "name": "host-system-backup-2017-02-27",
                "start": "2017-08-07T12:27:20.789123"
            }
        ],
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "2017-08-07T12:27:20.789123",
            "location": "/home/user/repository"
        }
    }

The same archive with more information (``borg info --last 1 --json``)::

    {
        "archives": [
            {
                "chunker_params": [
                    "buzhash",
                    13,
                    23,
                    16,
                    4095
                ],
                "command_line": [
                    "/home/user/.local/bin/borg",
                    "create",
                    "/home/user/repository",
                    "..."
                ],
                "comment": "",
                "duration": 5.641542,
                "end": "2017-02-27T12:27:20.789123",
                "hostname": "host",
                "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                "name": "host-system-backup-2017-02-27",
                "start": "2017-02-27T12:27:20.789123",
                "stats": {
                    "compressed_size": 1880961894,
                    "deduplicated_size": 2791,
                    "nfiles": 53669,
                    "original_size": 2400471280
                },
                "username": "user"
            }
        ],
        "cache": {
            "path": "/home/user/.cache/borg/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "stats": {
                "total_chunks": 511533,
                "total_size": 22635749792,
                "total_unique_chunks": 54892,
                "unique_size": 2449675468
            }
        },
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "2017-08-07T12:27:20.789123",
            "location": "/home/user/repository"
        }
    }

File listings
+++++++++++++

Each archive item (file, directory, ...) is described by one object in the :ref:`borg_list` output.
Refer to the *borg list* documentation for the available keys and their meaning.

Example (excerpt) of ``borg list --json-lines``::

    {"type": "d", "mode": "drwxr-xr-x", "user": "user", "group": "user", "uid": 1000, "gid": 1000, "path": "linux", "target": "", "flags": null, "mtime": "2017-02-27T12:27:20.023407", "size": 0}
    {"type": "d", "mode": "drwxr-xr-x", "user": "user", "group": "user", "uid": 1000, "gid": 1000, "path": "linux/baz", "target": "", "flags": null, "mtime": "2017-02-27T12:27:20.585407", "size": 0}


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

  - *modified* - file contents changed.
  - *added* - the file was added.
  - *removed* - the file was removed.
  - *added directory* - the directory was added.
  - *removed directory* - the directory was removed.
  - *added link* - the symlink was added.
  - *removed link* - the symlink was removed.
  - *changed link* - the symlink target was changed.
  - *mode* - the file/directory/link mode was changed. Note - this could indicate a change from a
    file/directory/link type to a different type (file/directory/link), such as -- a file is deleted and replaced
    with a directory of the same name.
  - *owner* - user and/or group ownership changed.

size:
    If **type** == '*added*' or '*removed*', then **size** provides the size of the added or removed file.

added:
    If **type** == '*modified*' and chunk ids can be compared, then **added** and **removed** indicate the amount
    of data 'added' and 'removed'. If chunk ids can not be compared, then **added** and **removed** properties are
    not provided and the only information available is that the file contents were modified.

removed:
    See **added** property.

old_mode:
    If **type** == '*mode*', then **old_mode** and **new_mode** provide the mode and permissions changes.

new_mode:
    See **old_mode** property.

old_user:
    If **type** == '*owner*', then **old_user**, **new_user**, **old_group** and **new_group** provide the user
    and group ownership changes.

old_group:
    See **old_user** property.

new_user:
    See **old_user** property.

new_group:
    See **old_user** property.


Example (excerpt) of ``borg diff --json-lines``::

    {"path": "file1", "changes": [{"path": "file1", "changes": [{"type": "modified", "added": 17, "removed": 5}, {"type": "mode", "old_mode": "-rw-r--r--", "new_mode": "-rwxr-xr-x"}]}]}
    {"path": "file2", "changes": [{"type": "modified", "added": 135, "removed": 252}]}
    {"path": "file4", "changes": [{"type": "added", "size": 0}]}
    {"path": "file3", "changes": [{"type": "removed", "size": 0}]}


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
        Could not pop_front first {} elements, collection only has {} elements..
    RTError rc: 2 traceback: no
        Runtime Error: {}

    CancelledByUser rc: 3 traceback: no
        Cancelled by user.

    CommandError rc: 4 traceback: no
        Command Error: {}
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
        Insufficient free space to complete transaction (required: {}, available: {}).
    Repository.InvalidRepository rc: 15 traceback: no
        {} is not a valid repository. Check repo config.
    Repository.InvalidRepositoryConfig rc: 16 traceback: no
        {} does not have a valid configuration. Check repo config [{}].
    Repository.ObjectNotFound rc: 17 traceback: yes
        Object with key {} not found in repository {}.
    Repository.ParentPathDoesNotExist rc: 18 traceback: no
        The parent path of the repo directory [{}] does not exist.
    Repository.PathAlreadyExists rc: 19 traceback: no
        There is already something at {}.
    Repository.PathPermissionDenied rc: 21 traceback: no
        Permission denied to {}.

    MandatoryFeatureUnsupported rc: 25 traceback: no
        Unsupported repository feature(s) {}. A newer version of borg is required to access this repository.
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
        This file is not a borg key backup, aborting.
    RepoKeyNotFoundError rc: 44 traceback: no
        No key entry found in the config of repository {}.
    RepoIdMismatch rc: 45 traceback: no
        This key backup seems to be for a different backup repository, aborting.
    UnencryptedRepo rc: 46 traceback: no
        Key management not available for unencrypted repositories.
    UnknownKeyType rc: 47 traceback: no
        Key type {0} is unknown.
    UnsupportedPayloadError rc: 48 traceback: no
        Unsupported payload type {}. A newer version is required to access this repository.
    UnsupportedKeyFormatError rc: 49 traceback:no
        Your borg key is stored in an unsupported format. Try using a newer version of borg.


    NoPassphraseFailure rc: 50 traceback: no
        can not acquire a passphrase: {}
    PasscommandFailure rc: 51 traceback: no
        passcommand supplied in BORG_PASSCOMMAND failed: {}
    PassphraseWrong rc: 52 traceback: no
        passphrase supplied in BORG_PASSPHRASE, by BORG_PASSCOMMAND or via BORG_PASSPHRASE_FD is incorrect.
    PasswordRetriesExceeded rc: 53 traceback: no
        exceeded the maximum password retries

    Cache.CacheInitAbortedError rc: 60 traceback: no
        Cache initialization aborted
    Cache.EncryptionMethodMismatch rc: 61 traceback: no
        Repository encryption method changed since last access, refusing to continue
    Cache.RepositoryAccessAborted rc: 62 traceback: no
        Repository access aborted
    Cache.RepositoryIDNotUnique rc: 63 traceback: no
        Cache is newer than repository - do you have multiple, independently updated repos with same ID?
    Cache.RepositoryReplay rc: 64 traceback: no
        Cache, or information obtained from the security directory is newer than repository - this is either an attack or unsafe (multiple repos with same ID)

    LockError rc: 70 traceback: no
        Failed to acquire the lock {}.
    LockErrorT rc: 71 traceback: yes
        Failed to acquire the lock {}.
    LockFailed rc: 72 traceback: yes
        Failed to create/acquire the lock {} ({}).
    LockTimeout rc: 73 traceback: no
        Failed to create/acquire the lock {} (timeout).
    NotLocked rc: 74 traceback: yes
        Failed to release the lock {} (was not locked).
    NotMyLock rc: 75 traceback: yes
        Failed to release the lock {} (was/is locked, but not by me).

    ConnectionClosed rc: 80 traceback: no
        Connection closed by remote host
    ConnectionClosedWithHint rc: 81 traceback: no
        Connection closed by remote host. {}
    InvalidRPCMethod rc: 82 traceback: no
        RPC method {} is not valid
    PathNotAllowed rc: 83 traceback: no
        Repository path not allowed: {}
    RemoteRepository.RPCServerOutdated rc: 84 traceback: no
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


Warnings
    BorgWarning rc: 1
        Warning: {}
    BackupWarning rc: 1
        {}: {}

    FileChangedWarning rc: 100
        {}: file changed while we backed it up
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

Operations
    - cache.begin_transaction
    - cache.download_chunks, appears with ``borg create --no-cache-sync``
    - cache.commit
    - cache.sync

      *info* is one string element, the name of the archive currently synced.
    - repository.compact_segments
    - repository.replay_segments
    - repository.check
    - check.verify_data
    - check.rebuild_manifest
    - check.rebuild_refcounts
    - extract

      *info* is one string element, the name of the path currently extracted.
    - extract.permissions
    - archive.delete
    - archive.calc_stats
    - prune
    - upgrade.convert_segments

Prompts
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK
        For "Warning: Attempting to access a previously unknown unencrypted repository"
    BORG_RELOCATED_REPO_ACCESS_IS_OK
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING
        For "This is a potentially dangerous function..." (check --repair)
    BORG_DELETE_I_KNOW_WHAT_I_AM_DOING
        For "You requested to DELETE the repository completely *including* all archives it contains:"
