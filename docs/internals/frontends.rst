.. include:: ../global.rst.inc
.. highlight:: json

.. _json_output:

All about JSON: How to develop frontends
========================================

Borg does not have a public API on the Python level. That does not keep you from writing :code:`import borg`,
but does mean that there are no release-to-release guarantees on what you might find in that package, not
even for point releases (1.1.x), and there is no documentation beyond the code and the internals documents.

Borg does on the other hand provide an API on a command-line level. In other words, a frontend should to
(for example) create a backup archive just invoke :ref:`borg_create`.

Logging
-------

Especially for graphical frontends it is important to be able to convey and reformat progress information
in meaningful ways. The ``--log-json`` option turns the stderr stream of Borg into a stream of JSON lines,
where each line is a JSON object. The *type* key of the object determines its other contents.

Since JSON can only encode text, any string representing a file system path may miss non-text parts.

The following types are in use. Progress information is governed by the usual rules for progress information,
it is not produced unless ``--progress`` is specified.

archive_progress
    Output during operations creating archives (:ref:`borg_create` and :ref:`borg_recreate`).
    The following keys exist, each represents the current progress.

    original_size
        Original size of data processed so far (before compression and deduplication)
    compressed_size
        Compressed size
    deduplicated_size
        Deduplicated size
    nfiles
        Number of (regular) files processed so far
    path
        Current path
    time
        Unix timestamp (float)

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
    current
        Current value (always less-or-equal to *total*)
    info
        Array that describes the current item, may be *null*, contents depend on *msgid*
    total
        Total value
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

When setting a new passphrase (:ref:`borg_init`, :ref:`borg_key_change-passphrase`) normally
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

Dates are formatted according to ISO-8601 with the strftime format string '%a, %Y-%m-%d %H:%M:%S',
e.g. *Sat, 2016-02-25 23:50:06*.

The root object at least contains a *repository* key with an object containing:

id
    The ID of the repository, normally 64 hex characters
location
    Canonicalized repository path, thus this may be different from what is specified on the command line
last_modified
    Date when the repository was last modified by the Borg client

The *encryption* key, if present, contains:

mode
    Textual encryption mode name (same as :ref:`borg_init` ``--encryption`` names)
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
    total_csize
        Total compressed and encrypted size of all chunks multiplied with their reference counts
    unique_size
        Uncompressed size of all chunks
    unique_csize
        Compressed and encrypted size of all chunks

Example *borg info* output::

    {
        "cache": {
            "path": "/home/user/.cache/borg/0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "stats": {
                "total_chunks": 511533,
                "total_csize": 17948017540,
                "total_size": 22635749792,
                "total_unique_chunks": 54892,
                "unique_csize": 1920405405,
                "unique_size": 2449675468
            }
        },
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "Mon, 2017-02-27 21:21:58",
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
limits
    Object describing the utilization of Borg limits

    max_archive_size
        Float between 0 and 1 describing how large this archive is relative to the maximum size allowed by Borg
command_line
    Array of strings of the command line that created the archive

    The note about paths from above applies here as well.

:ref:`borg_info` further has:

hostname
    Hostname of the creating host
username
    Name of the creating user
comment
    Archive comment, if any

Example of a simple archive listing (``borg list --last 1 --json``)::

    {
        "archives": [
            {
                "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                "name": "host-system-backup-2017-02-27",
                "start": "Mon, 2017-02-27 21:21:52"
            }
        ],
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "Mon, 2017-02-27 21:21:58",
            "location": "/home/user/repository"
        }
    }

The same archive with more information (``borg info --last 1 --json``)::

    {
        "archives": [
            {
                "command_line": [
                    "/home/user/.local/bin/borg",
                    "create",
                    "/home/user/repository",
                    "..."
                ],
                "comment": "",
                "duration": 5.641542,
                "end": "Mon, 2017-02-27 21:21:58",
                "hostname": "host",
                "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                "limits": {
                    "max_archive_size": 0.0001330855110409714
                },
                "name": "host-system-backup-2017-02-27",
                "start": "Mon, 2017-02-27 21:21:52",
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
                "total_csize": 17948017540,
                "total_size": 22635749792,
                "total_unique_chunks": 54892,
                "unique_csize": 1920405405,
                "unique_size": 2449675468
            }
        },
        "encryption": {
            "mode": "repokey"
        },
        "repository": {
            "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
            "last_modified": "Mon, 2017-02-27 21:21:58",
            "location": "/home/user/repository"
        }
    }

File listings
+++++++++++++

Listing the contents of an archive can produce *a lot* of JSON. Since many JSON implementations
don't support a streaming mode of operation, which is pretty much required to deal with this amount of
JSON, output is generated in the `JSON lines <http://jsonlines.org/>`_ format, which is simply
a number of JSON objects separated by new lines.

Each item (file, directory, ...) is described by one object in the :ref:`borg_list` output.
Refer to the *borg list* documentation for the available keys and their meaning.

Example (excerpt) of ``borg list --json-lines``::

    {"type": "d", "mode": "drwxr-xr-x", "user": "user", "group": "user", "uid": 1000, "gid": 1000, "path": "linux", "healthy": true, "source": "", "linktarget": "", "flags": null, "isomtime": "Sat, 2016-05-07 19:46:01", "size": 0}
    {"type": "d", "mode": "drwxr-xr-x", "user": "user", "group": "user", "uid": 1000, "gid": 1000, "path": "linux/baz", "healthy": true, "source": "", "linktarget": "", "flags": null, "isomtime": "Sat, 2016-05-07 19:46:01", "size": 0}

.. _msgid:

Message IDs
-----------

Message IDs are strings that essentially give a log message or operation a name, without actually using the
full text, since texts change more frequently. Message IDs are unambiguous and reduce the need to parse
log messages.

Assigned message IDs are:

.. See scripts/errorlist.py; this is slightly edited.

Errors
    Archive.AlreadyExists
        Archive {} already exists
    Archive.DoesNotExist
        Archive {} does not exist
    Archive.IncompatibleFilesystemEncodingError
        Failed to encode filename "{}" into file system encoding "{}". Consider configuring the LANG environment variable.
    Cache.CacheInitAbortedError
        Cache initialization aborted
    Cache.EncryptionMethodMismatch
        Repository encryption method changed since last access, refusing to continue
    Cache.RepositoryAccessAborted
        Repository access aborted
    Cache.RepositoryIDNotUnique
        Cache is newer than repository - do you have multiple, independently updated repos with same ID?
    Cache.RepositoryReplay
        Cache is newer than repository - this is either an attack or unsafe (multiple repos with same ID)
    Buffer.MemoryLimitExceeded
        Requested buffer size {} is above the limit of {}.
    ExtensionModuleError
        The Borg binary extension modules do not seem to be properly installed
    IntegrityError
        Data integrity error: {}
    NoManifestError
        Repository has no manifest.
    PlaceholderError
        Formatting Error: "{}".format({}): {}({})
    KeyfileInvalidError
        Invalid key file for repository {} found in {}.
    KeyfileMismatchError
        Mismatch between repository {} and key file {}.
    KeyfileNotFoundError
        No key file for repository {} found in {}.
    PassphraseWrong
        passphrase supplied in BORG_PASSPHRASE is incorrect
    PasswordRetriesExceeded
        exceeded the maximum password retries
    RepoKeyNotFoundError
        No key entry found in the config of repository {}.
    UnsupportedManifestError
        Unsupported manifest envelope. A newer version is required to access this repository.
    UnsupportedPayloadError
        Unsupported payload type {}. A newer version is required to access this repository.
    NotABorgKeyFile
        This file is not a borg key backup, aborting.
    RepoIdMismatch
        This key backup seems to be for a different backup repository, aborting.
    UnencryptedRepo
        Keymanagement not available for unencrypted repositories.
    UnknownKeyType
        Keytype {0} is unknown.
    LockError
        Failed to acquire the lock {}.
    LockErrorT
        Failed to acquire the lock {}.
    ConnectionClosed
        Connection closed by remote host
    InvalidRPCMethod
        RPC method {} is not valid
    PathNotAllowed
        Repository path not allowed
    RemoteRepository.RPCServerOutdated
        Borg server is too old for {}. Required version {}
    UnexpectedRPCDataFormatFromClient
        Borg {}: Got unexpected RPC data format from client.
    UnexpectedRPCDataFormatFromServer
        Got unexpected RPC data format from server:
        {}
    Repository.AlreadyExists
        Repository {} already exists.
    Repository.CheckNeeded
        Inconsistency detected. Please run "borg check {}".
    Repository.DoesNotExist
        Repository {} does not exist.
    Repository.InsufficientFreeSpaceError
        Insufficient free space to complete transaction (required: {}, available: {}).
    Repository.InvalidRepository
        {} is not a valid repository. Check repo config.
    Repository.ObjectNotFound
        Object with key {} not found in repository {}.

Operations
    - cache.begin_transaction
    - cache.download_chunks, appears with ``borg create --no-cache-sync``
    - cache.commit
    - cache.sync

      *info* is one string element, the name of the archive currently synced.
    - repository.compact_segments
    - repository.replay_segments
    - repository.check_segments
    - check.verify_data
    - extract

      *info* is one string element, the name of the path currently extracted.
    - extract.permissions
    - archive.delete

Prompts
    BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK
        For "Warning: Attempting to access a previously unknown unencrypted repository"
    BORG_RELOCATED_REPO_ACCESS_IS_OK
        For "Warning: The repository at location ... was previously located at ..."
    BORG_CHECK_I_KNOW_WHAT_I_AM_DOING
        For "Warning: 'check --repair' is an experimental feature that might result in data loss."
    BORG_DELETE_I_KNOW_WHAT_I_AM_DOING
        For "You requested to completely DELETE the repository *including* all archives it contains:"
    BORG_RECREATE_I_KNOW_WHAT_I_AM_DOING
        For "recreate is an experimental feature."
