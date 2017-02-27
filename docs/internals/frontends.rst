.. include:: ../global.rst.inc
.. highlight:: none

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

The following types are in use:

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

progress_message
    A message-based progress information with no concrete progress information, just a message
    saying what is currently worked on.

    operation
        unique, opaque integer ID of the operation
    msgid
        Message ID of the operation (may be *none*)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*.
    message
        current progress message (may be empty/absent)

progress_percent
    Absolute progress information with defined end/total and current value.

    operation
        unique, opaque integer ID of the operation
    msgid
        Message ID of the operation (may be *none*)
    finished
        boolean indicating whether the operation has finished, only the last object for an *operation*
        can have this property set to *true*.
    message
        A formatted progress message, this will include the percentage and perhaps other information
    current
        Current value (always less-or-equal to *total*)
    total
        Total value

file_status
    This is only output by :ref:`borg_create` and :ref:`borg_recreate` if ``--list`` is specified. The usual
    rules for the file listing applies, including the ``--filter`` option.

    status
        Single-character status as for regular list output
    path
        Path of the file system object

log_message
    Any regular log output invokes this type. Regular log options and filtering applies to these as well.

    created
        Unix timestamp (float)
    levelname
        Upper-case log level name (also called severity). Defined levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    name
        Name of the emitting entity
    message
        Formatted log message

Standard output
---------------

*stdout* is different and more command-dependent. Commands like :ref:`borg_info`, :ref:`borg_create`
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

.. rubric:: Archive formats

:ref:`borg_info` uses an extended format for archives, which is more expensive to retrieve, while
:ref:`borg_list` uses a simpler format that is faster to retrieve. Either return archives in an
array under the *archives* key, while :ref:`borg_create` returns a single archive object under the
*archive* key.

Both formats contain a *name* key with the archive name, and the *id* key with the hexadecimal archive ID.

 info and create further have:

start
    Start timestamp
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

.. rubric:: File listings

Listing the contents of an archive can produce *a lot* of JSON. Each item (file, directory, ...) is described
by one object in the *files* array of the :ref:`borg_list` output. Refer to the *borg list* documentation for
the available keys and their meaning.
