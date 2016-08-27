.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_info:

borg info
---------
::

    borg info <options> REPOSITORY_OR_ARCHIVE

positional arguments
    REPOSITORY_OR_ARCHIVE
        archive or repository to display information about

`Common options`_
    |

Description
~~~~~~~~~~~

This command displays detailed information about the specified archive or repository.

The "This archive" line refers exclusively to the given archive:
"Deduplicated size" is the size of the unique chunks stored only for the
given archive.

The "All archives" line shows global statistics (all chunks).
