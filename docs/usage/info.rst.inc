.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_info:

borg info
---------
::

    borg info <options> ARCHIVE

positional arguments
    ARCHIVE
        archive to display information about

`Common options`_
    |

Description
~~~~~~~~~~~

This command displays some detailed information about the specified archive.

The "This archive" line refers exclusively to this archive:
"Deduplicated size" is the size of the unique chunks stored only for this
archive. Non-unique / common chunks show up under "All archives".
