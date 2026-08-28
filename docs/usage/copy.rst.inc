.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_copy:

borg copy
---------
.. code-block:: none

    borg [common options] copy [options] OLDNAME NEWNAME

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------+-----------------------------------------+
    | **positional arguments**                                                                                      |
    +-------------------------------------------------------+-------------+-----------------------------------------+
    |                                                       | ``OLDNAME`` | specify the existing archive name or ID |
    +-------------------------------------------------------+-------------+-----------------------------------------+
    |                                                       | ``NEWNAME`` | specify the new archive name            |
    +-------------------------------------------------------+-------------+-----------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                |
    |                                                                                                               |
    | :ref:`common_options`                                                                                         |
    +-------------------------------------------------------+-------------+-----------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    OLDNAME
        specify the existing archive name or ID
    NEWNAME
        specify the new archive name


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command copies an existing archive to a new archive with a different name,
keeping the existing archive.

Afterwards, the repository has two archives with the same contents, but with
different names and different archive IDs. The copy is an independent archive:
deleting either of the two archives keeps the other one intact, because
``borg compact`` only frees chunks that no remaining archive references.

Copying is cheap and fast: no file content is read or written, only a new archive
metadata object is created. Like any deduplicated archives, the two archives share
their data, so a copy needs almost no additional repository space.

Because archive names do not need to be unique, NEWNAME may also be the name of
some *other* already existing archive - the copy then just becomes another archive
of that archive series.

NEWNAME must be different from the name of the archive that is copied, though: the
copy would get identical metadata and thus the same archive ID as its source, so no
second archive could be created.

OLDNAME must match precisely one archive: give an archive name (if it is unique) or
an archive ID, like ``aid:d34db33f``.

Note: to copy archives into a *different* repository, use ``borg transfer``.