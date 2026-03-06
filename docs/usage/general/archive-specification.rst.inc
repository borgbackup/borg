.. _archive_specification:

Specifying an archive
~~~~~~~~~~~~~~~~~~~~~

How to refer to an archive depends on whether you use archive series or not.

**By ID:** if you use archive series, many or all archives will have the same name, thus
you need to refer to a single archive by its archive ID (see ``borg repo-list``
output)::

    borg info aid:f7dea078

The ``aid:`` prefix does a prefix match on the archive ID (the hex representation
of the archive fingerprint). You only need to give enough hex digits to uniquely
identify the archive. This is useful when archive names are ambiguous or when
you want to refer to an archive by its immutable ID.

**By name:** if you don't use archive series, but do it old-style by giving every archive
a unique name, you can refer to an archive by its name::

    borg info my-backup-202512312359

For more details on archive matching patterns (including shell-style globs,
regular expressions, and matching by user/host/tags), see :ref:`borg_match-archives`.
