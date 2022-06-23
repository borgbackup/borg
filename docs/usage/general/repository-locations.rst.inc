Repository Locations / Archive names
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many commands need to know the repository location, give it via ``-r`` / ``--repo``
or use the ``BORG_REPO`` environment variable.

Commands needing one or two archive names usually get them as positional argument.

Commands working with an arbitrary amount of archives, usually take ``-a ARCH_GLOB``.

Archive names must not contain the ``/`` (slash) character. For simplicity,
maybe also avoid blanks or other characters that have special meaning on the
shell or in a filesystem (borg mount will use the archive name as directory
name).
