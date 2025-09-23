Repository Locations / Archive Names
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many commands need to know the repository location; specify it via ``-r``/``--repo``
or use the ``BORG_REPO`` environment variable.

Commands that need one or two archive names usually take them as positional arguments.

Commands that work with an arbitrary number of archives usually accept ``-a ARCH_GLOB``.

Archive names must not contain the ``/`` (slash) character. For simplicity,
also avoid spaces or other characters that have special meaning to the
shell or in a filesystem (``borg mount`` uses the archive name as a directory
name).
