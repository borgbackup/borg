Repository / Archive Locations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many commands want either a repository (just give the repo URL, see above) or
an archive location, which is a repo URL followed by ``::archive_name``.

Archive names must not contain the ``/`` (slash) character. For simplicity,
maybe also avoid blanks or other characters that have special meaning on the
shell or in a filesystem (borg mount will use the archive name as directory
name).

If you have set BORG_REPO (see above) and an archive location is needed, use
``::archive_name`` - the repo URL part is then read from BORG_REPO.
