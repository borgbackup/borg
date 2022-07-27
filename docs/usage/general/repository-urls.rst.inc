Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` - filesystem path to repo directory, absolute path

``path/to/repo`` - filesystem path to repo directory, relative path

Also, stuff like ``~/path/to/repo`` or ``~other/path/to/repo`` works (this is
expanded by your shell).

Note: you may also prepend a ``file://`` to a filesystem path to get URL style.

**Remote repositories** accessed via ssh user@host:

``ssh://user@host:port/path/to/repo`` - absolute path`

``ssh://user@host:port/./path/to/repo`` - path relative to current directory

``ssh://user@host:port/~/path/to/repo`` - path relative to user's home directory


If you frequently need the same repo URL, it is a good idea to set the
``BORG_REPO`` environment variable to set a default for the repo URL:

::

    export BORG_REPO='ssh://user@host:port/path/to/repo'

Then just leave away the ``--repo`` option if you want
to use the default - it will be read from BORG_REPO then.
