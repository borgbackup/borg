Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` - filesystem path to repo directory, absolute path

``path/to/repo`` - filesystem path to repo directory, relative path

Also, stuff like ``~/path/to/repo`` or ``~other/path/to/repo`` works (this is
expanded by your shell).

Note: you may also prepend a ``file://`` to a filesystem path to get URL style.

**Remote repositories** accessed via ssh user@host:

``user@host:/path/to/repo`` - remote repo, absolute path

``ssh://user@host:port/path/to/repo`` - same, alternative syntax, port can be given


**Remote repositories with relative paths** can be given using this syntax:

``user@host:path/to/repo`` - path relative to current directory

``user@host:~/path/to/repo`` - path relative to user's home directory

``user@host:~other/path/to/repo`` - path relative to other's home directory

Note: giving ``user@host:/./path/to/repo`` or ``user@host:/~/path/to/repo`` or
``user@host:/~other/path/to/repo`` is also supported, but not required here.


**Remote repositories with relative paths, alternative syntax with port**:

``ssh://user@host:port/./path/to/repo`` - path relative to current directory

``ssh://user@host:port/~/path/to/repo`` - path relative to user's home directory

``ssh://user@host:port/~other/path/to/repo`` - path relative to other's home directory


If you frequently need the same repo URL, it is a good idea to set the
``BORG_REPO`` environment variable to set a default for the repo URL:

::

    export BORG_REPO='ssh://user@host:port/path/to/repo'

Then just leave away the repo URL if only a repo URL is needed and you want
to use the default - it will be read from BORG_REPO then.

Use ``::`` syntax to give the repo URL when syntax requires giving a positional
argument for the repo (e.g. ``borg mount :: /mnt``).
