Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` - filesystem path to repo directory, absolute path

``path/to/repo`` - filesystem path to repo directory, relative path

Also, stuff like ``~/path/to/repo`` or ``~other/path/to/repo`` works (this is
expanded by your shell).

Note: you may also prepend a ``file://`` to a filesystem path to get URL style.

**Remote repositories** accessed via ssh user@host:

``ssh://user@host:port/path/to/repo`` - remote repo, absolute path

**Remote repositories with relative paths** can be given using this syntax:

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

Converting from scp-style repo URLs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Borg does not support scp-style repo URLs any more.

Here is how you can convert to URL style:

::

    user@host:path/to/repo              # relative to cwd
    -->
    ssh://user@host:22/./path/to/repo   # relative to cwd
    or (usually the cwd is the home dir after ssh login)
    ssh://user@host:22/~/path/to/repo   # relative to home dir

    user@host:/path/to/repo             # absolute repo path
    -->
    ssh://user@host:22/path/to/repo     # absolute repo path

Notes:

Port 22 is the default, so you can omit the ``:22`` if you like.

If you used some hack to use a non-standard port (which was not directly
supported by the scp-style repo specification), you can now do it that way
with the ``ssh:`` URL and remove the hack (usually in ssh configuration or
given via ``--rsh`` borg option).
