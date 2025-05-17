Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` - filesystem path to repo directory, absolute path

``path/to/repo`` - filesystem path to repo directory, relative path

Also, stuff like ``~/path/to/repo`` or ``~other/path/to/repo`` works (this is
expanded by your shell).

Note: you may also prepend a ``file://`` to a filesystem path to get URL style.

**Remote repositories** accessed via ssh user@host:

``ssh://user@host:port//abs/path/to/repo`` - absolute path

``ssh://user@host:port/rel/path/to/repo`` - path relative to current directory

**Remote repositories** accessed via sftp:

``sftp://user@host:port//abs/path/to/repo`` - absolute path

``sftp://user@host:port/rel/path/to/repo`` - path relative to current directory

For ssh and sftp URLs, the ``user@`` and ``:port`` parts are optional.

**Remote repositories** accessed via rclone:

``rclone:remote:path`` - see the rclone docs for more details about remote:path.

**Remote repositories** accessed via S3:

``(s3|b2):[profile|(access_key_id:access_key_secret)@][schema://hostname[:port]]/bucket/path`` - see the boto3 docs for more details about the credentials.

If you're connecting to AWS S3, ``[schema://hostname[:port]]`` is optional, but ``bucket`` and ``path`` are always required.

Note: There is a known issue with some S3-compatible services, e.g., Backblaze B2. If you encounter problems, try using ``b2:`` instead of ``s3:`` in the url.


If you frequently need the same repo URL, it is a good idea to set the
``BORG_REPO`` environment variable to set a default for the repo URL:

::

    export BORG_REPO='ssh://user@host:port/rel/path/to/repo'

Then just leave away the ``--repo`` option if you want
to use the default - it will be read from BORG_REPO then.
