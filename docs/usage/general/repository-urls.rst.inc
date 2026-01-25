Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` — filesystem path to the repository directory (absolute path)

``path/to/repo`` — filesystem path to the repository directory (relative path)

Also, paths like ``~/path/to/repo`` or ``~other/path/to/repo`` work (this is
expanded by your shell).

Note: You may also prepend ``file://`` to a filesystem path to use URL style.

**Remote repositories** accessed via SSH user@host:

``ssh://user@host:port//abs/path/to/repo`` — absolute path

``ssh://user@host:port/rel/path/to/repo`` — path relative to the current directory

**Remote repositories** accessed via SFTP:

``sftp://user@host:port//abs/path/to/repo`` — absolute path

``sftp://user@host:port/rel/path/to/repo`` — path relative to the current directory

For SSH and SFTP URLs, the ``user@`` and ``:port`` parts are optional.

**Remote repositories** accessed via rclone:

``rclone:remote:path`` — see the rclone docs for more details about ``remote:path``.

**Remote repositories** accessed via S3:

``(s3|b2):[profile|(access_key_id:access_key_secret)@][schema://hostname[:port]]/bucket/path`` — see the boto3 docs for more details about credentials.

If you are connecting to AWS S3, ``[schema://hostname[:port]]`` is optional, but ``bucket`` and ``path`` are always required.

Note: There is a known issue with some S3-compatible services, e.g., Backblaze B2. If you encounter problems, try using ``b2:`` instead of ``s3:`` in the URL.



If you frequently need the same repository URL, it is a good idea to set the
``BORG_REPO`` environment variable to set a default repository URL:

::

    export BORG_REPO='ssh://user@host:port/rel/path/to/repo'

Then simply omit the ``--repo`` option when you want
to use the default — it will be read from BORG_REPO.
