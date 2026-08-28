Repository URLs
~~~~~~~~~~~~~~~

**Local filesystem** (or locally mounted network filesystem):

``/path/to/repo`` — filesystem path to the repository directory (absolute path)

``path/to/repo`` — filesystem path to the repository directory (relative path)

Also, paths like ``~/path/to/repo`` or ``~other/path/to/repo`` work (this is
expanded by your shell).

Note: You may also prepend ``file://`` to a filesystem path to use URL style.

Note: UNC paths (``//server/share/path``, ``\\server\share\path``) are not
supported — mount the share (on Windows: map it to a drive letter, e.g.
``net use X: \\server\share``) and use the mounted path instead.

**Remote repositories** accessed via SSH user@host (REST http over stdio):

``rest://user@host:port//abs/path/to/repo`` — absolute path

``rest://user@host:port/rel/path/to/repo`` — path relative to the remote login directory

**Remote repositories** accessed via SSH user@host (legacy borg RPC protocol):

``ssh://user@host:port//abs/path/to/repo`` — absolute path

``ssh://user@host:port/rel/path/to/repo`` — path relative to the remote login directory

**Remote repositories** accessed via SFTP:

``sftp://user@host:port//abs/path/to/repo`` — absolute path

``sftp://user@host:port/rel/path/to/repo`` — path relative to the remote login directory

For REST, SSH and SFTP URLs, the ``user@`` and ``:port`` parts are optional, but the
path is required: a URL without one, e.g. ``rest://host`` or ``rest://host/``, is
rejected. Mind the difference between one and two slashes after the host: one slash
means a path relative to the directory the remote login lands in (usually the remote
user's home directory), two slashes mean an absolute path.

**Remote repositories** accessed via rclone:

``rclone:remote:path`` — see the rclone docs for more details about ``remote:path``.

**Remote repositories** accessed via S3:

``(s3|b2):[(profile|(access_key_id:access_key_secret))@][scheme://hostname[:port]]/bucket/path`` — see the boto3 docs for more details about credentials.

If you are connecting to AWS S3, ``[schema://hostname[:port]]`` is optional, but ``bucket`` and ``path`` are always required.
`scheme` is usually `https` here, hostname and optional port refer to your S3/B2 server, if that is not Amazon's.

Note: There is a known issue with some S3-compatible services, e.g., Backblaze B2. If you encounter problems, try using ``b2:`` instead of ``s3:`` in the URL.


If you frequently need the same repository URL, it is a good idea to set the
``BORG_REPO`` environment variable to set a default repository URL:

::

    export BORG_REPO='rest://user@host:port/rel/path/to/repo'

Then simply omit the ``--repo`` option when you want
to use the default — it will be read from BORG_REPO.
