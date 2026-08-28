.. include:: ../global.rst.inc
.. highlight:: none
.. _hosting_repositories:

Hosting repositories
====================

This section shows how to provide repository storage securely for users.

Repositories are accessed through SSH. Each user of the service should
have their own login, which is only able to access that user's files.
Technically, it is possible to have multiple users share one login;
however, separating them is better. Separate logins increase isolation
and provide an additional layer of security and safety for both the
provider and the users.

For example, if a user manages to breach ``borg serve``, they can
only damage their own data (assuming that the system does not have further
vulnerabilities).

Use the standard directory structure of the operating system. Each user
is assigned a home directory, and that user's repositories reside in their
home directory.

The following ``~user/.ssh/authorized_keys`` file is the most important
piece for a correct deployment. It allows the user to log in via
their public key (which must be provided by the user), and restricts
SSH access to safe operations only.

::

  command="borg serve --rest --restrict-to-repository /home/<user>/repository",restrict
  <key type> <key> <key host>

.. note:: The text shown above needs to be written on a **single** line!

.. warning::

    If this file should be automatically updated (e.g. by a web console),
    pay **utmost attention** to sanitizing user input. Strip all whitespace
    around the user-supplied key, ensure that it **only** contains ASCII
    with no control characters and that it consists of three parts separated
    by a single space. Ensure that no newlines are contained within the key.

The ``restrict`` keyword enables all restrictions, i.e. disables port, agent
and X11 forwarding, as well as disabling PTY allocation and execution of ~/.ssh/rc.
If any future restriction capabilities are added to authorized_keys
files they will be included in this set.

The ``command`` keyword forces execution of the specified command
upon login. This must be ``borg serve --rest``: ``--rest`` serves a current
repository (the server side of a ``rest://`` repository URL), while ``borg serve``
without it serves a legacy borg 1.x repository using the legacy RPC protocol.
The client cannot supply ``--rest`` itself - the mode is deliberately pinned by
the forced command - so a forced command without ``--rest`` locks out all clients
using current (``rest://``) repositories.

The ``--restrict-to-repository`` option permits access to exactly **one**
repository. It can be given multiple times to permit access to more than
one repository. Alternatively, ``--restrict-to-path`` permits access to every
repository below a directory.

The repository may not exist yet; it can be created by the user with
``borg repo-create``, which allows for encryption.

The forced command does not name a repository - the client does. The client
appends ``--backend FILE:<path>`` to the ``borg serve --rest`` command line it
wants to run; sshd hands that command line to the server in the
``SSH_ORIGINAL_COMMAND`` environment variable, and ``borg serve`` takes the
requested backend path from there and checks it against
``--restrict-to-repository`` and ``--restrict-to-path``. If the requested path
is not allowed, the server terminates with exit code 83 (``PathNotAllowed``).
Apart from the log level, the lock wait time and debug topics, everything else
the client requests is ignored, so the serve mode and the restrictions always
come from the forced command.

The user therefore selects the repository through the path in the repository
URL::

  borg -r rest://<user>@<host>/repository repo-list

A path with a single leading slash is relative to the directory ssh logs into
(the user's home directory), so with the forced command shown above,
``rest://<user>@<host>/repository`` and
``rest://<user>@<host>//home/<user>/repository`` address the same repository.

Refer to the `sshd(8) <https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/sshd.8>`_
man page for more details on SSH options.
See also :ref:`borg_serve`
