.. include:: ../global.rst.inc
.. highlight:: none

Hosting repositories
====================

This sections shows how to securely provide repository storage for users.
Optionally, each user can have a storage quota.

Repositories are accessed through SSH. Each user of the service should
have her own login which is only able to access the user's files.
Technically it would be possible to have multiple users share one login,
however, separating them is better. Separate logins increase isolation
and are thus an additional layer of security and safety for both the
provider and the users.

For example, if a user manages to breach ``borg serve`` then she can
only damage her own data (assuming that the system does not have further
vulnerabilities).

Use the standard directory structure of the operating system. Each user
is assigned a home directory and repositories of the user reside in her
home directory.

The following ``~user/.ssh/authorized_keys`` file is the most important
piece for a correct deployment. It allows the user to login via
their public key (which must be provided by the user), and restricts
SSH access to safe operations only.

::

  restrict,command="borg serve --restrict-to-repository /home/<user>/repository"
  <key type> <key> <key host>

.. note:: The text shown above needs to be written on a **single** line!

.. warning::

	If this file should be automatically updated (e.g. by a web console),
	pay **utmost attention** to sanitizing user input. Strip all whitespace
	around the user-supplied key, ensure that it **only** contains ASCII
	with no control characters and that it consists of three parts separated
	by a single space. Ensure that no newlines are contained within the key.

The `restrict` keyword enables all restrictions, i.e. disables port, agent
and X11 forwarding, as well as disabling PTY allocation and execution of ~/.ssh/rc.
If any future restriction capabilities are added to authorized_keys
files they will be included in this set.

The `command` keyword forces execution of the specified command line
upon login. This must be ``borg serve``. The `--restrict-to-repository`
option permits access to exactly **one** repository. It can be given
multiple times to permit access to more than one repository.

The repository may not exist yet; it can be initialized by the user,
which allows for encryption.

**Storage quotas** can be enabled by adding the ``--storage-quota`` option
to the ``borg serve`` command line::

	restrict,command="borg serve --storage-quota 20G ..." ...

The storage quotas of repositories are completely independent. If a
client is able to access multiple repositories, each repository
can be filled to the specified quota.

If storage quotas are used, ensure that all deployed Borg releases
support storage quotas.

Refer to :ref:`internals_storage_quota` for more details on storage quotas.

Refer to the `sshd(8) <http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/sshd.8>`_
man page for more details on SSH options.
