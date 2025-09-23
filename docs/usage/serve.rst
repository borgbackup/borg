.. include:: serve.rst.inc

Examples
~~~~~~~~

``borg serve`` has special support for ssh forced commands (see ``authorized_keys``
example below): if the environment variable SSH_ORIGINAL_COMMAND is set it will
ignore some options given on the command line and use the values from the
variable instead. This only applies to a carefully controlled allowlist of safe
options. This list currently contains:

- Options that control the log level and debug topics printed
  such as ``--verbose``, ``--info``, ``--debug``, ``--debug-topic``, etc.
- ``--lock-wait`` to allow the client to control how long to wait before
  giving up and aborting the operation when another process is holding a lock.

Environment variables (such as BORG_XXX) contained in the original
command sent by the client are *not* interpreted, but ignored. If BORG_XXX environment
variables should be set on the ``borg serve`` side, then these must be set in system-specific
locations like ``/etc/environment`` or in the forced command itself (example below).

::

    # Allow an SSH keypair to run only borg, and only have access to /path/to/repo.
    # Use key options to disable unneeded and potentially dangerous SSH functionality.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /path/to/repo",restrict ssh-rsa AAAAB3[...]

    # Specify repository permissions for an SSH keypair.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --permissions=read-only",restrict ssh-rsa AAAAB3[...]

    # Set a BORG_XXX environment variable on the "borg serve" side
    $ cat ~/.ssh/authorized_keys
    command="BORG_XXX=value borg serve [...]",restrict ssh-rsa [...]

.. note::
    The examples above use the ``restrict`` directive and assume a POSIX
    compliant shell set as the user's login shell.
    This automatically blocks potentially dangerous SSH features, even when
    they are added in a future update. Thus, this option should be preferred.

    If you are using OpenSSH server < 7.2, however, you must explicitly
    specify the SSH features to restrict and cannot simply use the ``restrict`` option, as it
    was introduced in v7.2. We recommend using
    ``no-port-forwarding,no-X11-forwarding,no-pty,no-agent-forwarding,no-user-rc``
    in this case.

Details about sshd usage: `sshd(8) <https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/sshd.8>`_

.. _ssh_configuration:

SSH Configuration
~~~~~~~~~~~~~~~~~

``borg serve``'s pipes (``stdin``/``stdout``/``stderr``) are connected to the ``sshd`` process on the server side. In the event that the SSH connection between ``borg serve`` and the client is disconnected or stuck abnormally (for example, due to a network outage), it can take a long time for ``sshd`` to notice the client is disconnected. In the meantime, ``sshd`` continues running, and as a result so does the ``borg serve`` process holding the lock on the repository. This can cause subsequent ``borg`` operations on the remote repository to fail with the error: ``Failed to create/acquire the lock``.

To avoid this, it is recommended to perform the following additional SSH configuration:

Either in the client-side ``~/.ssh/config`` file or in the client's ``/etc/ssh/ssh_config`` file:
::

    Host backupserver
            ServerAliveInterval 10
            ServerAliveCountMax 30

Replacing ``backupserver`` with the hostname, FQDN or IP address of the borg server.

This will cause the client to send a keepalive to the server every 10 seconds. If 30 consecutive keepalives are sent without a response (a time of 300 seconds), the SSH client process will be terminated, causing the borg process to terminate gracefully.

In the server-side ``sshd`` configuration file (typically ``/etc/ssh/sshd_config``):
::

    ClientAliveInterval 10
    ClientAliveCountMax 30

This will cause the server to send a keepalive to the client every 10 seconds. If 30 consecutive keepalives are sent without a response (a time of 300 seconds), the server's sshd process will be terminated, causing the ``borg serve`` process to terminate gracefully and release the lock on the repository.

If you then run borg commands with ``--lock-wait 600``, this gives sufficient time for the borg serve processes to terminate after the SSH connection is torn down after the 300 second wait for the keepalives to fail.

You may, of course, modify the timeout values demonstrated above to values that suit your environment and use case.

When the client is untrusted, it is a good idea to set the backup
user's shell to a simple implementation (``/bin/sh`` is only an example and may or may
not be such a simple implementation)::

  chsh -s /bin/sh BORGUSER

Because the configured shell is used by `OpenSSH <https://www.openssh.com/>`_
to execute the command configured through the ``authorized_keys`` file
using ``"$SHELL" -c "$COMMAND"``,
setting a minimal shell implementation reduces the attack surface
compared to when a feature-rich and complex shell implementation is
used.
