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

    # Set a BORG_XXX environment variable on the "borg serve" side
    $ cat ~/.ssh/authorized_keys
    command="export BORG_XXX=value; borg serve [...]",restrict ssh-rsa [...]

.. note::
    The examples above use the ``restrict`` directive. This does automatically
    block potential dangerous ssh features, even when they are added in a future
    update. Thus, this option should be preferred.
    
    If you're using openssh-server < 7.2, however, you have to specify explicitly
    the ssh features to restrict and cannot simply use the restrict option as it
    has been introduced in v7.2. We recommend to use
    ``no-port-forwarding,no-X11-forwarding,no-pty,no-agent-forwarding,no-user-rc``
    in this case.

Details about sshd usage: `sshd(8) <https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/sshd.8>`_

.. _ssh_configuration:

SSH Configuration
~~~~~~~~~~~~~~~~~
``borg serve``'s pipes (``stdin``/``stdout``/``stderr``) are connected to the ``sshd`` process on the server side. In the event that the SSH connection between ``borg serve`` and the client is disconnected or stuck abnormally (for example, due to a network outage), it can take a long time for ``sshd`` to notice the client is disconnected. In the meantime, ``sshd`` continues running, and as a result so does the ``borg serve`` process holding the lock on the repository. This can cause subsequent ``borg`` operations on the remote repository to fail with the error: ``Failed to create/acquire the lock``.

In order to avoid this, it is recommended to perform the following additional SSH configuration:

Either in the client side's ``~/.ssh/config`` file, or in the client's ``/etc/ssh/ssh_config`` file:
::

    Host backupserver
            ServerAliveInterval 10
            ServerAliveCountMax 30

Replacing ``backupserver`` with the hostname, FQDN or IP address of the borg server.

This will cause the client to send a keepalive to the server every 10 seconds. If 30 consecutive keepalives are sent without a response (a time of 300 seconds), the ssh client process will be terminated, causing the borg process to terminate gracefully.

On the server side's ``sshd`` configuration file (typically ``/etc/ssh/sshd_config``):
::

    ClientAliveInterval 10
    ClientAliveCountMax 30

This will cause the server to send a keep alive to the client every 10 seconds. If 30 consecutive keepalives are sent without a response (a time of 300 seconds), the server's sshd process will be terminated, causing the ``borg serve`` process to terminate gracefully and release the lock on the repository.

If you then run borg commands with ``--lock-wait 600``, this gives sufficient time for the borg serve processes to terminate after the SSH connection is torn down after the 300 second wait for the keepalives to fail.

You may, of course, modify the timeout values demonstrated above to values that suit your environment and use case.
