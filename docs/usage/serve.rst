.. include:: serve.rst.inc

Examples
~~~~~~~~

borg serve has special support for ssh forced commands (see ``authorized_keys``
example below): it will detect that you use such a forced command and extract
the value of the ``--restrict-to-path`` option(s).

It will then parse the original command that came from the client, makes sure
that it is also ``borg serve`` and enforce path restriction(s) as given by the
forced command. That way, other options given by the client (like ``--info`` or
``--umask``) are preserved (and are not fixed by the forced command).

Environment variables (such as BORG_HOSTNAME_IS_UNIQUE) contained in the original
command sent by the client are *not* interpreted, but ignored. If BORG_XXX environment
variables should be set on the ``borg serve`` side, then these must be set in system-specific
locations like ``/etc/environment`` or in the forced command itself (example below).

::

    # Allow an SSH keypair to only run borg, and only have access to /path/to/repo.
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
    
    If you're using openssh-server < 7.2, however, you have to explicitly specify
    the ssh features to restrict and cannot simply use the restrict option as it
    has been introduced in v7.2. We recommend to use
    ``no-port-forwarding,no-X11-forwarding,no-pty,no-agent-forwarding,no-user-rc``
    in this case.
