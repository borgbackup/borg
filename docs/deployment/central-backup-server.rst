.. include:: ../global.rst.inc
.. highlight:: none

Central repository server with Ansible or Salt
==============================================

This section will give an example how to setup a borg repository server for multiple
clients.

Machines
--------

There are multiple machines used in this section and will further be named by their
respective fully qualified domain name (fqdn).

* The backup server: `backup01.srv.local`
* The clients:

  - John Doe's desktop: `johndoe.clnt.local`
  - Webserver 01: `web01.srv.local`
  - Application server 01: `app01.srv.local`

User and group
--------------

The repository server needs to have only one UNIX user for all the clients.
Recommended user and group with additional settings:

* User: `backup`
* Group: `backup`
* Shell: `/bin/bash` (or other capable to run the `borg serve` command)
* Home: `/home/backup`

Most clients shall initiate a backup from the root user to catch all
users, groups and permissions (e.g. when backing up `/home`).

Folders
-------

The following folder tree layout is suggested on the repository server:

* User home directory, /home/backup
* Repositories path (storage pool): /home/backup/repos
* Clients restricted paths (`/home/backup/repos/<client fqdn>`):

  - johndoe.clnt.local: `/home/backup/repos/johndoe.clnt.local`
  - web01.srv.local: `/home/backup/repos/web01.srv.local`
  - app01.srv.local: `/home/backup/repos/app01.srv.local`

Restrictions
------------

Borg is instructed to restrict clients into their own paths:
``borg serve --restrict-to-path /home/backup/repos/<client fqdn>``

The client will be able to access any file or subdirectory inside of ``/home/backup/repos/<client fqdn>``
but no other directories. You can allow a client to access several separate directories by passing multiple
``--restrict-to-path`` flags, for instance: ``borg serve --restrict-to-path /home/backup/repos/<client fqdn> --restrict-to-path /home/backup/repos/<other client fqdn>``,
which could make sense if multiple machines belong to one person which should then have access to all the
backups of their machines.

There is only one ssh key per client allowed. Keys are added for ``johndoe.clnt.local``, ``web01.srv.local`` and
``app01.srv.local``. But they will access the backup under only one UNIX user account as:
``backup@backup01.srv.local``. Every key in ``$HOME/.ssh/authorized_keys`` has a
forced command and restrictions applied as shown below:

::

  command="cd /home/backup/repos/<client fqdn>;
           borg serve --restrict-to-path /home/backup/repos/<client fqdn>",
           restrict <keytype> <key> <host>

.. note:: The text shown above needs to be written on a single line!

The options which are added to the key will perform the following:

1. Change working directory
2. Run ``borg serve`` restricted to the client base path
3. Restrict ssh and do not allow stuff which imposes a security risk

Due to the ``cd`` command we use, the server automatically changes the current
working directory. Then client doesn't need to have knowledge of the absolute
or relative remote repository path and can directly access the repositories at
``<user>@<host>:<repo>``.

.. note:: The setup above ignores all client given commandline parameters
          which are normally appended to the `borg serve` command.

Client
------

The client needs to initialize the `pictures` repository like this:

::

 borg init backup@backup01.srv.local:pictures

Or with the full path (should actually never be used, as only for demonstrational purposes).
The server should automatically change the current working directory to the `<client fqdn>` folder.

::

  borg init backup@backup01.srv.local:/home/backup/repos/johndoe.clnt.local/pictures

When `johndoe.clnt.local` tries to access a not restricted path the following error is raised.
John Doe tries to backup into the Web 01 path:

::

  borg init backup@backup01.srv.local:/home/backup/repos/web01.srv.local/pictures

::

  ~~~ SNIP ~~~
  Remote: borg.remote.PathNotAllowed: /home/backup/repos/web01.srv.local/pictures
  ~~~ SNIP ~~~
  Repository path not allowed

Ansible
-------

Ansible takes care of all the system-specific commands to add the user, create the
folder, install and configure software.

::

  - hosts: backup01.srv.local
    vars:
      user: backup
      group: backup
      home: /home/backup
      pool: "{{ home }}/repos"
      auth_users:
        - host: johndoe.clnt.local
          key: "{{ lookup('file', '/path/to/keys/johndoe.clnt.local.pub') }}"
        - host: web01.clnt.local
          key: "{{ lookup('file', '/path/to/keys/web01.clnt.local.pub') }}"
        - host: app01.clnt.local
          key: "{{ lookup('file', '/path/to/keys/app01.clnt.local.pub') }}"
    tasks:
    - package: name=borg state=present
    - group: name="{{ group }}" state=present
    - user: name="{{ user }}" shell=/bin/bash home="{{ home }}" createhome=yes group="{{ group }}" groups= state=present
    - file: path="{{ home }}" owner="{{ user }}" group="{{ group }}" mode=0700 state=directory
    - file: path="{{ home }}/.ssh" owner="{{ user }}" group="{{ group }}" mode=0700 state=directory
    - file: path="{{ pool }}" owner="{{ user }}" group="{{ group }}" mode=0700 state=directory
    - authorized_key: user="{{ user }}"
                      key="{{ item.key }}"
                      key_options='command="cd {{ pool }}/{{ item.host }};borg serve --restrict-to-path {{ pool }}/{{ item.host }}",restrict'
      with_items: "{{ auth_users }}"
    - file: path="{{ home }}/.ssh/authorized_keys" owner="{{ user }}" group="{{ group }}" mode=0600 state=file
    - file: path="{{ pool }}/{{ item.host }}" owner="{{ user }}" group="{{ group }}" mode=0700 state=directory
      with_items: "{{ auth_users }}"

Salt
----

This is a configuration similar to the one above, configured to be deployed with
Salt running on a Debian system.

::

  Install borg backup from pip:
    pkg.installed:
      - pkgs:
        - python3
        - python3-dev
        - python3-pip
        - python-virtualenv
        - libssl-dev
        - openssl
        - libacl1-dev
        - libacl1
        - build-essential
        - libfuse-dev
        - fuse
        - pkg-config
    pip.installed:
      - pkgs: ["borgbackup"]
      - bin_env: /usr/bin/pip3

  Setup backup user:
    user.present:
      - name: backup
      - fullname: Backup User
      - home: /home/backup
      - shell: /bin/bash
  # CAUTION!
  # If you change the ssh command= option below, it won't necessarily get pushed to the backup
  # server correctly unless you delete the ~/.ssh/authorized_keys file and re-create it!
  {% for host in backupclients %}
  Give backup access to {{host}}:
    ssh_auth.present:
      - user: backup
      - source: salt://conf/ssh-pubkeys/{{host}}-backup.id_ecdsa.pub
      - options:
        - command="cd /home/backup/repos/{{host}}; borg serve --restrict-to-path /home/backup/repos/{{host}}"
        - restrict
  {% endfor %}


Enhancements
------------

As this section only describes a simple and effective setup it could be further
enhanced when supporting (a limited set) of client supplied commands. A wrapper
for starting `borg serve` could be written. Or borg itself could be enhanced to
autodetect it runs under SSH by checking the `SSH_ORIGINAL_COMMAND` environment
variable. This is left open for future improvements.

When extending ssh autodetection in borg no external wrapper script is necessary
and no other interpreter or application has to be deployed.

See also
--------

* `SSH Daemon manpage <https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man8/sshd.8>`_
* `Ansible <https://docs.ansible.com>`_
* `Salt <https://docs.saltstack.com/>`_
