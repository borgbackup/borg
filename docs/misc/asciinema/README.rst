The borg 1.4 demo screencast
============================

The screencast linked from our README and website is not recorded by hand:
``demo.tcl`` is "typed" into a shell by expect_, while asciinema_ records the
result. So, when borg's output changes, we just record it again.

Do **not** run these scripts directly on your machine: they create users,
mount filesystems and write to ``/media``. They are meant to run inside the
container defined by ``Containerfile``.

Recording
---------

::

    ./record.sh [output directory]     # uses podman, set ENGINE=docker for docker

This exports the borg sources of the git tag given by ``BORG_VERSION`` at the
top of ``record.sh``, builds borg from them in a container, generates the demo
data and records the screencast to ``borg14-demo.cast``. So, for a new release,
set ``BORG_VERSION`` to its tag (after tagging it) and record again.

While working on the demo itself, you can also record from your work tree::

    BORG_VERSION=HEAD ./record.sh

Then have a look at it and upload it::

    asciinema play borg14-demo.cast
    asciinema upload borg14-demo.cast

Afterwards, update the links in ``README.rst`` (in the repository root) and on
borgbackup.org to point to the new screencast.

Editing the demo
----------------

``demo.tcl`` contains the commands and comments that get typed, in the order
they appear in the screencast. Keep the typed lines below ~95 characters, the
recording uses a 100x30 terminal (see ``record.exp``).

The lines we type are colored by ``type_line`` (comments, commands, options),
see the ``color`` array at the top of ``demo.tcl`` if you want other colors.
The output of the commands is not touched, it looks like in your terminal.

``demo-data.py`` generates the data that gets backed up: compressible, but not
trivially repetitive, so that both compression and deduplication show
realistic numbers (see #6303).

The borg 2.0 branch has the same setup, recording ``borg2-demo.cast`` with the
borg 2 command syntax. Keep the two demos in sync where the syntax allows it.

Known quirks
------------

``borg extract`` runs with ``--noxattrs``: when recording with rootless podman
on a SELinux host, restoring the ``security.selinux`` xattrs of the demo data
is not permitted, and the warnings about it would show up in the screencast.

.. _expect: https://core.tcl-lang.org/expect/index
.. _asciinema: https://asciinema.org/
