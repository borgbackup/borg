Debugging Facilities
--------------------

There is a ``borg debug`` command that has some subcommands which are all
**not intended for normal use** and **potentially very dangerous** if used incorrectly.

For example, ``borg debug put-obj`` and ``borg debug delete-obj`` will only do
what their name suggests: put objects into repo / delete objects from repo.

Please note:

- they will not update the chunks cache (chunks index) about the object
- they will not update the manifest (so no automatic chunks index resync is triggered)
- they will not check whether the object is in use (e.g. before delete-obj)
- they will not update any metadata which may point to the object

They exist to improve debugging capabilities without direct system access, e.g.
in case you ever run into some severe malfunction. Use them only if you know
what you are doing or if a trusted Borg developer tells you what to do.

Borg has a ``--debug-topic TOPIC`` option to enable specific debugging messages. Topics
are generally not documented.

A ``--debug-profile FILE`` option exists which writes a profile of the main program's
execution to a file. The format of these files is not directly compatible with the
Python profiling tools, since these use the "marshal" format, which is not intended
to be secure (quoting the Python docs: "Never unmarshal data received from an untrusted
or unauthenticated source.").

The ``borg debug profile-convert`` command can be used to take a Borg profile and convert
it to a profile file that is compatible with the Python tools.

Additionally, if the filename specified for ``--debug-profile`` ends with ".pyprof" a
Python compatible profile is generated. This is only intended for local use by developers.
