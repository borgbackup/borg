Positional Arguments and Options: Order matters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Borg only supports taking options (``-s`` and ``--progress`` in the example)
to the left or right of all positional arguments (``repo::archive`` and ``path``
in the example), but not in between them:

::

    borg create -s --progress archive path  # good and preferred
    borg create archive path -s --progress  # also works
    borg create -s archive path --progress  # works, but ugly
    borg create archive -s --progress path  # BAD

This is due to a problem in the argparse module: https://bugs.python.org/issue15112
