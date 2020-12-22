Positional Arguments and Options: Order matters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Borg only supports taking options (``-s`` and ``--progress`` in the example)
to the left or right of all positional arguments (``repo::archive`` and ``path``
in the example), but not in between them:

::

    borg create -s --progress repo::archive path  # good and preferred
    borg create repo::archive path -s --progress  # also works
    borg create -s repo::archive path --progress  # works, but ugly
    borg create repo::archive -s --progress path  # BAD

This is due to a problem in the argparse module: https://bugs.python.org/issue15112
