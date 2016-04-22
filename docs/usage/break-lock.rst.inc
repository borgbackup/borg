.. _borg_break-lock:

borg break-lock
---------------
::

    borg break-lock <options> REPOSITORY

positional arguments
    REPOSITORY
        repository for which to break the locks

`Common options`_
    |

Description
~~~~~~~~~~~

This command breaks the repository and cache locks.
Please use carefully and only while no borg process (on any machine) is
trying to access the Cache or the Repository.
