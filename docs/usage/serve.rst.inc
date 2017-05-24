.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_serve:

borg serve
----------
::

    borg [common options] serve <options>

optional arguments
    ``--restrict-to-path PATH``
        | restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all sub-directories is granted implicitly; PATH doesn't need to directly point to a repository.
    ``--append-only``
        | only allow appending to repository segment files
    ``--storage-quota``
        | Override storage quota of the repository (e.g. 5G, 1.5T). When a new repository is initialized, sets the storage quota on the new repository as well. Default: no quota.

`Common options`_
    |

Description
~~~~~~~~~~~

This command starts a repository server process. This command is usually not used manually.