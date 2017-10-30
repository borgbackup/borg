.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_serve:

borg serve
----------
.. code-block:: none

    borg [common options] serve [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-path PATH``       | restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all sub-directories is granted implicitly; PATH doesn't need to directly point to a repository.                                                                                                                                                                                                                                      |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-repository PATH`` | restrict repository access. Only the repository located at PATH (no sub-directories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path`` sub-directories are not accessible; PATH needs to directly point at a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there. |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--append-only``                 | only allow appending to repository segment files                                                                                                                                                                                                                                                                                                                                                                                                                      |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--storage-quota QUOTA``         | Override storage quota of the repository (e.g. 5G, 1.5T). When a new repository is initialized, sets the storage quota on the new repository as well. Default: no quota.                                                                                                                                                                                                                                                                                              |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --restrict-to-path PATH    restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all sub-directories is granted implicitly; PATH doesn't need to directly point to a repository.
        --restrict-to-repository PATH    restrict repository access. Only the repository located at PATH (no sub-directories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path`` sub-directories are not accessible; PATH needs to directly point at a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there.
        --append-only             only allow appending to repository segment files
        --storage-quota QUOTA     Override storage quota of the repository (e.g. 5G, 1.5T). When a new repository is initialized, sets the storage quota on the new repository as well. Default: no quota.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command starts a repository server process. This command is usually not used manually.