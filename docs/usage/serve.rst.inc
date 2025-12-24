.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_serve:

borg serve
----------
.. code-block:: none

    borg [common options] serve [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-path PATH``       | Restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all subdirectories is granted implicitly; PATH does not need to point directly to a repository.                                                                                                                                                                                                                                 |
    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-repository PATH`` | Restrict repository access. Only the repository located at PATH (no subdirectories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path``, subdirectories are not accessible; PATH must point directly to a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there. |
    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--permissions``                 | Set repository permission mode. Overrides BORG_REPO_PERMISSIONS environment variable.                                                                                                                                                                                                                                                                                                                                                                            |
    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
    +-------------------------------------------------------+-----------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --restrict-to-path PATH           Restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all subdirectories is granted implicitly; PATH does not need to point directly to a repository.
        --restrict-to-repository PATH     Restrict repository access. Only the repository located at PATH (no subdirectories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path``, subdirectories are not accessible; PATH must point directly to a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there.
        --permissions                     Set repository permission mode. Overrides BORG_REPO_PERMISSIONS environment variable.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command starts a repository server process.

`borg serve` currently supports:

- Being automatically started via SSH when the borg client uses an ssh://...
  remote repository. In this mode, `borg serve` will run until that SSH connection
  is terminated.

- Being started by some other means (not by the borg client) as a long-running socket
  server to be used for borg clients using a socket://... repository (see the `--socket`
  option if you do not want to use the default path for the socket and PID file).

Please note that `borg serve` does not support providing a specific repository via the
`--repo` option or the `BORG_REPO` environment variable. It is always the borg client that
specifies the repository to use when communicating with `borg serve`.

The --permissions option enforces repository permissions:

- `all`: All permissions are granted. (Default; the permissions system is not used.)
- `no-delete`: Allow reading and writing; disallow deleting and overwriting data.
  New archives can be created; existing archives cannot be deleted. New chunks can
  be added; existing chunks cannot be deleted or overwritten.
- `write-only`: Allow writing; disallow reading data.
  New archives can be created; existing archives cannot be read.
  New chunks can be added; existing chunks cannot be read, deleted, or overwritten.
- `read-only`: Allow reading; disallow writing or deleting data.
  Existing archives can be read, but no archives can be created or deleted.