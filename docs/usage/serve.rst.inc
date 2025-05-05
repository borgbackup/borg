.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_serve:

borg serve
----------
.. code-block:: none

    borg [common options] serve [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-path PATH``       | restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all sub-directories is granted implicitly; PATH doesn't need to point directly to a repository.                                                                                                                                                                                                                                      |
    +-------------------------------------------------------+-----------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--restrict-to-repository PATH`` | restrict repository access. Only the repository located at PATH (no sub-directories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path`` sub-directories are not accessible; PATH needs to point directly at a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there. |
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



    options
        --restrict-to-path PATH           restrict repository access to PATH. Can be specified multiple times to allow the client access to several directories. Access to all sub-directories is granted implicitly; PATH doesn't need to point directly to a repository.
        --restrict-to-repository PATH     restrict repository access. Only the repository located at PATH (no sub-directories are considered) is accessible. Can be specified multiple times to allow the client access to several repositories. Unlike ``--restrict-to-path`` sub-directories are not accessible; PATH needs to point directly at a repository location. PATH may be an empty directory or the last element of PATH may not exist, in which case the client may initialize a repository there.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command starts a repository server process.

borg serve can currently support:

- Getting automatically started via ssh when the borg client uses a ssh://...
  remote repository. In this mode, `borg serve` will live until that ssh connection
  gets terminated.

- Getting started by some other means (not by the borg client) as a long-running socket
  server to be used for borg clients using a socket://... repository (see the `--socket`
  option if you do not want to use the default path for the socket and pid file).

Please note that `borg serve` does not support giving a specific repository via the
`--repo` option or `BORG_REPO` environment variable. It is always the borg client which
specifies the repo to use when talking to `borg serve`.