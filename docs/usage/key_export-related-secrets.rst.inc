.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_export-related-secrets:

borg key export-related-secrets
-------------------------------
.. code-block:: none

    borg [common options] key export-related-secrets [options] [REPOSITORY] [PATH]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+----------------+----------------------------+
    | **positional arguments**                                                                            |
    +-------------------------------------------------------+----------------+----------------------------+
    |                                                       | ``REPOSITORY`` |                            |
    +-------------------------------------------------------+----------------+----------------------------+
    |                                                       | ``PATH``       | where to store the secrets |
    +-------------------------------------------------------+----------------+----------------------------+
    | .. class:: borg-common-opt-ref                                                                      |
    |                                                                                                     |
    | :ref:`common_options`                                                                               |
    +-------------------------------------------------------+----------------+----------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY

    PATH
        where to store the secrets


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command exports the deduplication secrets (``id_key`` and ``chunk_seed``)
of a repository. These secrets can be used to initialize a **related repository**.

Related repositories share the same deduplication metadata but have their own
independent encryption keys. This is useful for:

1. Creating independent backup targets that still benefit from being
   "compatible" for future archive transfers.
2. Preparing for a migration to Borg 2.0, where archives can be transferred
   between related repositories using ``borg transfer``.

The exported secrets are stored in a JSON file. This file contains sensitive
information and should be deleted immediately after usage.

Examples::

    # Export secrets from an existing repository
    $ borg key export-related-secrets /path/to/repo1 secrets.json

    # Initialize a new related repository using these secrets
    $ borg init --import-related-secrets=secrets.json --encryption=repokey /path/to/repo2
    $ rm secrets.json

.. IMPORTANT::
   When initializing a related repository using ``borg init --import-related-secrets``,
   the new repository must use the same ID hash algorithm (either both HMAC-SHA256
   or both BLAKE2) as the original repository.

   - HMAC-SHA256: ``repokey``, ``keyfile``, ``authenticated``
   - BLAKE2: ``repokey-blake2``, ``keyfile-blake2``, ``authenticated-blake2``

.. WARNING::
   Please note that future Borg 2.0 versions might remove support for BLAKE2
   in new repositories (see :issue:`8867`).