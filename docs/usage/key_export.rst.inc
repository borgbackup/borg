.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_export:

borg key export
---------------
.. code-block:: none

    borg [common options] key export [options] [PATH]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                       |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    |                                                       | ``PATH``      | where to store the backup                                              |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    | **options**                                                                                                                                    |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    |                                                       | ``--paper``   | Create an export suitable for printing and later type-in               |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    |                                                       | ``--qr-html`` | Create an HTML file suitable for printing and later type-in or QR scan |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                 |
    |                                                                                                                                                |
    | :ref:`common_options`                                                                                                                          |
    +-------------------------------------------------------+---------------+------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    PATH
        where to store the backup


    options
        --paper       Create an export suitable for printing and later type-in
        --qr-html     Create an HTML file suitable for printing and later type-in or QR scan


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command backs up the borg key.

If repository encryption is used, the repository is inaccessible
without the borg key (and the passphrase that protects the borg key).
If a repository is not encrypted, but authenticated, the borg key is
still needed to access the repository normally.

For repositories using **keyfile** encryption the key is kept locally
on the system that is capable of doing backups. To guard against loss
or corruption of this key, the key needs to be backed up independently
of the main data backup.

For repositories using **repokey** encryption or **authenticated** mode
the key is kept in the repository. A backup is thus not strictly needed,
but guards against the repository becoming inaccessible if the key is
corrupted or lost.

Note that the backup produced does not include the passphrase itself
(i.e. the exported key stays encrypted). In order to regain access to a
repository, one needs both the exported key and the original passphrase.
Keep the exported key and the passphrase at safe places.

There are three backup formats. The normal backup format is suitable for
digital storage as a file. The ``--paper`` backup format is optimized
for printing and typing in while importing, with per line checks to
reduce problems with manual input. The ``--qr-html`` creates a printable
HTML template with a QR code and a copy of the ``--paper``-formatted key.