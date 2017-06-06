.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_migrate-to-repokey:

borg key migrate-to-repokey
---------------------------
.. code-block:: none

    borg [common options] key migrate-to-repokey [options] REPOSITORY

positional arguments
    REPOSITORY


:ref:`common_options`
    |

Description
~~~~~~~~~~~

This command migrates a repository from passphrase mode (removed in Borg 1.0)
to repokey mode.

You will be first asked for the repository passphrase (to open it in passphrase
mode). This is the same passphrase as you used to use for this repo before 1.0.

It will then derive the different secrets from this passphrase.

Then you will be asked for a new passphrase (twice, for safety). This
passphrase will be used to protect the repokey (which contains these same
secrets in encrypted form). You may use the same passphrase as you used to
use, but you may also use a different one.

After migrating to repokey mode, you can change the passphrase at any time.
But please note: the secrets will always stay the same and they could always
be derived from your (old) passphrase-mode passphrase.