.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_add:

borg key add
------------
.. code-block:: none

    borg [common options] key add [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                             |
    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--label LABEL``         | label for the new borg key (must be unique)                                                                                                                                                                                                                                         |
    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--fido2-device DEVICE`` | protect the new borg key with a FIDO2 token's hmac-secret instead of a passphrase. DEVICE is a platform device identifier (see ``fido2-token -L``); when omitted, the single plugged-in FIDO2 device is used.                                                                       |
    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--fido2-touch``         | whether unlocking with the new FIDO2 borg key requires a touch (user presence) on the token (default: yes). 'no' requires a token that supports touchless hmac-secret derivation (the CTAP spec forbids it, so most tokens, e.g. YubiKeys, refuse); this is verified at enrollment. |
    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                          |
    |                                                                                                                                                                                                                                                                                                                                                                         |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --label LABEL     label for the new borg key (must be unique)
        --fido2-device DEVICE    protect the new borg key with a FIDO2 token's hmac-secret instead of a passphrase. DEVICE is a platform device identifier (see ``fido2-token -L``); when omitted, the single plugged-in FIDO2 device is used.
        --fido2-touch     whether unlocking with the new FIDO2 borg key requires a touch (user presence) on the token (default: yes). 'no' requires a token that supports touchless hmac-secret derivation (the CTAP spec forbids it, so most tokens, e.g. YubiKeys, refuse); this is verified at enrollment.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

A repository can be protected by more than one borg key. Each borg key contains the
same secret key material, but is protected independently - by its own passphrase, or
by a FIDO2 hardware token - and any of them can be used to unlock the same repository.
This is useful e.g. to give individual users their own passphrase while keeping a
separate admin/recovery passphrase.

This command adds an additional borg key. It does not re-encrypt any repository data
and does not change the existing borg keys. The new passphrase is read from
``BORG_NEW_PASSPHRASE`` or queried interactively.

With ``--fido2-device``, the new borg key is protected by a FIDO2 token's hmac-secret
instead of a passphrase: the token holds a device-bound secret that is needed to
unlock this borg key, so the key blob is useless without the plugged-in token.
Enrollment needs two touches on the token (create the credential, then derive the
secret once). If the token has a PIN or built-in user verification configured, it is
also required - both at enrollment and at every unlock. Without ``DEVICE``, the single
plugged-in FIDO2 device is used; with several devices plugged in, one must be selected
explicitly (``fido2-token -L`` lists devices). At unlock time, the matching token is
found automatically among the plugged-in devices (``BORG_FIDO2_DEVICE`` pins one).

``--fido2-touch=no`` stores a borg key that unlocks without a touch on the token
(useful for unattended backups; the key is then bound to the plugged-in device, but
not presence-gated). Note that the CTAP specification requires tokens to refuse
touchless hmac-secret derivation and most (e.g. YubiKeys) do - only tokens deviating
from the spec on this point support it. That is verified at enrollment, which fails
cleanly in that case.

Note that a repository is only as secure as its *weakest* borg key: adding a FIDO2 key
does not strengthen a weak or empty admin passphrase. The admin key is the recovery
path if the token is lost - treat it like one.

Each borg key has a label. The first borg key, created at repository creation time, has
the reserved label ``admin`` and is protected from deletion. Additionally added borg
keys require a unique, user-defined ``--label``.