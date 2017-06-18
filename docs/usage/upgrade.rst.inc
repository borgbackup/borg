.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_upgrade:

borg upgrade
------------
.. code-block:: none

    borg [common options] upgrade [options] REPOSITORY

positional arguments
    REPOSITORY
        path to the repository to be upgraded

optional arguments
    ``-n``, ``--dry-run``
        | do not change repository
    ``--inplace``
        | rewrite repository in place, with no chance of going back to older
        |                                versions of the repository.
    ``--force``
        | Force upgrade
    ``--tam``
        | Enable manifest authentication (in key and cache) (Borg 1.0.9 and later)
    ``--disable-tam``
        | Disable manifest authentication (in key and cache)

:ref:`common_options`
    |

Description
~~~~~~~~~~~

Upgrade an existing, local Borg repository.

When you do not need borg upgrade
+++++++++++++++++++++++++++++++++

Not every change requires that you run ``borg upgrade``.

You do **not** need to run it when:

- moving your repository to a different place
- upgrading to another point release (like 1.0.x to 1.0.y),
  except when noted otherwise in the changelog
- upgrading from 1.0.x to 1.1.x,
  except when noted otherwise in the changelog

Borg 1.x.y upgrades
+++++++++++++++++++

Use ``borg upgrade --tam REPO`` to require manifest authentication
introduced with Borg 1.0.9 to address security issues. This means
that modifying the repository after doing this with a version prior
to 1.0.9 will raise a validation error, so only perform this upgrade
after updating all clients using the repository to 1.0.9 or newer.

This upgrade should be done on each client for safety reasons.

If a repository is accidentally modified with a pre-1.0.9 client after
this upgrade, use ``borg upgrade --tam --force REPO`` to remedy it.

If you routinely do this you might not want to enable this upgrade
(which will leave you exposed to the security issue). You can
reverse the upgrade by issuing ``borg upgrade --disable-tam REPO``.

See
https://borgbackup.readthedocs.io/en/stable/changes.html#pre-1-0-9-manifest-spoofing-vulnerability
for details.

Attic and Borg 0.xx to Borg 1.x
+++++++++++++++++++++++++++++++

This currently supports converting an Attic repository to Borg and also
helps with converting Borg 0.xx to 1.0.

Currently, only LOCAL repositories can be upgraded (issue #465).

Please note that ``borg create`` (since 1.0.0) uses bigger chunks by
default than old borg or attic did, so the new chunks won't deduplicate
with the old chunks in the upgraded repository.
See ``--chunker-params`` option of ``borg create`` and ``borg recreate``.

``borg upgrade`` will change the magic strings in the repository's
segments to match the new Borg magic strings. The keyfiles found in
$ATTIC_KEYS_DIR or ~/.attic/keys/ will also be converted and
copied to $BORG_KEYS_DIR or ~/.config/borg/keys.

The cache files are converted, from $ATTIC_CACHE_DIR or
~/.cache/attic to $BORG_CACHE_DIR or ~/.cache/borg, but the
cache layout between Borg and Attic changed, so it is possible
the first backup after the conversion takes longer than expected
due to the cache resync.

Upgrade should be able to resume if interrupted, although it
will still iterate over all segments. If you want to start
from scratch, use `borg delete` over the copied repository to
make sure the cache files are also removed:

    borg delete borg

Unless ``--inplace`` is specified, the upgrade process first
creates a backup copy of the repository, in
REPOSITORY.upgrade-DATETIME, using hardlinks. This takes
longer than in place upgrades, but is much safer and gives
progress information (as opposed to ``cp -al``). Once you are
satisfied with the conversion, you can safely destroy the
backup copy.

WARNING: Running the upgrade in place will make the current
copy unusable with older version, with no way of going back
to previous versions. This can PERMANENTLY DAMAGE YOUR
REPOSITORY!  Attic CAN NOT READ BORG REPOSITORIES, as the
magic strings have changed. You have been warned.