====
borg
====

----------------------------------------
deduplicating and encrypting backup tool
----------------------------------------

:Author: The Borg Collective
:Date: 2017-02-05
:Manual section: 1
:Manual group: borg backup tool

SYNOPSIS
--------

borg [common options] <command> [options] [arguments]

DESCRIPTION
-----------

.. we don't include the README.rst here since we want to keep this terse.

BorgBackup (short: Borg) is a deduplicating backup program.
Optionally, it supports compression and authenticated encryption.

The main goal of Borg is to provide an efficient and secure way to backup data.
The data deduplication technique used makes Borg suitable for daily backups
since only changes are stored.
The authenticated encryption technique makes it suitable for backups to not
fully trusted targets.

Borg stores a set of files in an *archive*. A *repository* is a collection
of *archives*. The format of repositories is Borg-specific. Borg does not
distinguish archives from each other in a any way other than their name,
it does not matter when or where archives where created (eg. different hosts).

EXAMPLES
--------

A step-by-step example
~~~~~~~~~~~~~~~~~~~~~~

.. include:: quickstart_example.rst.inc

NOTES
-----

.. include:: usage_general.rst.inc

SEE ALSO
--------

`borg-common(1)` for common command line options

`borg-init(1)`,
`borg-create(1)`, `borg-mount(1)`, `borg-extract(1)`,
`borg-list(1)`, `borg-info(1)`,
`borg-delete(1)`, `borg-prune(1)`,
`borg-recreate(1)`

`borg-compression(1)`, `borg-patterns(1)`, `borg-placeholders(1)`

* Main web site https://borgbackup.readthedocs.org/
* Releases https://github.com/borgbackup/borg/releases
* Changelog https://github.com/borgbackup/borg/blob/master/docs/changes.rst
* GitHub https://github.com/borgbackup/borg
* Security contact https://borgbackup.readthedocs.io/en/latest/support.html#security-contact
