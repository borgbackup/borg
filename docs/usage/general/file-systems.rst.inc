File systems
~~~~~~~~~~~~

We strongly recommend against using Borg (or any other database-like
software) on non-journaling file systems like FAT, since it is not
possible to assume any consistency in case of power failures (or a
sudden disconnect of an external drive or similar failures).

While Borg uses a data store that is resilient against these failures
when used on journaling file systems, it is not possible to guarantee
this with some hardware -- independent of the software used. We don't
know a list of affected hardware.

If you are suspicious whether your Borg repository is still consistent
and readable after one of the failures mentioned above occurred, run
``borg check --verify-data`` to make sure it is consistent.

.. rubric:: Requirements for Borg repository file systems

- Long file names
- At least three directory levels with short names
- Typically, file sizes up to a few hundred MB.
  Large repositories may require large files (>2 GB).
- Up to 1000 files per directory (10000 for repositories initialized with Borg 1.0)
- mkdir(2) should be atomic, since it is used for locking
- Hardlinks are needed for :ref:`borg_upgrade` (if ``--inplace`` option is not used).
  Also hardlinks are used for more safe and secure file updating (e.g. of the repo
  config file), but the code tries to work also if hardlinks are not supported.
