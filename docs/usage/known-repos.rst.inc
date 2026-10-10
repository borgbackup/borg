.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_known-repos:

borg known-repos
----------------
.. code-block:: none

    borg [common options] known-repos [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------+-----------------------+
    | **options**                                                                                |
    +-------------------------------------------------------+------------+-----------------------+
    |                                                       | ``--json`` | format output as JSON |
    +-------------------------------------------------------+------------+-----------------------+
    | .. class:: borg-common-opt-ref                                                             |
    |                                                                                            |
    | :ref:`common_options`                                                                      |
    +-------------------------------------------------------+------------+-----------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --json     format output as JSON


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command lists the repositories that this local Borg installation currently
has state for: security information (key type, last known location) and/or a
local repository cache.

It inspects only local state - the security directory and the cache directory,
each checked both at its current (borg2) default location and, separately, at
the legacy (borg 1.x) default location those same kinds of state used before the
borg2 base-dir rewrite (see ``$BORG_SECURITY_DIR``/``$BORG_CACHE_DIR`` in
``borg help environment`` for the exact resolution rules, including the platforms
where the two locations differ by default, e.g. macOS). It does not access any
repository, locally or remotely, so a repository that is currently unreachable
(e.g. a disconnected external disk or an unresponsive remote host) will still be
listed just fine. This also means -r/--repo has no effect on this command: it
always lists every locally known repository.

"Layout" reflects which state directory tree the repository was discovered in -
``borg2`` or ``legacy`` - not the repository's actual on-disk format version (see
``borg repo-info``'s "Repository version" for that; this command never opens the
repository, so it cannot report that field at all). The borg2 security entry is
checked first, then the legacy (borg 1.x) security entry, then - only when
neither security entry could be confirmed - whichever cache root matched (borg2
cache checked before the legacy cache). "unknown" means neither a security entry
nor a cache entry could be confirmed for this id - it was listed as a directory
name, but this command could not establish which layout (if either) it belongs
to. If ``$BORG_SECURITY_DIR``/``$BORG_CACHE_DIR`` make the borg2 and legacy
locations resolve to the same path, only the borg2 scan runs and a legacy (v1)
repository there is reported with layout ``borg2``.

This is useful for auditing which repositories this installation has local state for
(and, for repository-encrypted modes, which crypto suite each one uses), finding
repositories with a local cache that may be taking up unwanted disk space, and general
housekeeping of stale local Borg state.

The reported cache size is the size of all regular files below the repository's
cache directory (symlinks are not followed and not counted) - for a current (borg2)
repository that is the files cache plus a small amount of metadata (``config``,
``README``), not an index of the repository's chunks; a legacy (borg 1.x) cache
directory can be considerably larger, since it also holds a local chunks index.
A repository-id directory that is a symlink (Borg itself always creates a plain
directory) is skipped, and a ``location`` or ``key-type`` file that is a symlink
is treated the same as missing; neither is followed.

"Cache last written" is the modification time of the cache's own config file, as
a best-effort proxy for when a cache-using Borg command last ran against this
repository. It is not a precise "last backup" or "last access" time: not every
Borg command updates the cache, and a repository without a local cache at all
will not show one.

This command does not list or export any key material: the keys dir
(``$BORG_KEYS_DIR``) is not scanned.

"Security info" and "Local cache" are each one of three states, not a plain
yes/no: "yes" (confirmed present - for security info, a ``location`` and/or
``key-type`` file was confirmed to exist there, independent of whether its
*content* could be read; for cache, a real, non-symlinked cache directory with a
``config`` file was confirmed to exist), "no" (confirmed absent - this command
actually searched the relevant location(s) and found nothing there - for the
cache specifically, the legacy root is only checked once the borg2 cache root is
confirmed absent for this id, so an unreadable borg2 cache entry reports
"unknown" rather than falling back to check whether a legacy cache exists), or
"unknown"
(this command could not determine which of the above is true - most commonly a
permission error on the repository-id directory itself, or on one of the files
inside it). A file that is simply missing (e.g. a repository with only a
"location" file and no "key-type") does not affect the other field's state (that
repository still has "Security info: yes"); a security file that exists but
could not be fully read (a permission error, a file too large, or not valid
UTF-8) does not change "Security info" away from "yes" either - existence, not
readability, is what that field reports. A repository-id directory that was found
during the directory listing but that then could not be opened or classified for
some other reason - rather than being dropped from the results, as the directory
listing already proves it exists - is still listed, with "unknown" for whichever
of "Security info"/"Local cache"/"Layout" could not be established, so a script
auditing this output never mistakes "could not check" for "confirmed not there".
For the cache specifically, once a cache directory's own existence is confirmed
(a real, non-symlinked directory containing a ``config`` file), a later failure
to fully list its *contents* does not change "Local cache" away from "yes" -
only the reported size becomes a partial count rather than the exact size. Any
of these inspection failures is both logged as its own warning and counted
towards a final summary warning, which (unlike a plain log message) makes this
command exit with a non-zero return code (usually 1) - including when the
failure happened while listing a security or cache root itself (e.g. EIO), which
can keep a repository that exists only there out of the output entirely, with no
per-repository record to point to. A script checking the exit code therefore
learns only that the scan was incomplete, not that every affected repository is
still represented somewhere in the output.