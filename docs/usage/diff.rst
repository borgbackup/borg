.. include:: diff.rst.inc

Examples
~~~~~~~~
::

    # By default, borg diff reports metadata changes (mode, mtime, ctime, ...) besides
    # the content changes, so the lines can get quite long:
    $ borg diff archive1 archive2
    [mtime: Fri, 2026-08-28 12:26:23.433047048 +0200 -> Fri, 2026-08-28 12:26:24.204040020 +0200] [ctime: Fri, 2026-08-28 12:26:23.433047048 +0200 -> Fri, 2026-08-28 12:26:24.204040020 +0200] .
    modified:    +17 B     -5 B [-rw-r--r-- -> -rwxr-xr-x] [mtime: Fri, 2026-08-28 12:26:23.431245244 +0200 -> Fri, 2026-08-28 12:26:24.199251801 +0200] [ctime: Fri, 2026-08-28 12:26:23.431245244 +0200 -> Fri, 2026-08-28 12:26:24.200688313 +0200] file1
    modified:   +135 B   -252 B [mtime: Fri, 2026-08-28 12:26:23.432895166 +0200 -> Fri, 2026-08-28 12:26:24.202236091 +0200] [ctime: Fri, 2026-08-28 12:26:23.432895166 +0200 -> Fri, 2026-08-28 12:26:24.202236091 +0200] file2
    added:                  0 B file4
    removed:                0 B file3

    # --content-only hides the metadata changes and only reports content differences:
    $ borg diff --content-only archive1 archive2
    modified:    +17 B     -5 B file1
    modified:   +135 B   -252 B file2
    added:                  0 B file4
    removed:                0 B file3

    # Use --json-lines to get one JSON object per changed path:
    $ borg diff --json-lines --content-only archive1 archive2
    {"changes": [{"added": 17, "removed": 5, "type": "modified"}], "path": "file1"}
    {"changes": [{"added": 135, "removed": 252, "type": "modified"}], "path": "file2"}
    {"changes": [{"added": 0, "removed": 0, "type": "added"}], "path": "file4"}
    {"changes": [{"added": 0, "removed": 0, "type": "removed"}], "path": "file3"}

    # Use --sort-by with a comma-separated list; sorts apply stably from last to first.
    # Here: primary by net size change descending, tie-breaker by path ascending
    $ borg diff --content-only --sort-by=">size_diff,path" archive1 archive2
    modified:    +17 B     -5 B file1
    removed:                0 B file3
    added:                  0 B file4
    modified:   +135 B   -252 B file2
