.. include:: diff.rst.inc

Examples
~~~~~~~~
::

    $ borg diff archive1 archive2
        +17 B      -5 B [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2
    added           0 B file4
    removed         0 B file3

    $ borg diff archive1 archive2
    {"path": "file1", "changes": [{"type": "modified", "added": 17, "removed": 5}, {"type": "mode", "old_mode": "-rw-r--r--", "new_mode": "-rwxr-xr-x"}]}
    {"path": "file2", "changes": [{"type": "modified", "added": 135, "removed": 252}]}
    {"path": "file4", "changes": [{"type": "added", "size": 0}]}
    {"path": "file3", "changes": [{"type": "removed", "size": 0}]}


    # Use --sort-by with a comma-separated list; sorts apply stably from last to first.
    # Here: primary by net size change descending, tie-breaker by path ascending
    $ borg diff --sort-by=">size_diff,path" archive1 archive2
        +17 B      -5 B [-rw-r--r-- -> -rwxr-xr-x] file1
    removed         0 B file3
    added           0 B file4
       +135 B    -252 B file2
