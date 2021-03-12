.. include:: diff.rst.inc

Examples
~~~~~~~~
::

    $ borg init -e=none testrepo
    $ mkdir testdir
    $ cd testdir
    $ echo asdf > file1
    $ dd if=/dev/urandom bs=1M count=4 > file2
    $ touch file3
    $ borg create ../testrepo::archive1 .

    $ chmod a+x file1
    $ echo "something" >> file2
    $ borg create ../testrepo::archive2 .

    $ echo "testing 123" >> file1
    $ rm file3
    $ touch file4
    $ borg create ../testrepo::archive3 .

    $ cd ..
    $ borg diff testrepo::archive1 archive2
    [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2

    $ borg diff testrepo::archive2 archive3
        +17 B      -5 B file1
    added           0 B file4
    removed         0 B file3

    $ borg diff testrepo::archive1 archive3
        +17 B      -5 B [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2
    added           0 B file4
    removed         0 B file3

    $ borg diff --json-lines testrepo::archive1 archive3
    {"path": "file1", "changes": [{"type": "modified", "added": 17, "removed": 5}, {"type": "mode", "old_mode": "-rw-r--r--", "new_mode": "-rwxr-xr-x"}]}
    {"path": "file2", "changes": [{"type": "modified", "added": 135, "removed": 252}]}
    {"path": "file4", "changes": [{"type": "added", "size": 0}]}
    {"path": "file3", "changes": [{"type": "removed", "size": 0}]}