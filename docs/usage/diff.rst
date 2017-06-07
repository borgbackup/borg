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

    $ rm file3
    $ touch file4
    $ borg create ../testrepo::archive3 .

    $ cd ..
    $ borg diff testrepo::archive1 archive2
    [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2

    $ borg diff testrepo::archive2 archive3
    added           0 B file4
    removed         0 B file3

    $ borg diff testrepo::archive1 archive3
    [-rw-r--r-- -> -rwxr-xr-x] file1
       +135 B    -252 B file2
    added           0 B file4
    removed         0 B file3
