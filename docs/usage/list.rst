.. include:: list.rst.inc

Examples
~~~~~~~~
::

    $ borg list root-2016-02-15
    drwxr-xr-x root   root          0 Mon, 2016-02-15 17:44:27 .
    drwxrwxr-x root   root          0 Mon, 2016-02-15 19:04:49 bin
    -rwxr-xr-x root   root    1029624 Thu, 2014-11-13 00:08:51 bin/bash
    lrwxrwxrwx root   root          0 Fri, 2015-03-27 20:24:26 bin/bzcmp -> bzdiff
    -rwxr-xr-x root   root       2140 Fri, 2015-03-27 20:24:22 bin/bzdiff
    ...

    $ borg list root-2016-02-15 --pattern "- bin/ba*"
    drwxr-xr-x root   root          0 Mon, 2016-02-15 17:44:27 .
    drwxrwxr-x root   root          0 Mon, 2016-02-15 19:04:49 bin
    lrwxrwxrwx root   root          0 Fri, 2015-03-27 20:24:26 bin/bzcmp -> bzdiff
    -rwxr-xr-x root   root       2140 Fri, 2015-03-27 20:24:22 bin/bzdiff
    ...

    $ borg list archiveA --format="{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}"
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 .
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code
    drwxrwxr-x user   user          0 Sun, 2015-02-01 11:00:00 code/myproject
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.ext
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.text
    ...

    $ borg list archiveA --pattern 're:\.ext$'
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.ext
    ...

    $ borg list archiveA --pattern 're:.ext$'
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.ext
    -rw-rw-r-- user   user    1416192 Sun, 2015-02-01 11:00:00 code/myproject/file.text
    ...

