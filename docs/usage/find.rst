.. include:: find.rst.inc

Examples
~~~~~~~~
::

    # In which archives is this file? Searched / printed from newest to oldest archive.
    $ borg find home/user/file.txt
    41a2ed21 docs -rw-rw-r-- user   user       1522 Sun, 2022-02-06 21:02:18 +0100 home/user/file.txt
    20e70e3a docs -rw-rw-r-- user   user       1440 Sun, 2022-01-30 20:47:32 +0100 home/user/file.txt

    # Find all jpg files in the last 3 archives.
    $ borg find 'sh:**/*.jpg' --last 3
    39c8956e photos -rw-rw-r-- user   user     919337 Sat, 2022-01-01 14:20:21 +0100 photos/paris/eiffel.jpg
    39c8956e photos -rw-rw-r-- user   user    1023881 Sun, 2022-02-06 09:12:44 +0100 photos/rome/colosseum.jpg
    04061a53 photos -rw-rw-r-- user   user     919337 Sat, 2022-01-01 14:20:21 +0100 photos/paris/eiffel.jpg

    # Only print the archive and the path, nothing else.
    $ borg find --format '{archiveid:.8} {archivename} {path}{NL}' home/user/file.txt
    41a2ed21 docs home/user/file.txt
    20e70e3a docs home/user/file.txt
