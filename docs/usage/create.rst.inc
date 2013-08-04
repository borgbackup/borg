.. _attic_create:

attic create
------------
::


    usage: attic create [-h] [-v] [-s] [-e PATTERN] [-c SECONDS]
                        [--do-not-cross-mountpoints] [--numeric-owner]
                        ARCHIVE PATH [PATH ...]
    
    Create new archive
    
    positional arguments:
      ARCHIVE               archive to create
      PATH                  paths to archive
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      -s, --stats           print statistics for the created archive
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      -c SECONDS, --checkpoint-interval SECONDS
                            write checkpoint every SECONDS seconds (Default: 300)
      --do-not-cross-mountpoints
                            do not cross mount points
      --numeric-owner       only store numeric user and group identifiers

Description
~~~~~~~~~~~


