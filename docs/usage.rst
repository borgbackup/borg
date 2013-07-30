.. _usage_attic_change-passphrase:

attic change-passphrase
~~~~~~~~~~~~~~~~~~~~~~~
::

usage: attic change-passphrase [-h] [-v] repository

Change passphrase on repository key file

positional arguments:
  repository

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose output
.. _usage_attic_create:

attic create
~~~~~~~~~~~~
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
                        write checkpointe ever SECONDS seconds (Default: 300)
  --do-not-cross-mountpoints
                        do not cross mount points
  --numeric-owner       only store numeric user and group identifiers
.. _usage_attic_delete:

attic delete
~~~~~~~~~~~~
::

usage: attic delete [-h] [-v] ARCHIVE

Delete archive

positional arguments:
  ARCHIVE        archive to delete

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose output
.. _usage_attic_extract:

attic extract
~~~~~~~~~~~~~
::

usage: attic extract [-h] [-v] [-e PATTERN] [--numeric-owner]
                     ARCHIVE [PATH [PATH ...]]

Extract archive contents

positional arguments:
  ARCHIVE               archive to extract
  PATH                  paths to extract

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -e PATTERN, --exclude PATTERN
                        exclude paths matching PATTERN
  --numeric-owner       only obey numeric user and group identifiers
.. _usage_attic_init:

attic init
~~~~~~~~~~
::

usage: attic init [-h] [-v] [--key-file] [--passphrase] repository

Initialize a new repository

positional arguments:
  repository     repository to create

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose output
  --key-file     enable key file based encryption
  --passphrase   enable passphrase based encryption
.. _usage_attic_mount:

attic mount
~~~~~~~~~~~
::

usage: attic mount [-h] [-v] [-f] [-o OPTIONS] ARCHIVE MOUNTPOINT

Mount archive as a FUSE fileystem

positional arguments:
  ARCHIVE           archive to mount
  MOUNTPOINT        where to mount filesystem

optional arguments:
  -h, --help        show this help message and exit
  -v, --verbose     verbose output
  -f, --foreground  stay in foreground, do not daemonize
  -o OPTIONS        Extra mount options
.. _usage_attic_prune:

attic prune
~~~~~~~~~~~
::

usage: attic prune [-h] [-v] [-H HOURLY] [-d DAILY] [-w WEEKLY] [-m MONTHLY]
                   [-y YEARLY] [-p PREFIX]
                   REPOSITORY

Prune repository archives according to specified rules

positional arguments:
  REPOSITORY            repository to prune

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -H HOURLY, --hourly HOURLY
                        number of hourly archives to keep
  -d DAILY, --daily DAILY
                        number of daily archives to keep
  -w WEEKLY, --weekly WEEKLY
                        number of daily archives to keep
  -m MONTHLY, --monthly MONTHLY
                        number of monthly archives to keep
  -y YEARLY, --yearly YEARLY
                        number of yearly archives to keep
  -p PREFIX, --prefix PREFIX
                        only consider archive names starting with this prefix
.. _usage_attic_verify:

attic verify
~~~~~~~~~~~~
::

usage: attic verify [-h] [-v] [-e PATTERN] ARCHIVE [PATH [PATH ...]]

Verify archive consistency

positional arguments:
  ARCHIVE               archive to verity integrity of
  PATH                  paths to verify

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -e PATTERN, --exclude PATTERN
                        exclude paths matching PATTERN
