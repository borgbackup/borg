.. _attic_check:

attic check
-----------
::


    usage: attic check [-h] [-v] [--progress] [--no-progress] REPOSITORY
    
    Check repository consistency
    
    positional arguments:
      REPOSITORY     repository to check consistency of
    
    optional arguments:
      -h, --help     show this help message and exit
      -v, --verbose  verbose output
      --progress     Report progress status to standard output stream
      --no-progress  Disable progress reporting
    
    Progress status will be reported on the standard output stream by default when
    it is attached to a terminal. Any problems found are printed to the standard
    error stream and the command will have a non zero exit code.

Description
~~~~~~~~~~~


