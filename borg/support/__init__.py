"""
3rd party stuff that needed fixing

Note: linux package maintainers feel free to remove any of these hacks
      IF your python version is not affected.

argparse is broken with default args (double conversion):
affects: 3.2.0 <= python < 3.2.4
affects: 3.3.0 <= python < 3.3.1

as we still support 3.2 and 3.3 there is no other way than to bundle
a fixed version (I just took argparse.py from 3.2.6) and import it from
here (see import in archiver.py).
DEPRECATED - remove support.argparse after requiring python 3.4.
"""

