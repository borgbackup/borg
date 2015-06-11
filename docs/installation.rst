.. include:: global.rst.inc
.. _installation:

Installation
============

|project_name| requires:

* Python_ >= 3.2
* OpenSSL_ >= 1.0.0
* libacl_
* some python dependencies, see install_requires in setup.py

General notes
-------------
Even though Python 3 is not the default Python version on many systems, it is
usually available as an optional install.

Virtualenv_ can be used to build and install |project_name| without affecting
the system Python or requiring root access.

The llfuse_ python package is also required if you wish to mount an
archive as a FUSE filesystem. Only FUSE >= 2.8.0 can support llfuse.

You only need Cython to compile the .pyx files to the respective .c files
when using |project_name| code from git. For |project_name| releases, the .c
files will be bundled.

Platform notes
--------------
FreeBSD: You may need to get a recent enough OpenSSL version from FreeBSD ports.

Mac OS X: You may need to get a recent enough OpenSSL version from homebrew_.

Mac OS X: A recent enough FUSE implementation might be unavailable.


Debian / Ubuntu installation (from git)
---------------------------------------
Note: this uses latest, unreleased development code from git.
While we try not to break master, there are no guarantees on anything.

Some of the steps detailled below might be useful also for non-git installs.

.. parsed-literal::

    # Python 3.x (>= 3.2) + Headers, Py Package Installer
    apt-get install python3 python3-dev python3-pip

    # we need OpenSSL + Headers for Crypto
    apt-get install libssl-dev openssl

    # ACL support Headers + Library
    apt-get install libacl1-dev libacl1

    # if you do not have gcc / make / etc. yet
    apt-get install build-essential

    # optional: lowlevel FUSE py binding - to mount backup archives
    apt-get install python3-llfuse fuse

    # optional: for unit testing
    apt-get install fakeroot

    # get |project_name| from github, install it
    git clone |git_url|

    apt-get install python-virtualenv
    virtualenv --python=python3 borg-env
    source borg-env/bin/activate   # always before using!

    # install borg + dependencies into virtualenv
    pip install cython  # compile .pyx -> .c
    pip install tox pytest  # optional, for running unit tests
    pip install sphinx  # optional, to build the docs
    cd borg
    pip install -e .  # in-place editable mode

    # optional: run all the tests, on all supported Python versions
    fakeroot -u tox
