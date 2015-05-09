.. include:: global.rst.inc
.. _installation:

Installation
============

|project_name| requires Python_ 3.2 or above to work. Even though Python 3 is
not the default Python version on most Linux distributions, it is usually
available as an optional install.

Other dependencies:

* `msgpack-python`_ >= 0.1.10
* OpenSSL_ >= 1.0.0
* libacl_

The OpenSSL version bundled with Mac OS X and FreeBSD is most likey too old.
Newer versions are available from homebrew_ on OS X and from FreeBSD ports.

The llfuse_ python package is also required if you wish to mount an
archive as a FUSE filesystem.

Virtualenv_ can be used to build and install |project_name|
without affecting the system Python or requiring root access.

Common compilation pre-requisites
---------------------------------

The following Debian packages are generally necessary to compile
|project_name|, either through pip, the tarball or git::

  $ sudo apt-get install python3 python3-dev python3-msgpack python3-sphinx libssl-dev libacl1-dev

Installing from PyPI using pip
------------------------------

To install |project_name| system-wide::

  $ sudo pip3 install borgbackup

To install it in a user-specific account::

  $ pip3 install --user borgbackup

Then add ``$HOME/.library/bin`` to your ``$PATH``.

Installing from source tarballs
-------------------------------
.. parsed-literal::

    $ curl -O :targz_url:`Borg`
    $ tar -xvzf |package_filename|
    $ cd |package_dirname|
    $ sudo python3 setup.py install

Installing from git
-------------------
.. parsed-literal::

    $ git clone |git_url|
    $ cd borg
    $ sudo python3 setup.py install

Please note that when installing from git, Cython_ is required to generate some files that
are normally bundled with the release tarball.
