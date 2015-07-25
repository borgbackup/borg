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
files will be bundled, so you won't need Cython to install a release.

Platform notes
--------------
FreeBSD: You may need to get a recent enough OpenSSL version from FreeBSD ports.

Mac OS X: You may need to get a recent enough OpenSSL version from homebrew_.

Mac OS X: You need OS X FUSE >= 3.0.


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
    # in case you get complaints about permission denied on /etc/fuse.conf:
    # on ubuntu this means your user is not in the "fuse" group. just add
    # yourself there, log out and log in again.
    # if it complains about not being able to find llfuse: make a symlink
    # borg-env/lib/python3.4/site-packages/llfuse -> /usr/lib/python3/dist-packages/llfuse
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


Korora / Fedora 21 installation (from git)
------------------------------------------
Note: this uses latest, unreleased development code from git.
While we try not to break master, there are no guarantees on anything.

Some of the steps detailled below might be useful also for non-git installs.

.. parsed-literal::
    # Python 3.x (>= 3.2) + Headers, Py Package Installer
    sudo dnf install python3 python3-devel python3-pip

    # we need OpenSSL + Headers for Crypto
    sudo dnf install openssl-devel openssl

    # ACL support Headers + Library
    sudo dnf install libacl-devel libacl
    
    # optional: lowlevel FUSE py binding - to mount backup archives
    sudo dnf install python3-llfuse fuse
    
    # optional: for unit testing
    sudo dnf install fakeroot
    
    # get |project_name| from github, install it
    git clone |git_url|

    dnf install python3-virtualenv
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


Cygwin (from git)
-----------------
Please note that running under cygwin is rather experimental, stuff has been
tested with CygWin (x86-64) v2.1.0.

You'll need at least (use the cygwin installer to fetch/install these):

::

    python3
    python3-setuptools
    python3-cython
    binutils
    gcc-core
    git
    libopenssl
    make
    openssh
    openssl-devel

You can then install ``pip`` and ``virtualenv``:

::

    easy_install-3.4 pip
    pip install virtualenv

And now continue as for Linux (see above).

In case that creation of the virtual env fails, try deleting this file:

::

    /usr/lib/python3.4/__pycache__/platform.cpython-34.pyc

