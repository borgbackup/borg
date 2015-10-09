.. include:: global.rst.inc
.. _installation:

Installation
============

|project_name| pyinstaller binary installation requires:

* Linux: glibc >= 2.12 (ok for most supported Linux releases)
* MacOS X: 10.10 (unknown whether it works for older releases)
* FreeBSD: 10.2 (unknown whether it works for older releases)

|project_name| non-binary installation requires:

* Python_ >= 3.2.2
* OpenSSL_ >= 1.0.0
* libacl_ (that pulls in libattr_ also)
* liblz4_
* some python dependencies, see install_requires in setup.py

General notes
-------------
You need to do some platform specific preparation steps (to install libraries
and tools) followed by the generic installation of |project_name| itself:

Below, we describe different ways to install |project_name|.

- **dist package** - easy and fast, needs a distribution and platform specific
  binary package (for your Linux/*BSD/OS X/... distribution).
- **pyinstaller binary** - easy and fast, we provide a ready-to-use binary file
  that just works on the supported platforms
- **pypi** - installing a source package from pypi needs more installation steps
  and will need a compiler, development headers, etc..
- **git** - for developers and power users who want to have the latest code or
  use revision control (each release is tagged).

**Python 3**: Even though this is not the default Python version on many systems,
it is usually available as an optional install.

Virtualenv_ can be used to build and install |project_name| without affecting
the system Python or requiring root access.

Important:
If you install into a virtual environment, you need to **activate**
the virtual env first (``source borg-env/bin/activate``).
Alternatively, directly run ``borg-env/bin/borg`` (or symlink that into some
directory that is in your PATH so you can just run ``borg``).
Using a virtual environment is optional, but recommended except for the most
simple use cases.

The llfuse_ python package is also required if you wish to mount an
archive as a FUSE filesystem. Only FUSE >= 2.8.0 can support llfuse.

You only need **Cython** to compile the .pyx files to the respective .c files
when using |project_name| code from git. For |project_name| releases, the .c
files will be bundled, so you won't need Cython to install a release.

Platform notes
--------------
FreeBSD: You may need to get a recent enough OpenSSL version from FreeBSD ports.

Mac OS X: You may need to get a recent enough OpenSSL version from homebrew_.

Mac OS X: You need OS X FUSE >= 3.0.


Installation (dist package)
---------------------------
Some Linux, BSD and OS X distributions might offer a ready-to-use
`borgbackup` package (which can be easily installed in the usual way).

As |project_name| is still relatively new, such a package might be not
available for your system yet. Please ask package maintainers to build a
package or, if you can package / submit it yourself, please help us with
that!

If a package is available, it might be interesting for you to check its version
and compare that to our latest release and review the change log (see links on
our web site).


Installation (pyinstaller binary)
---------------------------------
For some platforms we offer a ready-to-use standalone borg binary.

It is supposed to work without requiring installation or preparations.

Check https://github.com/borgbackup/borg/issues/214 for available binaries.


Debian Jessie / Ubuntu 14.04 preparations (git/pypi)
----------------------------------------------------

.. parsed-literal::

    # Python 3.x (>= 3.2) + Headers, Py Package Installer, VirtualEnv
    apt-get install python3 python3-dev python3-pip python-virtualenv

    # we need OpenSSL + Headers for Crypto
    apt-get install libssl-dev openssl

    # ACL support Headers + Library
    apt-get install libacl1-dev libacl1

    # lz4 super fast compression support Headers + Library
    apt-get install liblz4-dev liblz4-1

    # if you do not have gcc / make / etc. yet
    apt-get install build-essential

    # optional: FUSE support - to mount backup archives
    # in case you get complaints about permission denied on /etc/fuse.conf:
    # on ubuntu this means your user is not in the "fuse" group. just add
    # yourself there, log out and log in again.
    apt-get install libfuse-dev fuse pkg-config

    # optional: for unit testing
    apt-get install fakeroot


Korora / Fedora 21 preparations (git/pypi)
------------------------------------------

.. parsed-literal::

    # Python 3.x (>= 3.2) + Headers, Py Package Installer, VirtualEnv
    sudo dnf install python3 python3-devel python3-pip python3-virtualenv

    # we need OpenSSL + Headers for Crypto
    sudo dnf install openssl-devel openssl

    # ACL support Headers + Library
    sudo dnf install libacl-devel libacl

    # lz4 super fast compression support Headers + Library
    sudo dnf install lz4-devel

    # optional: FUSE support - to mount backup archives
    sudo dnf install fuse-devel fuse pkgconfig
    
    # optional: for unit testing
    sudo dnf install fakeroot


Cygwin preparations (git/pypi)
------------------------------

Please note that running under cygwin is rather experimental, stuff has been
tested with CygWin (x86-64) v2.1.0.

You'll need at least (use the cygwin installer to fetch/install these):

::

    python3 python3-setuptools
    python3-cython  # not needed for releases
    binutils gcc-core
    libopenssl openssl-devel
    liblz4_1 liblz4-devel  # from cygwinports.org
    git make openssh

You can then install ``pip`` and ``virtualenv``:

::

    easy_install-3.4 pip
    pip install virtualenv

And now continue with the generic installation (see below).

In case that creation of the virtual env fails, try deleting this file:

::

    /usr/lib/python3.4/__pycache__/platform.cpython-34.pyc


Installation (pypi)
-------------------

This uses the latest (source package) release from PyPi.

.. parsed-literal::

    virtualenv --python=python3 borg-env
    source borg-env/bin/activate   # always before using!

    # install borg + dependencies into virtualenv
    pip install 'llfuse<0.41'  # optional, for FUSE support
                               # 0.41 and 0.41.1 have unicode issues at install time
    pip install borgbackup

Note: we install into a virtual environment here, but this is not a requirement.


Installation (git)
------------------

This uses latest, unreleased development code from git.
While we try not to break master, there are no guarantees on anything.

.. parsed-literal::

    # get |project_name| from github, install it
    git clone |git_url|

    virtualenv --python=python3 borg-env
    source borg-env/bin/activate   # always before using!

    # install borg + dependencies into virtualenv
    pip install sphinx  # optional, to build the docs
    pip install 'llfuse<0.41'  # optional, for FUSE support
                               # 0.41 and 0.41.1 have unicode issues at install time
    cd borg
    pip install -r requirements.d/development.txt
    pip install -e .  # in-place editable mode

    # optional: run all the tests, on all supported Python versions
    fakeroot -u tox

Note: as a developer or power user, you always want to use a virtual environment.
