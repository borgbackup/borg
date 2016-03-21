.. include:: global.rst.inc
.. _installation:

Installation
============

There are different ways to install |project_name|:

- :ref:`distribution-package` - easy and fast if a package is
  available from your distribution.
- :ref:`pyinstaller-binary` - easy and fast, we provide a ready-to-use binary file
  that comes bundled with all dependencies.
- :ref:`source-install`, either:

  - :ref:`pip-installation` - installing a source package with pip needs
    more installation steps and requires all dependencies with
    development headers and a compiler.
  - :ref:`git-installation`  - for developers and power users who want to
    have the latest code or use revision control (each release is
    tagged).

.. _distribution-package:

Distribution Package
--------------------

Some distributions might offer a ready-to-use ``borgbackup``
package which can be installed with the package manager.  As |project_name| is
still a young project, such a package might be not available for your system
yet.

============ ============================================= =======
Distribution Source                                        Command
============ ============================================= =======
Arch Linux   `[community]`_                                ``pacman -S borg``
Debian       `stretch`_, `unstable/sid`_                   ``apt install borgbackup``
NetBSD       `pkgsrc`_                                     ``pkg_add py-borgbackup``
NixOS        `.nix file`_                                  N/A
OS X         `Brew cask`_                                  ``brew cask install borgbackup``
Ubuntu       `Xenial 16.04`_, `Wily 15.10 (backport PPA)`_ ``apt install borgbackup``
Ubuntu       `Trusty 14.04 (backport PPA)`_                ``apt install borgbackup``
============ ============================================= =======

.. _[community]: https://www.archlinux.org/packages/?name=borg
.. _stretch: https://packages.debian.org/stretch/borgbackup
.. _unstable/sid: https://packages.debian.org/sid/borgbackup
.. _pkgsrc: http://pkgsrc.se/sysutils/py-borgbackup
.. _Xenial 16.04: https://launchpad.net/ubuntu/xenial/+source/borgbackup
.. _Wily 15.10 (backport PPA): https://launchpad.net/~costamagnagianfranco/+archive/ubuntu/borgbackup
.. _Trusty 14.04 (backport PPA): https://launchpad.net/~costamagnagianfranco/+archive/ubuntu/borgbackup
.. _.nix file: https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/backup/borg/default.nix
.. _Brew cask: http://caskroom.io/

Please ask package maintainers to build a package or, if you can package /
submit it yourself, please help us with that! See :issue:`105` on
github to followup on packaging efforts.

If a package is available, it might be interesting to check its version
and compare that to our latest release and review the :doc:`changes`.

.. _pyinstaller-binary:

Standalone Binary
-----------------

|project_name| binaries (generated with `pyinstaller`_) are available
on the releases_ page for the following platforms:

* **Linux**: glibc >= 2.13 (ok for most supported Linux releases). Maybe older
  glibc versions also work, if they are compatible to 2.13.
* **Mac OS X**: 10.10 (does not work with older OS X releases)
* **FreeBSD**: 10.2 (unknown whether it works for older releases)

To install such a binary, just drop it into a directory in your ``PATH``,
make borg readable and executable for its users and then you can run ``borg``::

    sudo cp borg-linux64 /usr/local/bin/borg
    sudo chown root:root /usr/local/bin/borg
    sudo chmod 755 /usr/local/bin/borg

Note that the binary uses /tmp to unpack |project_name| with all dependencies.
It will fail if /tmp has not enough free space or is mounted with the ``noexec`` option.
You can change the temporary directory by setting the ``TEMP`` environment variable before running |project_name|.

If a new version is released, you will have to manually download it and replace
the old version using the same steps as shown above.

.. _pyinstaller: http://www.pyinstaller.org
.. _releases: https://github.com/borgbackup/borg/releases

.. _source-install:

From Source
-----------

Dependencies
~~~~~~~~~~~~

To install |project_name| from a source package (including pip), you have to install the
following dependencies first:

* `Python 3`_ >= 3.4.0, plus development headers. Even though Python 3 is not
  the default Python version on most systems, it is usually available as an
  optional install.
* OpenSSL_ >= 1.0.0, plus development headers.
* libacl_ (that pulls in libattr_ also), both plus development headers.
* liblz4_, plus development headers.
* some Python dependencies, pip will automatically install them for you
* optionally, the llfuse_ Python package is required if you wish to mount an
  archive as a FUSE filesystem. See setup.py about the version requirements.

If you have troubles finding the right package names, have a look at the
distribution specific sections below and also at the Vagrantfile in our repo.

In the following, the steps needed to install the dependencies are listed for a
selection of platforms. If your distribution is not covered by these
instructions, try to use your package manager to install the dependencies.  On
FreeBSD, you may need to get a recent enough OpenSSL version from FreeBSD
ports.

After you have installed the dependencies, you can proceed with steps outlined
under :ref:`pip-installation`.

Debian / Ubuntu
+++++++++++++++

Install the dependencies with development headers::

    sudo apt-get install python3 python3-dev python3-pip python-virtualenv \
    libssl-dev openssl \
    libacl1-dev libacl1 \
    liblz4-dev liblz4-1 \
    build-essential
    sudo apt-get install libfuse-dev fuse pkg-config    # optional, for FUSE support

In case you get complaints about permission denied on ``/etc/fuse.conf``: on
Ubuntu this means your user is not in the ``fuse`` group. Add yourself to that
group, log out and log in again.

Fedora / Korora
+++++++++++++++

Install the dependencies with development headers::

    sudo dnf install python3 python3-devel python3-pip python3-virtualenv
    sudo dnf install openssl-devel openssl
    sudo dnf install libacl-devel libacl
    sudo dnf install lz4-devel
    sudo dnf install gcc gcc-c++
    sudo dnf install fuse-devel fuse pkgconfig         # optional, for FUSE support


Mac OS X
++++++++

Assuming you have installed homebrew_, the following steps will install all the
dependencies::

    brew install python3 lz4 openssl
    pip3 install virtualenv

For FUSE support to mount the backup archives, you need at least version 3.0 of
FUSE for OS X, which is available as a pre-release_.

.. _pre-release: https://github.com/osxfuse/osxfuse/releases


FreeBSD
++++++++
Listed below are packages you will need to install |project_name|, its dependencies,
and commands to make fuse work for using the mount command.

::

     pkg install -y python3 openssl liblz4 fusefs-libs pkgconf
     pkg install -y git
     python3.4 -m ensurepip # to install pip for Python3
     To use the mount command:
     echo 'fuse_load="YES"' >> /boot/loader.conf
     echo 'vfs.usermount=1' >> /etc/sysctl.conf
     kldload fuse
     sysctl vfs.usermount=1
    

Cygwin
++++++

.. note::
    Running under Cygwin is experimental and has only been tested with Cygwin
    (x86-64) v2.1.0.

Use the Cygwin installer to install the dependencies::

    python3 python3-setuptools
    python3-cython  # not needed for releases
    binutils gcc-g++
    libopenssl openssl-devel
    liblz4_1 liblz4-devel  # from cygwinports.org
    git make openssh

You can then install ``pip`` and ``virtualenv``::

    easy_install-3.4 pip
    pip install virtualenv

In case the creation of the virtual environment fails, try deleting this file::

    /usr/lib/python3.4/__pycache__/platform.cpython-34.pyc


.. _pip-installation:

Using pip
~~~~~~~~~

Virtualenv_ can be used to build and install |project_name| without affecting
the system Python or requiring root access.  Using a virtual environment is
optional, but recommended except for the most simple use cases.

.. note::
    If you install into a virtual environment, you need to **activate** it
    first (``source borg-env/bin/activate``), before running ``borg``.
    Alternatively, symlink ``borg-env/bin/borg`` into some directory that is in
    your ``PATH`` so you can just run ``borg``.

This will use ``pip`` to install the latest release from PyPi::

    virtualenv --python=python3 borg-env
    source borg-env/bin/activate

    # install Borg + Python dependencies into virtualenv
    pip install borgbackup
    # or alternatively (if you want FUSE support):
    pip install borgbackup[fuse]

To upgrade |project_name| to a new version later, run the following after
activating your virtual environment::

    pip install -U borgbackup  # or ... borgbackup[fuse]

.. _git-installation:

Using git
~~~~~~~~~

This uses latest, unreleased development code from git.
While we try not to break master, there are no guarantees on anything. ::

    # get borg from github
    git clone https://github.com/borgbackup/borg.git

    virtualenv --python=python3 borg-env
    source borg-env/bin/activate   # always before using!

    # install borg + dependencies into virtualenv
    pip install sphinx  # optional, to build the docs
    cd borg
    pip install -r requirements.d/development.txt
    pip install -r requirements.d/fuse.txt  # optional, for FUSE support
    pip install -e .  # in-place editable mode

    # optional: run all the tests, on all supported Python versions
    # requires fakeroot, available through your package manager
    fakeroot -u tox

.. note:: As a developer or power user, you always want to use a virtual environment.
