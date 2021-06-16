.. include:: global.rst.inc
.. highlight:: bash
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
package which can be installed with the package manager.

.. important:: Those packages may not be up to date with the latest
               |project_name| releases. Before submitting a bug
               report, check the package version and compare that to
               our latest release then review :doc:`changes` to see if
               the bug has been fixed. Report bugs to the package
               maintainer rather than directly to |project_name| if the
               package is out of date in the distribution.

.. keep this list in alphabetical order

============ ============================================= =======
Distribution Source                                        Command
============ ============================================= =======
Alpine Linux `Alpine repository`_                          ``apk add borgbackup``
Arch Linux   `[community]`_                                ``pacman -S borg``
Debian       `Debian packages`_                            ``apt install borgbackup``
Gentoo       `ebuild`_                                     ``emerge borgbackup``
GNU Guix     `GNU Guix`_                                   ``guix package --install borg``
Fedora/RHEL  `Fedora official repository`_                 ``dnf install borgbackup``
FreeBSD      `FreeBSD ports`_                              ``cd /usr/ports/archivers/py-borgbackup && make install clean``
macOS        `Homebrew`_                                   | ``brew install borgbackup`` (official formula, **no** FUSE support)
                                                           | **or**
                                                           | ``brew install --cask macfuse`` (`private Tap`_, FUSE support) 
                                                           | ``brew install borgbackup/tap/borgbackup-fuse``
Mageia       `cauldron`_                                   ``urpmi borgbackup``
NetBSD       `pkgsrc`_                                     ``pkg_add py-borgbackup``
NixOS        `.nix file`_                                  N/A
OpenBSD      `OpenBSD ports`_                              ``pkg_add borgbackup``
OpenIndiana  `OpenIndiana hipster repository`_             ``pkg install borg``
openSUSE     `openSUSE official repository`_               ``zypper in borgbackup``
Raspbian     `Raspbian testing`_                           ``apt install borgbackup``
Ubuntu       `Ubuntu packages`_, `Ubuntu PPA`_             ``apt install borgbackup``
============ ============================================= =======

.. _Alpine repository: https://pkgs.alpinelinux.org/packages?name=borgbackup
.. _[community]: https://www.archlinux.org/packages/?name=borg
.. _Debian packages: https://packages.debian.org/search?keywords=borgbackup&searchon=names&exact=1&suite=all&section=all
.. _Fedora official repository: https://apps.fedoraproject.org/packages/borgbackup
.. _FreeBSD ports: https://www.freshports.org/archivers/py-borgbackup/
.. _ebuild: https://packages.gentoo.org/packages/app-backup/borgbackup
.. _GNU Guix: https://www.gnu.org/software/guix/package-list.html#borg
.. _pkgsrc: http://pkgsrc.se/sysutils/py-borgbackup
.. _cauldron: http://madb.mageia.org/package/show/application/0/release/cauldron/name/borgbackup
.. _.nix file: https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/backup/borg/default.nix
.. _OpenBSD ports: https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/sysutils/borgbackup/
.. _OpenIndiana hipster repository: https://pkg.openindiana.org/hipster/en/search.shtml?token=borg&action=Search
.. _openSUSE official repository: https://software.opensuse.org/package/borgbackup
.. _Homebrew: https://formulae.brew.sh/formula/borgbackup
.. _private Tap: https://github.com/borgbackup/homebrew-tap
.. _Raspbian testing: https://archive.raspbian.org/raspbian/pool/main/b/borgbackup/
.. _Ubuntu packages: https://packages.ubuntu.com/xenial/borgbackup
.. _Ubuntu PPA: https://launchpad.net/~costamagnagianfranco/+archive/ubuntu/borgbackup

Please ask package maintainers to build a package or, if you can package /
submit it yourself, please help us with that! See :issue:`105` on
github to followup on packaging efforts.

**Current status of package in the repositories**

.. start-badges

|Packaging status|
 
.. |Packaging status| image:: https://repology.org/badge/vertical-allrepos/borgbackup.svg
        :alt: Packaging status
        :target: https://repology.org/project/borgbackup/versions

.. end-badges

.. _pyinstaller-binary:

Standalone Binary
-----------------

.. note:: Releases are signed with an OpenPGP key, see
          :ref:`security-contact` for more instructions.

|project_name| x86/x64 amd/intel compatible binaries (generated with `pyinstaller`_)
are available on the releases_ page for the following platforms:

* **Linux**: glibc >= 2.19 (ok for most supported Linux releases).
  Older glibc releases are untested and may not work.
* **MacOS**: 10.10 or newer (To avoid signing issues download the file via
  command line **or** remove the ``quarantine`` attribute after downloading:
  ``$ xattr -dr com.apple.quarantine borg-macosx64.tgz``)
* **FreeBSD**: 10.3 (unknown whether it works for older releases)

ARM binaries are built by Johann Bauer, see: https://borg.bauerj.eu/

To install such a binary, just drop it into a directory in your ``PATH``,
make borg readable and executable for its users and then you can run ``borg``::

    sudo cp borg-linux64 /usr/local/bin/borg
    sudo chown root:root /usr/local/bin/borg
    sudo chmod 755 /usr/local/bin/borg

Optionally you can create a symlink to have ``borgfs`` available, which is an
alias for ``borg mount``::

    ln -s /usr/local/bin/borg /usr/local/bin/borgfs

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

.. note::

  Some older Linux systems (like RHEL/CentOS 5) and Python interpreter binaries
  compiled to be able to run on such systems (like Python installed via Anaconda)
  might miss functions required by Borg.

  This issue will be detected early and Borg will abort with a fatal error.

Dependencies
~~~~~~~~~~~~

To install |project_name| from a source package (including pip), you have to install the
following dependencies first:

* `Python 3`_ >= 3.5.0, plus development headers. Even though Python 3 is not
  the default Python version on most systems, it is usually available as an
  optional install.
* OpenSSL_ >= 1.0.0, plus development headers.
* libacl_ (which depends on libattr_), both plus development headers.
* We have bundled code of the following packages, but borg by default (see
  setup.py if you want to change that) prefers a shared library if it can
  be found on the system (lib + dev headers) at build time:

  - liblz4_ >= 1.7.0 (r129)
  - libzstd_ >= 1.3.0
  - libb2_
* some Python dependencies, pip will automatically install them for you
* optionally, the llfuse_ Python package is required if you wish to mount an
  archive as a FUSE filesystem. See setup.py about the version requirements.

If you have troubles finding the right package names, have a look at the
distribution specific sections below or the Vagrantfile in the git repository,
which contains installation scripts for a number of operating systems.

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
    sudo dnf install gcc gcc-c++
    sudo dnf install redhat-rpm-config                 # not needed in Korora
    sudo dnf install fuse-devel fuse pkgconfig         # optional, for FUSE support

openSUSE Tumbleweed / Leap
++++++++++++++++++++++++++

Install the dependencies automatically using zypper::

    sudo zypper source-install --build-deps-only borgbackup

Alternatively, you can enumerate all build dependencies in the command line::

    sudo zypper install python3 python3-devel \
    libacl-devel openssl-devel \
    python3-Cython python3-Sphinx python3-msgpack-python \
    python3-pytest python3-setuptools python3-setuptools_scm \
    python3-sphinx_rtd_theme python3-llfuse gcc gcc-c++

macOS
+++++

When installing via Homebrew_, dependencies are installed automatically. To install
dependencies manually::

    brew install python3 openssl zstd lz4 xxhash
    brew install pkg-config
    pip3 install virtualenv

For FUSE support to mount the backup archives, you need at least version 3.0 of
macFUSE, which is available via `Github
<https://github.com/osxfuse/osxfuse/releases/latest>`__, or Homebrew::

    brew install --cask macfuse

For OS X Catalina and later, be aware that you must authorize full disk access.
It is no longer sufficient to run borg backups as root. If you have not yet
granted full disk access, and you run Borg backup from cron, you will see
messages such as::

    /Users/you/Pictures/Photos Library.photoslibrary: scandir: [Errno 1] Operation not permitted:

To fix this problem, you should grant full disk access to cron, and to your
Terminal application. More information `can be found here
<https://osxdaily.com/2020/04/27/fix-cron-permissions-macos-full-disk-access/>`__.

FreeBSD
++++++++
Listed below are packages you will need to install |project_name|, its dependencies,
and commands to make FUSE work for using the mount command.

::

     pkg install -y python3 openssl fusefs-libs pkgconf
     pkg install -y git
     python3 -m ensurepip  # to install pip for Python3
     To use the mount command:
     echo 'fuse_load="YES"' >> /boot/loader.conf
     echo 'vfs.usermount=1' >> /etc/sysctl.conf
     kldload fuse
     sysctl vfs.usermount=1


Windows 10's Linux Subsystem
++++++++++++++++++++++++++++

.. note::
    Running under Windows 10's Linux Subsystem is experimental and has not been tested much yet.

Just follow the Ubuntu Linux installation steps. You can omit the FUSE stuff, it won't work anyway.


Cygwin
++++++

.. note::
    Running under Cygwin is experimental and has not been tested much yet.

Use the Cygwin installer to install the dependencies::

    python3 python3-devel python3-setuptools
    binutils gcc-g++
    libopenssl openssl-devel
    git make openssh

You can then install ``pip`` and ``virtualenv``::

    easy_install-3.7 pip
    pip install virtualenv


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

    # might be required if your tools are outdated
    pip install -U pip setuptools wheel
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
While we try not to break master, there are no guarantees on anything.

::

    # get borg from github
    git clone https://github.com/borgbackup/borg.git

    virtualenv --python=python3 borg-env
    source borg-env/bin/activate   # always before using!

    # install borg + dependencies into virtualenv
    cd borg
    pip install -r requirements.d/development.txt
    pip install -r requirements.d/docs.txt  # optional, to build the docs
    pip install -r requirements.d/fuse.txt  # optional, for FUSE support
    pip install -e .  # in-place editable mode

    # optional: run all the tests, on all installed Python versions
    # requires fakeroot, available through your package manager
    fakeroot -u tox --skip-missing-interpreters

.. note:: As a developer or power user, you always want to use a virtual environment.
