.. include:: global.rst.inc
.. _development:

Development
===========

This chapter will get you started with |project_name| development.

|project_name| is written in Python (with a little bit of Cython and C for
the performance critical parts).

Style guide
-----------

We generally follow `pep8
<https://www.python.org/dev/peps/pep-0008/>`_, with 120 columns
instead of 79. We do *not* use form-feed (``^L``) characters to
separate sections either. Compliance is tested automatically when
you run the tests.

Output and Logging
------------------
When writing logger calls, always use correct log level (debug only for
debugging, info for informative messages, warning for warnings, error for
errors, critical for critical errors/states).

When directly talking to the user (e.g. Y/N questions), do not use logging,
but directly output to stderr (not: stdout, it could be connected to a pipe).

To control the amount and kinds of messages output to stderr or emitted at
info level, use flags like ``--stats`` or ``--list``.

Building a development environment
----------------------------------

First, just install borg into a virtual env as described before.

To install some additional packages needed for running the tests, activate your
virtual env and run::

  pip install -r requirements.d/development.txt


Running the tests
-----------------

The tests are in the borg/testsuite package.

To run all the tests, you need to have fakeroot installed. If you do not have
fakeroot, you still will be able to run most tests, just leave away the
`fakeroot -u` from the given command lines.

To run the test suite use the following command::

  fakeroot -u tox  # run all tests

Some more advanced examples::

  # verify a changed tox.ini (run this after any change to tox.ini):
  fakeroot -u tox --recreate

  fakeroot -u tox -e py34  # run all tests, but only on python 3.4

  fakeroot -u tox borg.testsuite.locking  # only run 1 test module

  fakeroot -u tox borg.testsuite.locking -- -k '"not Timer"'  # exclude some tests

  fakeroot -u tox borg.testsuite -- -v  # verbose py.test

Important notes:

- When using ``--`` to give options to py.test, you MUST also give ``borg.testsuite[.module]``.


Regenerate usage files
----------------------

Usage and API documentation is currently committed directly to git,
although those files are generated automatically from the source
tree.

When a new module is added, the ``docs/api.rst`` file needs to be
regenerated::

  ./setup.py build_api

When a command is added, a commandline flag changed, added or removed,
the usage docs need to be rebuilt as well::

  ./setup.py build_usage

Building the docs with Sphinx
-----------------------------

The documentation (in reStructuredText format, .rst) is in docs/.

To build the html version of it, you need to have sphinx installed::

  pip3 install sphinx  # important: this will install sphinx with Python 3

Now run::

  cd docs/
  make html

Then point a web browser at docs/_build/html/index.html.

The website is updated automatically through Github web hooks on the
main repository.

Using Vagrant
-------------

We use Vagrant for the automated creation of testing environments and borgbackup
standalone binaries for various platforms.

For better security, there is no automatic sync in the VM to host direction.
The plugin `vagrant-scp` is useful to copy stuff from the VMs to the host.

Usage::

   # To create and provision the VM:
   vagrant up OS
   # To create an ssh session to the VM:
   vagrant ssh OS command
   # To shut down the VM:
   vagrant halt OS
   # To shut down and destroy the VM:
   vagrant destroy OS
   # To copy files from the VM (in this case, the generated binary):
   vagrant scp OS:/vagrant/borg/borg.exe .


Creating standalone binaries
----------------------------

Make sure you have everything built and installed (including llfuse and fuse).
When using the Vagrant VMs, pyinstaller will already be installed.

With virtual env activated::

  pip install pyinstaller  # or git checkout master
  pyinstaller -F -n borg-PLATFORM borg/__main__.py
  for file in dist/borg-*; do gpg --armor --detach-sign $file; done

If you encounter issues, see also our `Vagrantfile` for details.

.. note:: Standalone binaries built with pyinstaller are supposed to
          work on same OS, same architecture (x86 32bit, amd64 64bit)
          without external dependencies.


Creating a new release
----------------------

Checklist:

- make sure all issues for this milestone are closed or moved to the
  next milestone
- find and fix any low hanging fruit left on the issue tracker
- check that Travis CI is happy
- update ``CHANGES.rst``, based on ``git log $PREVIOUS_RELEASE..``
- check version number of upcoming release in ``CHANGES.rst``
- verify that ``MANIFEST.in`` and ``setup.py`` are complete
- ``python setup.py build_api ; python setup.py build_usage`` and commit
- tag the release::

    git tag -s -m "tagged/signed release X.Y.Z" X.Y.Z

- run tox and/or binary builds on all supported platforms via vagrant,
  check for test failures
- create a release on PyPi::

    python setup.py register sdist upload --identity="Thomas Waldmann" --sign

- close release milestone on Github
- announce on:

 - Mailing list
 - Twitter (follow @ThomasJWaldmann for these tweets)
 - IRC channel (change ``/topic``)

- create a Github release, include:

  * standalone binaries (see above for how to create them)

    + for OS X, document the OS X Fuse version in the README of the binaries.
      OS X FUSE uses a kernel extension that needs to be compatible with the
      code contained in the binary.
  * a link to ``CHANGES.rst``
