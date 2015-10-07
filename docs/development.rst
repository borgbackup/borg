.. include:: global.rst.inc
.. _development:

Development
===========

This chapter will get you started with |project_name|' development.

|project_name| is written in Python (with a little bit of Cython and C for
the performance critical parts).


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

  fakeroot -u tox -e py32  # run all tests, but only on python 3.2

  fakeroot -u tox borg.testsuite.locking  # only run 1 test module

  fakeroot -u tox borg.testsuite.locking -- -k '"not Timer"'  # exclude some tests

  fakeroot -u tox borg.testsuite -- -v  # verbose py.test

Important notes:

- When using -- to give options to py.test, you MUST also give borg.testsuite[.module].


Building the docs with Sphinx
-----------------------------

The documentation (in reStructuredText format, .rst) is in docs/.

To build the html version of it, you need to have sphinx installed::

  pip3 install sphinx  # important: this will install sphinx with Python 3

Now run::

  cd docs/
  make html

Then point a web browser at docs/_build/html/index.html.

Using Vagrant
-------------

We use Vagrant for the automated creation of testing environment and borgbackup
standalone binaries for various platforms.

For better security, there is no automatic sync in the VM to host direction.
The plugin `vagrant-scp` is useful to copy stuff from the VMs to the host.

Usage::

   To create and provision the VM:
     vagrant up OS
   To create an ssh session to the VM:
     vagrant ssh OS command
   To shut down the VM:
     vagrant halt OS
   To shut down and destroy the VM:
     vagrant destroy OS
   To copy files from the VM (in this case, the generated binary):
     vagrant scp OS:/vagrant/borg/borg/dist/borg .


Creating a new release
----------------------

Checklist::

- all issues for this milestone closed?
- any low hanging fruit left on the issue tracker?
- run tox on all supported platforms via vagrant, check for test fails.
- is Travis CI happy also?
- update CHANGES.rst (compare to git log). check version number of upcoming release.
- check MANIFEST.in and setup.py - are they complete?
- tag the release::

  git tag -s -m "tagged release" 0.26.0

- cd docs ; make html  # to update the usage include files
- update website with the html
- create a release on PyPi::

    python setup.py register sdist upload --identity="Thomas Waldmann" --sign

- close release milestone.
- announce on::

  - mailing list
  - Twitter
  - IRC channel (topic)

- create standalone binaries and link them from issue tracker: https://github.com/borgbackup/borg/issues/214


Creating standalone binaries
----------------------------

Make sure you have everything built and installed (including llfuse and fuse).

With virtual env activated::

  pip install pyinstaller>=3.0  # or git checkout master
  pyinstaller -F -n borg-PLATFORM --hidden-import=logging.config borg/__main__.py
  ls -l dist/*

If you encounter issues, see also our `Vagrantfile` for details.

Note: Standalone binaries built with pyinstaller are supposed to work on same OS,
      same architecture (x86 32bit, amd64 64bit) without external dependencies.
