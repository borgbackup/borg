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

  pip3 install sphinx

Now run::

  cd docs/
  make html

Then point a web browser at docs/_build/html/index.html.
