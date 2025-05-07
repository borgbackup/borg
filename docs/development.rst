.. include:: global.rst.inc
.. highlight:: bash
.. _development:

Development
===========

This chapter will get you started with Borg development.

Borg is written in Python (with a little bit of Cython and C for
the performance critical parts).

Contributions
-------------

... are welcome!

Some guidance for contributors:

- Discuss changes on the GitHub issue tracker, on IRC or on the mailing list.

- Make your PRs on the ``master`` branch (see `Branching Model`_ for details and exceptions).

- Do clean changesets:

  - Focus on some topic, resist changing anything else.
  - Do not do style changes mixed with functional changes.
  - Try to avoid refactorings mixed with functional changes.
  - If you need to fix something after commit/push:

    - If there are ongoing reviews: do a fixup commit you can
      squash into the bad commit later.
    - If there are no ongoing reviews or you did not push the
      bad commit yet: amend the commit to include your fix or
      merge the fixup commit before pushing.
  - Have a nice, clear, typo-free commit comment.
  - If you fixed an issue, refer to it in your commit comment.
  - Follow the style guide (see below).

- If you write new code, please add tests and docs for it.

- Run the tests, fix any issues that come up.

- Make a pull request on GitHub.

- Wait for review by other developers.

Branching model
---------------

Borg development happens on the ``master`` branch and uses GitHub pull
requests (if you don't have GitHub or don't want to use it you can
send smaller patches via the borgbackup mailing list to the maintainers).

Stable releases are maintained on maintenance branches named ``x.y-maint``, eg.
the maintenance branch of the 1.4.x series is ``1.4-maint``.

Most PRs should be filed against the ``master`` branch. Only if an
issue affects **only** a particular maintenance branch a PR should be
filed against it directly.

While discussing / reviewing a PR it will be decided whether the
change should be applied to maintenance branches. Each maintenance
branch has a corresponding *backport/x.y-maint* label, which will then
be applied.

Changes that are typically considered for backporting:

- Data loss, corruption and inaccessibility fixes.
- Security fixes.
- Forward-compatibility improvements.
- Documentation corrections.

.. rubric:: Maintainer part

From time to time a maintainer will backport the changes for a
maintenance branch, typically before a release or if enough changes
were collected:

1. Notify others that you're doing this to avoid duplicate work.
2. Branch a backporting branch off the maintenance branch.
3. Cherry pick and backport the changes from each labelled PR, remove
   the label for each PR you've backported.

   To preserve authorship metadata, do not follow the ``git cherry-pick``
   instructions to use ``git commit`` after resolving conflicts. Instead,
   stage conflict resolutions and run ``git cherry-pick --continue``,
   much like using ``git rebase``.

   To avoid merge issues (a cherry pick is a form of merge), use
   these options (similar to the ``git merge`` options used previously,
   the ``-x`` option adds a reference to the original commit)::

     git cherry-pick --strategy recursive -X rename-threshold=5% -x

4. Make a PR of the backporting branch against the maintenance branch
   for backport review. Mention the backported PRs in this PR, e.g.:

       Includes changes from #2055 #2057 #2381

   This way GitHub will automatically show in these PRs where they
   were backported.

.. rubric:: Historic model

Previously (until release 1.0.10) Borg used a `"merge upwards"
<https://git-scm.com/docs/gitworkflows#_merging_upwards>`_ model where
most minor changes and fixes where committed to a maintenance branch
(eg. 1.0-maint), and the maintenance branch(es) were regularly merged
back into the main development branch. This became more and more
troublesome due to merges growing more conflict-heavy and error-prone.

How to submit a pull request
----------------------------

In order to contribute to Borg, you will need to fork the ``borgbackup/borg``
main repository to your own Github repository. Then clone your Github repository
to your local machine. The instructions for forking and cloning a repository
can be found there:
`<https://docs.github.com/en/get-started/quickstart/fork-a-repo>`_ .

Make sure you also fetched the git tags, because without them, ``setuptools-scm``
will run into issues determining the correct borg version. Check if ``git tag``
shows a lot of release tags (version numbers).
If it does not, use ``git fetch --tags`` to fetch them.

To work on your contribution, you first need to decide which branch your pull
request should be against. Often, this might be master branch (esp. for big /
risky contributions), but it could be also a maintenance branch like e.g.
1.4-maint (esp. for small fixes that should go into next maintenance release,
e.g. 1.4.x).

Start by checking out the appropriate branch:
::

    git checkout master

It is best practice for a developer to keep local ``master`` branch as an
uptodate copy of the upstream ``master`` branch and always do own work in a
separate feature or bugfix branch.
This is useful to be able to rebase own branches onto the upstream branches
they were branched from, if necessary.

This also applies to other upstream branches (like e.g. ``1.4-maint``), not
only to ``master``.

Thus, create a new branch now:
::

    git checkout -b MYCONTRIB-master  # choose an appropriate own branch name

Now, work on your contribution in that branch. Use these git commands:
::

    git status   # is there anything that needs to be added?
    git add ...  # if so, add it
    git commit   # finally, commit it. use a descriptive comment.

Then push the changes to your Github repository:
::

    git push --set-upstream origin MYCONTRIB-master

Finally, make a pull request on ``borgbackup/borg`` Github repository against
the appropriate branch (e.g. ``master``) so that your changes can be reviewed.

What to do if work was accidentally started in wrong branch
-----------------------------------------------------------

If you accidentally worked in ``master`` branch, check out the ``master``
branch and make sure there are no uncommitted changes. Then, create a feature
branch from that, so that your contribution is in a feature branch.
::

    git checkout master
    git checkout -b MYCONTRIB-master

Next, check out the ``master`` branch again. Find the commit hash of the last
commit that was made before you started working on your contribution and perform
a hard reset.
::

    git checkout master
    git log
    git reset --hard THATHASH

Then, update the local ``master`` branch with changes made in the upstream
repository.
::

    git pull borg master

Rebase feature branch onto updated master branch
------------------------------------------------

After updating the local ``master`` branch from upstream, the feature branch
can be checked out and rebased onto (the now uptodate) ``master`` branch.
::

    git checkout MYCONTRIB-master
    git rebase -i master

Next, check if there are any commits that exist in the feature branch
but not in the ``master`` branch and vice versa. If there are no
conflicts or after resolving them, push your changes to your Github repository.
::

    git log
    git diff master
    git push -f

Code and issues
---------------

Code is stored on GitHub, in the `Borgbackup organization
<https://github.com/borgbackup/borg/>`_. `Issues
<https://github.com/borgbackup/borg/issues>`_ and `pull requests
<https://github.com/borgbackup/borg/pulls>`_ should be sent there as
well. See also the :ref:`support` section for more details.

Style guide / Automated Code Formatting
---------------------------------------

We use `black`_ for automatically formatting the code.

If you work on the code, it is recommended that you run black **before each commit**
(so that new code is always using the desired formatting and no additional commits
are required to fix the formatting).
::

    pip install -r requirements.d/codestyle.txt     # everybody use same black version
    black --check .                                 # only check, don't change
    black .                                         # reformat the code


The CI workflows will check the code formatting and will fail if it is not formatted correctly.

When (mass-)reformatting existing code, we need to avoid ruining `git blame`, so please
follow their `guide about avoiding ruining git blame`_:

.. _black: https://black.readthedocs.io/
.. _guide about avoiding ruining git blame: https://black.readthedocs.io/en/stable/guides/introducing_black_to_your_project.html#avoiding-ruining-git-blame

Continuous Integration
----------------------

All pull requests go through `GitHub Actions`_, which runs the tests on misc.
Python versions and on misc. platforms as well as some additional checks.

.. _GitHub Actions: https://github.com/borgbackup/borg/actions

Output and Logging
------------------
When writing logger calls, always use correct log level (debug only for
debugging, info for informative messages, warning for warnings, error for
errors, critical for critical errors/states).

When directly talking to the user (e.g. Y/N questions), do not use logging,
but directly output to stderr (not: stdout, it could be connected to a pipe).

To control the amount and kinds of messages output emitted at info level, use
flags like ``--stats`` or ``--list``, then create a topic logger for messages
controlled by that flag.  See ``_setup_implied_logging()`` in
``borg/archiver.py`` for the entry point to topic logging.

Building a development environment
----------------------------------

First, just install borg into a virtual env :ref:`as described before <git-installation>`.

To install some additional packages needed for running the tests, activate your
virtual env and run::

  pip install -r requirements.d/development.txt


This project utilizes pre-commit to format and lint code before it is committed.
Although pre-commit is installed when running the command above, the pre-commit hooks
will have to be installed separately. Run this command to install the pre-commit hooks::

  pre-commit install

Running the tests
-----------------

The tests are in the borg/testsuite package.

To run all the tests, you need to have fakeroot installed. If you do not have
fakeroot, you still will be able to run most tests, just leave away the
``fakeroot -u`` from the given command lines.

To run the test suite use the following command::

  fakeroot -u tox  # run all tests

Some more advanced examples::

  # verify a changed tox.ini (run this after any change to tox.ini):
  fakeroot -u tox --recreate

  fakeroot -u tox -e py313  # run all tests, but only on python 3.13

  fakeroot -u tox borg.testsuite.locking  # only run 1 test module

  fakeroot -u tox borg.testsuite.locking -- -k '"not Timer"'  # exclude some tests

  fakeroot -u tox borg.testsuite -- -v  # verbose py.test

Important notes:

- When using ``--`` to give options to py.test, you MUST also give ``borg.testsuite[.module]``.

Running the tests (using the pypi package)
------------------------------------------

Since borg 1.4, it is also possible to run the tests without a development
environment, using the borgbackup dist package (downloaded from pypi.org or
github releases page):
::

    # optional: create and use a virtual env:
    python3 -m venv env
    . env/bin/activate

    # install packages
    pip install borgbackup
    pip install pytest pytest-benchmark

    # run the tests
    pytest -v -rs --benchmark-skip --pyargs borg.testsuite

Adding a compression algorithm
------------------------------

If you want to add a new compression algorithm, please refer to :issue:`1633`
and leave a post there in order to discuss about the proposal.

Documentation
-------------

Generated files
~~~~~~~~~~~~~~~

Usage documentation (found in ``docs/usage/``) and man pages
(``docs/man/``) are generated automatically from the command line
parsers declared in the program and their documentation, which is
embedded in the program (see archiver.py). These are committed to git
for easier use by packagers downstream.

When a command is added, a command line flag changed, added or removed,
the usage docs need to be rebuilt as well::

  python scripts/make.py build_usage
  python scripts/make.py build_man

However, we prefer to do this as part of our :ref:`releasing`
preparations, so it is generally not necessary to update these when
submitting patches that change something about the command line.

Building the docs with Sphinx
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The documentation (in reStructuredText format, .rst) is in docs/.

To build the html version of it, you need to have Sphinx installed
(in your Borg virtualenv with Python 3)::

  pip install -r requirements.d/docs.txt

Now run::

  cd docs/
  make html

Then point a web browser at docs/_build/html/index.html.

The website is updated automatically by ReadTheDocs through GitHub web hooks on the
main repository.

Using Vagrant
-------------

We use Vagrant for the automated creation of testing environments and borgbackup
standalone binaries for various platforms.

For better security, there is no automatic sync in the VM to host direction.
The plugin `vagrant-scp` is useful to copy stuff from the VMs to the host.

The "windows10" box requires the `reload` plugin (``vagrant plugin install vagrant-reload``).

Usage::

   # To create and provision the VM:
   vagrant up OS
   # same, but use 6 VM cpus and 12 workers for pytest:
   VMCPUS=6 XDISTN=12 vagrant up OS
   # To create an ssh session to the VM:
   vagrant ssh OS
   # To execute a command via ssh in the VM:
   vagrant ssh OS -c "command args"
   # To shut down the VM:
   vagrant halt OS
   # To shut down and destroy the VM:
   vagrant destroy OS
   # To copy files from the VM (in this case, the generated binary):
   vagrant scp OS:/vagrant/borg/borg.exe .

Creating standalone binaries
----------------------------

Make sure you have everything built and installed (including fuse stuff).
When using the Vagrant VMs, pyinstaller will already be installed.

With virtual env activated::

  pip install pyinstaller  # or git checkout master
  pyinstaller -F -n borg-PLATFORM borg/__main__.py
  for file in dist/borg-*; do gpg --armor --detach-sign $file; done

If you encounter issues, see also our `Vagrantfile` for details.

.. note:: Standalone binaries built with pyinstaller are supposed to
          work on same OS, same architecture (x86 32bit, amd64 64bit)
          without external dependencies.

.. _releasing:

Creating a new release
----------------------

Checklist:

- Make sure all issues for this milestone are closed or moved to the
  next milestone.
- Check if there are any pending fixes for security issues.
- Find and fix any low hanging fruit left on the issue tracker.
- Check that GitHub Actions CI is happy.
- Update ``CHANGES.rst``, based on ``git log $PREVIOUS_RELEASE..``.
- Check version number of upcoming release in ``CHANGES.rst``.
- Render ``CHANGES.rst`` via ``make html`` and check for markup errors.
- Verify that ``MANIFEST.in``, ``pyproject.toml`` and ``setup.py`` are complete.
- Run these commands and commit::

    python scripts/make.py build_usage
    python scripts/make.py build_man

- Tag the release::

    git tag -s -m "tagged/signed release X.Y.Z" X.Y.Z

- Create a clean repo and use it for the following steps::

    git clone borg borg-clean

  This makes sure no uncommitted files get into the release archive.
  It will also reveal uncommitted required files.
  Moreover, it makes sure the vagrant machines only get committed files and
  do a fresh start based on that.
- Run tox and/or binary builds on all supported platforms via vagrant,
  check for test failures.
- Create sdist, sign it, upload release to (test) PyPi:

  ::

    scripts/sdist-sign X.Y.Z
    scripts/upload-pypi X.Y.Z test
    scripts/upload-pypi X.Y.Z

  Note: the signature is not uploaded to PyPi any more, but we upload it to
  github releases.
- Put binaries into dist/borg-OSNAME and sign them:

  ::

    scripts/sign-binaries 201912312359

- Close the release milestone on GitHub.
- `Update borgbackup.org
  <https://github.com/borgbackup/borgbackup.github.io/pull/53/files>`_ with the
  new version number and release date.
- Announce on:

  - Mailing list.
  - Mastodon / BlueSky / X (aka Twitter).
  - IRC channel (change ``/topic``).

- Create a GitHub release, include:

  - pypi dist package and signature
  - Standalone binaries (see above for how to create them).

    - For macOS, document the macFUSE version in the README of the binaries.
      macFUSE uses a kernel extension that needs to be compatible with the
      code contained in the binary.
  - A link to ``CHANGES.rst``.
