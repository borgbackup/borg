Borg Changelog
==============


Version 0.25.0 (not released yet)
---------------------------------

Incompatible changes (compared to 0.24):

- none yet

Deprecations:

- none yet

New features:

- honor the nodump flag (UF_NODUMP) and do not backup such items

Bug fixes:

- close fds of segments we delete (during compaction)

Other changes:

- none yet


Version 0.24.0
--------------

Incompatible changes (compared to 0.23):

- borg now always issues --umask NNN option when invoking another borg via ssh
  on the repository server. By that, it's making sure it uses the same umask
  for remote repos as for local ones. Because of this, you must upgrade both
  server and client(s) to 0.24.
- the default umask is 077 now (if you do not specify via --umask) which might
  be a different one as you used previously. The default umask avoids that
  you accidentally give access permissions for group and/or others to files
  created by borg (e.g. the repository).

Deprecations:

- "--encryption passphrase" mode is deprecated, see #85 and #97.
  See the new "--encryption repokey" mode for a replacement.

New features:

- borg create --chunker-params ... to configure the chunker, fixes #16
  (attic #302, attic #300, and somehow also #41).
  This can be used to reduce memory usage caused by chunk management overhead,
  so borg does not create a huge chunks index/repo index and eats all your RAM
  if you back up lots of data in huge files (like VM disk images).
  See docs/misc/create_chunker-params.txt for more information.
- borg info now reports chunk counts in the chunk index.
- borg create --compression 0..9 to select zlib compression level, fixes #66
  (attic #295).
- borg init --encryption repokey (to store the encryption key into the repo),
  fixes #85
- improve at-end error logging, always log exceptions and set exit_code=1
- LoggedIO: better error checks / exceptions / exception handling
- implement --remote-path to allow non-default-path borg locations, #125
- implement --umask M and use 077 as default umask for better security, #117
- borg check: give a named single archive to it, fixes #139
- cache sync: show progress indication
- cache sync: reimplement the chunk index merging in C

Bug fixes:

- fix segfault that happened for unreadable files (chunker: n needs to be a
  signed size_t), #116
- fix the repair mode, #144
- repo delete: add destroy to allowed rpc methods, fixes issue #114
- more compatible repository locking code (based on mkdir), maybe fixes #92
  (attic #317, attic #201).
- better Exception msg if no Borg is installed on the remote repo server, #56
- create a RepositoryCache implementation that can cope with >2GiB,
  fixes attic #326.
- fix Traceback when running check --repair, attic #232
- clarify help text, fixes #73.
- add help string for --no-files-cache, fixes #140

Other changes:

- improved docs:

  - added docs/misc directory for misc. writeups that won't be included
    "as is" into the html docs.
  - document environment variables and return codes (attic #324, attic #52)
  - web site: add related projects, fix web site url, IRC #borgbackup
  - Fedora/Fedora-based install instructions added to docs
  - Cygwin-based install instructions added to docs
  - updated AUTHORS
  - add FAQ entries about redundancy / integrity
  - clarify that borg extract uses the cwd as extraction target
  - update internals doc about chunker params, memory usage and compression
  - added docs about development
  - add some words about resource usage in general
  - document how to backup a raw disk
  - add note about how to run borg from virtual env
  - add solutions for (ll)fuse installation problems
  - document what borg check does, fixes #138
  - reorganize borgbackup.github.io sidebar, prev/next at top
  - deduplicate and refactor the docs / README.rst

- use borg-tmp as prefix for temporary files / directories
- short prune options without "keep-" are deprecated, do not suggest them
- improved tox configuration
- remove usage of unittest.mock, always use mock from pypi
- use entrypoints instead of scripts, for better use of the wheel format and
  modern installs
- add requirements.d/development.txt and modify tox.ini
- use travis-ci for testing based on Linux and (new) OS X
- use coverage.py, pytest-cov and codecov.io for test coverage support

I forgot to list some stuff already implemented in 0.23.0, here they are:

New features:

- efficient archive list from manifest, meaning a big speedup for slow
  repo connections and "list <repo>", "delete <repo>", "prune" (attic #242,
  attic #167)
- big speedup for chunks cache sync (esp. for slow repo connections), fixes #18
- hashindex: improve error messages

Other changes:

- explicitly specify binary mode to open binary files
- some easy micro optimizations


Version 0.23.0
--------------

Incompatible changes (compared to attic, fork related):

- changed sw name and cli command to "borg", updated docs
- package name (and name in urls) uses "borgbackup" to have less collisions
- changed repo / cache internal magic strings from ATTIC* to BORG*,
  changed cache location to .cache/borg/ - this means that it currently won't
  accept attic repos (see issue #21 about improving that)

Bug fixes:

- avoid defect python-msgpack releases, fixes attic #171, fixes attic #185
- fix traceback when trying to do unsupported passphrase change, fixes attic #189
- datetime does not like the year 10.000, fixes attic #139
- fix "info" all archives stats, fixes attic #183
- fix parsing with missing microseconds, fixes attic #282
- fix misleading hint the fuse ImportError handler gave, fixes attic #237
- check unpacked data from RPC for tuple type and correct length, fixes attic #127
- fix Repository._active_txn state when lock upgrade fails
- give specific path to xattr.is_enabled(), disable symlink setattr call that
  always fails
- fix test setup for 32bit platforms, partial fix for attic #196
- upgraded versioneer, PEP440 compliance, fixes attic #257

New features:

- less memory usage: add global option --no-cache-files
- check --last N (only check the last N archives)
- check: sort archives in reverse time order
- rename repo::oldname newname (rename repository)
- create -v output more informative
- create --progress (backup progress indicator)
- create --timestamp (utc string or reference file/dir)
- create: if "-" is given as path, read binary from stdin
- extract: if --stdout is given, write all extracted binary data to stdout
- extract --sparse (simple sparse file support)
- extra debug information for 'fread failed'
- delete <repo> (deletes whole repo + local cache)
- FUSE: reflect deduplication in allocated blocks
- only allow whitelisted RPC calls in server mode
- normalize source/exclude paths before matching
- use posix_fadvise to not spoil the OS cache, fixes attic #252
- toplevel error handler: show tracebacks for better error analysis
- sigusr1 / sigint handler to print current file infos - attic PR #286
- RPCError: include the exception args we get from remote

Other changes:

- source: misc. cleanups, pep8, style
- docs and faq improvements, fixes, updates
- cleanup crypto.pyx, make it easier to adapt to other AES modes
- do os.fsync like recommended in the python docs
- source: Let chunker optionally work with os-level file descriptor.
- source: Linux: remove duplicate os.fsencode calls
- source: refactor _open_rb code a bit, so it is more consistent / regular
- source: refactor indicator (status) and item processing
- source: use py.test for better testing, flake8 for code style checks
- source: fix tox >=2.0 compatibility (test runner)
- pypi package: add python version classifiers, add FreeBSD to platforms


Attic Changelog
===============

Here you can see the full list of changes between each Attic release until Borg
forked from Attic:

Version 0.17
------------

(bugfix release, released on X)
- Fix hashindex ARM memory alignment issue (#309)
- Improve hashindex error messages (#298)

Version 0.16
------------

(bugfix release, released on May 16, 2015)
- Fix typo preventing the security confirmation prompt from working (#303)
- Improve handling of systems with improperly configured file system encoding (#289)
- Fix "All archives" output for attic info. (#183)
- More user friendly error message when repository key file is not found (#236)
- Fix parsing of iso 8601 timestamps with zero microseconds (#282)

Version 0.15
------------

(bugfix release, released on Apr 15, 2015)
- xattr: Be less strict about unknown/unsupported platforms (#239)
- Reduce repository listing memory usage (#163).
- Fix BrokenPipeError for remote repositories (#233)
- Fix incorrect behavior with two character directory names (#265, #268)
- Require approval before accessing relocated/moved repository (#271)
- Require approval before accessing previously unknown unencrypted repositories (#271)
- Fix issue with hash index files larger than 2GB.
- Fix Python 3.2 compatibility issue with noatime open() (#164)
- Include missing pyx files in dist files (#168)

Version 0.14
------------

(feature release, released on Dec 17, 2014)
- Added support for stripping leading path segments (#95)
  "attic extract --strip-segments X"
- Add workaround for old Linux systems without acl_extended_file_no_follow (#96)
- Add MacPorts' path to the default openssl search path (#101)
- HashIndex improvements, eliminates unnecessary IO on low memory systems.
- Fix "Number of files" output for attic info. (#124)
- limit create file permissions so files aren't read while restoring
- Fix issue with empty xattr values (#106)

Version 0.13
------------

(feature release, released on Jun 29, 2014)

- Fix sporadic "Resource temporarily unavailable" when using remote repositories
- Reduce file cache memory usage (#90)
- Faster AES encryption (utilizing AES-NI when available)
- Experimental Linux, OS X and FreeBSD ACL support (#66)
- Added support for backup and restore of BSDFlags (OSX, FreeBSD) (#56)
- Fix bug where xattrs on symlinks were not correctly restored
- Added cachedir support. CACHEDIR.TAG compatible cache directories
  can now be excluded using ``--exclude-caches`` (#74)
- Fix crash on extreme mtime timestamps (year 2400+) (#81)
- Fix Python 3.2 specific lockf issue (EDEADLK)

Version 0.12
------------

(feature release, released on April 7, 2014)

- Python 3.4 support (#62)
- Various documentation improvements a new style
- ``attic mount`` now supports mounting an entire repository not only
  individual archives (#59)
- Added option to restrict remote repository access to specific path(s):
  ``attic serve --restrict-to-path X`` (#51)
- Include "all archives" size information in "--stats" output. (#54)
- Added ``--stats`` option to ``attic delete`` and ``attic prune``
- Fixed bug where ``attic prune`` used UTC instead of the local time zone
  when determining which archives to keep.
- Switch to SI units (Power of 1000 instead 1024) when printing file sizes

Version 0.11
------------

(feature release, released on March 7, 2014)

- New "check" command for repository consistency checking (#24)
- Documentation improvements
- Fix exception during "attic create" with repeated files (#39)
- New "--exclude-from" option for attic create/extract/verify.
- Improved archive metadata deduplication.
- "attic verify" has been deprecated. Use "attic extract --dry-run" instead.
- "attic prune --hourly|daily|..." has been deprecated.
  Use "attic prune --keep-hourly|daily|..." instead.
- Ignore xattr errors during "extract" if not supported by the filesystem. (#46)

Version 0.10
------------

(bugfix release, released on Jan 30, 2014)

- Fix deadlock when extracting 0 sized files from remote repositories
- "--exclude" wildcard patterns are now properly applied to the full path
  not just the file name part (#5).
- Make source code endianness agnostic (#1)

Version 0.9
-----------

(feature release, released on Jan 23, 2014)

- Remote repository speed and reliability improvements.
- Fix sorting of segment names to ignore NFS left over files. (#17)
- Fix incorrect display of time (#13)
- Improved error handling / reporting. (#12)
- Use fcntl() instead of flock() when locking repository/cache. (#15)
- Let ssh figure out port/user if not specified so we don't override .ssh/config (#9)
- Improved libcrypto path detection (#23).

Version 0.8.1
-------------

(bugfix release, released on Oct 4, 2013)

- Fix segmentation fault issue.

Version 0.8
-----------

(feature release, released on Oct 3, 2013)

- Fix xattr issue when backing up sshfs filesystems (#4)
- Fix issue with excessive index file size (#6)
- Support access of read only repositories.
- New syntax to enable repository encryption:
    attic init --encryption="none|passphrase|keyfile".
- Detect and abort if repository is older than the cache.


Version 0.7
-----------

(feature release, released on Aug 5, 2013)

- Ported to FreeBSD
- Improved documentation
- Experimental: Archives mountable as fuse filesystems.
- The "user." prefix is no longer stripped from xattrs on Linux


Version 0.6.1
-------------

(bugfix release, released on July 19, 2013)

- Fixed an issue where mtime was not always correctly restored.


Version 0.6
-----------

First public release on July 9, 2013
