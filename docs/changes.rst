.. _important_notes:

Important notes 2.x
===================

This section provides information about security and corruption issues.

(nothing to see here yet)

.. _upgradenotes2:

Upgrade Notes
=============

borg 1.2.x/1.4.x to borg 2.0
----------------------------

Compatibility notes:

- this is a major "breaking" release that is not compatible with existing repos.

  We tried to put all the necessary "breaking" changes into this release, so we
  hopefully do not need another breaking release in the near future. The changes
  were necessary for improved security, improved speed and parallelism,
  unblocking future improvements, getting rid of legacy crap and design
  limitations, having less and simpler code to maintain.

  You can use "borg transfer" to transfer archives from borg 1.2/1.4 repos to
  a new borg 2.0 repo, but it will need some time and space.

  Before using "borg transfer", you must have upgraded to borg >= 1.2.6 (or
  another borg version that was patched to fix CVE-2023-CVE-2023-36811) and
  you must have followed the upgrade instructions at top of the change log
  relating to manifest and archive TAMs (borg2 just requires these TAMs now).

- command line syntax was changed, scripts and wrappers will need changes:

  - you will usually either export BORG_REPO=<MYREPO> into your environment or
    call borg like: "borg -r <MYREPO> <COMMAND>".
    in the docs, we usually omit "-r ..." for brevity.
  - the scp-style REPO syntax was removed, please use ssh://..., #6697
  - ssh:// URLs: removed support for /~otheruser/, /~/ and /./, #6855.
    New format:

    - ssh://user@host:port/relative/path
    - ssh://user@host:port//absolute/path
  - -P / --prefix option was removed, please use the similar -a / --match-archives.
  - archive names don't need to be unique anymore. to the contrary:
    it is now strongly recommended to use the identical name for borg create
    within the same series of archives to make borg work more efficiently.
    the name now identifies a series of archive, to identify a single archive
    please use aid:<archive-hash-prefix>, e.g.: borg delete aid:d34db33f
  - in case you do NOT want to adopt the "series name" way of naming archives
    (like "myarchive") as we recommend, but keep using always-changing names
    (like "myserver-myarchive-20241231"), you can do that, but then you must
    make use of BORG_FILES_CACHE_SUFFIX and either set it to a constant suffix
    (like "all") or to a unique suffix per archive series (like
    "myserver-myarchive") so that borg can find the correct files cache.
    For the "all" variant, you must also set BORG_FILES_CACHE_TTL to a value
    greater than the count of different archives series you write to that repo.
    Usually borg uses a different files cache suffix per archive (series) name
    and defaults to BORG_FILES_CACHE_TTL=2 because that is sufficient for that.
  - the archive id is always given separately from the repository
    (differently than with borg 1.x you must not give repo::archive).
  - the series name or archive id is either given as a positional parameter,
    like:

    - borg create documents ~/Documents
    - borg diff aid:deadbeef aid:d34db33f
  - or, if the command makes sense for an arbitrary amount of archives, archives
    can be selected using a glob pattern, like:

    - borg delete -a 'sh:myarchive-2024-??-??'
    - borg recreate -a 'sh:myarchive-2024-??-??'
  - some borg 1.x commands that supported working on a repo AND on an archive
    were split into 2 commands, some others were renamed:

    - borg 2 repo commands:

      - borg repo-create  # was: borg init
      - borg repo-list
      - borg repo-info
      - borg repo-delete
      - borg repo-compress
      - borg repo-space
    - borg 2 archive commands:

      - borg create NAME ...
      - borg list ID
      - borg extract ID ...
      - borg diff ID1 ID2
      - borg rename ID NEWNAME
      - borg info ID
      - borg delete ID
      - borg recreate ID ...
      - borg mount -a ID mountpoint ...

    For more details, please consult the docs or --help option output.
  - create/recreate/import-tar --timestamp: defaults to local timezone
    now (was: UTC)
- some deprecated options were removed:

  - removed --remote-ratelimit (use --upload-ratelimit)
  - removed --numeric-owner (use --numeric-ids)
  - removed --nobsdflags (use --noflags)
  - removed --noatime (default now, see also --atime)
  - removed --save-space option (does not change behaviour)
- removed --bypass-lock option
- removed borg config command (only worked locally anyway)
- compact command now requires access to the borg key if the repo is encrypted
  or authenticated
- using --list together with --progress is now disallowed (except with --log-json), #7219
- the --glob-archives option was renamed to --match-archives (the short option
  name -a is unchanged) and extended to support different pattern styles:

  - id: for identical string match (this is the new default!)
  - sh: for shell pattern / globbing match (this was used by --glob-archives)
  - re: for regular expression match

  So you might need to edit your scripts like e.g.::

      borg 1.x: --glob-archives 'myserver-2024-*'
      borg 2.0: --match-archives 'sh:myserver-2024-*'

- use platformdirs 3.x.x instead of home-grown code. Due to that:

  - XDG_*_HOME is not honoured on macOS and on Windows.
  - BORG_BASE_DIR can still be used to enforce some base dir + .config/ or .cache/.
  - the default macOS config and cache dir will now be in ~/Library/Application Support/borg/.
- create: different included/excluded status chars, #7321

  - dry-run: now uses "+" (was: "-") and "-" (was: "x") for included/excluded status
  - non-dry-run: now uses "-" (was: "x") for excluded files

  Option --filter=... might need an update, if you filter for the status chars
  that were changed.
- borg is now more strict and disallows giving some options multiple times -
  if that makes no sense. Highlander options, see #6269. That might make scripts
  fail now that somehow "worked" before (but maybe didn't work as intended due to
  the contradicting options).

.. _changelog:

Change Log 2.x
==============

Version 2.0.0b17 (2025-05-23)
-----------------------------

Please note:

Beta releases are only for testing on NEW repos - do not use for production.

For upgrade and compatibility hints, please also read the section "Upgrade Notes"
above.

New features:

- transfer: implement --chunker-params to re-chunk while transferring, #8706
- list --depth=N: list files up to N depth in path hierarchy, #8268
- compact: also clean up files cache, #8852
- `BORG_REPO_PERMISSIONS=all|no-delete|write-only|read-only`, #8823

  The posixfs borgstore backend implements permissions to make
  testing with differently permissive stores easier.

  The env var selects from pre-defined permission configurations
  within borg and gives the chosen permissions config to borgstore.
  borg uses borgstore's posixfs backend only for file: and ssh: repos.

Fixes:

- correct the signature of __set_name__ as cython 3.1 added support,
  fixing build on Cython 3.1, #6858
- compact/check: fix bug not writing the complete index, #8813
- compact: add --iec option, #8831
- check/compact/analyze: show archive timestamp in local tz, #8814
- repo-space: enable ssh: repo testing, fix AttributeError, #8815
- repo-info: fix output formatting

Other changes:

- require borgstore 0.3.x
- some updates and fixes for shell completions, needs more work
- dir_is_tagged/_is_cachedir: add fd-based operations
- cython: suppress compiler warning about CYTHON_FALLTHROUGH in unreachable code
- source code: `pyupgrade --py310-plus ./**/*.py`
- tests:

  - add/improve tests for repo-compress --stats, transfer, repo-space
  - split helpers tests from a single module into borg.testsuite.helpers package
  - save temp space (good for ramdisk users)
  - fix diff cmd test on macOS HFS+, #8860
  - test validity of shell completion files
  - CI: fix and enable windows CI, #8728
  - CI: upload coverage for windows tests
  - CI: install zsh and fish so we can test shell completions
- docs:

  - must have the release tags in the local repo, #8582
  - remove outdated docs/man files about borg change-passphrase
  - add S3/B2 urls to documentation for repository urls, #8833


Version 2.0.0b16 (2025-05-06)
-----------------------------

Fixes:

- chunks cache: invalidate old chunk index cache, #8795
- compact: always write updated chunkindex to repo, #8791
- ChunksMixin: don't use self._chunks until it is demand-built, #8785
- AdhocWithFilesCache: fix call to _maybe_write_chunks_cache
- format_time: output date/time in local tz, #8802
- check: ask for key passphrase early, #1931
- only obfuscate the size of file content chunks, #7559
- better support other repo by misc. passphrase env vars, #8457

  - passphrases now come from `BORG_[OTHER_]PASSPHRASE`, `BORG_[OTHER_]PASSCOMMAND`
    or `BORG_[OTHER_]PASSPHRASE_FD`.
  - `borg repo-create --repo B --other-repo A` does not silently copy the
    passphrase of key A to key B anymore, but either asks for the passphrase
    or reads it from env vars.

Other changes:

- remove support for / testing on Python 3.9
- docs: borg serve --repo is not supported, #8591
- remove remainders of append-only and quota support
- remove cygwin < 2.8.0 bug workaround
- fix remote api versioning


Version 2.0.0b15 (2025-04-22)
-----------------------------

New features:

- compact: without --stats, it will be faster by using the cached chunks index.
  with --stats it will be as slow as before, listing all repo objs.
- compact: support --dry-run (do nothing), #8300
- extract: --dry-run now displays +/- status flags (included/excluded), #8564
- allow timespan to be specified with common time units, #8624
- enhance passphrase handling, #8496.

  Setting `BORG_DEBUG_PASSPHRASE=YES` enables passphrase debug logging to
  stderr, showing passphrase, hex utf-8 byte sequence and related env vars if
  a wrong passphrase was encountered.

  Setting `BORG_DISPLAY_PASSPHRASE=YES` now always shows passphrase and its hex
  utf-8 byte sequence.
- add {unixtime} placeholder, #8522
- implement padme chunk size obfuscation (SPEC 250), #8705
- macOS: retrieve birthtime in nanosecond precision via system call, #8724

Bug fixes:

- borg exits when assertions are disabled with Python optimizations, #8649
- yes(): deal with UnicodeDecodeError in input(), #6984
- fix remote repository exception handling / modern exit codes, #8631
- freebsd: fix nfs4 acl processing, #8756.
  This issue only affected borg extract --numeric-ids when processing NFS4
  ACLs, it didn't affect POSIX ACL processing.

Other changes:

- adapt to and require borghash 0.1.0
- adapt to and require borgstore 0.2.0 (new s3/b2 backend, fixes/improvements)
- create: remove --make-parent-dirs option (borgstore now does this automatically), #8619
- iter_items: decouple item iteration and content data chunks preloading
- remote: simplify code, add debug logging
- pyproject.toml: SPDX expression for license, add license-files, #8771
- Item: remove .chunks_healthy, #8559
- OpenBSD fixes:

  - support other OpenSSL versions on OpenBSD, #8553
  - vagrant: fix OpenBSD box, #8506
  - Filter test output with LibreSSL related warnings on OpenBSD
- macOS: fix brew's broken pkg-config -> pkgconf transition
- tests: ignore 'com.apple.provenance' xattr (macOS specific)
- vagrant updates:

  - use pyinstaller 6.11.1 (also use this in msys2 build scripts)
  - use python 3.12.10
  - build binaries with borgstore[sftp], #8574
- docs:

  - automated backup: append to SYSTEMD_WANTS rather than overwrite, #8641
  - fix udev rule priority in automated-local.rst, #8639
  - FAQ: Why backups are slow on a Linux server that is a member of a windows domain? #8636
  - within a shell, cli options with special characters may require quoting, #8578
  - update prune documentation for new --keep-within intervals, #8630
  - borg serve: recommend using a simple shell, #3818
  - update install docs (requirements, pkgconfig, fuse), #8342
  - libffi-dev is required for argon2-cffi-bindings
  - add undelete command to index
  - borg commands updated with --repo option, #8550
  - FAQ: add entry about pure-python msgpack warning, #8323
  - readthedocs theme fixes

    - bring back highlighted content preview in search results.
    - fix erroneous warning about missing javascript support.


Version 2.0.0b14 (2024-11-17)
-----------------------------

New features:

- delete: now only soft-deletes archives (same for prune)
- repo-list: --deleted lists deleted archives
- undelete: undelete soft-deleted archives, #8500

Fixes:

- chunks index cache:

  - enable partial/incremental updates (F_NEW flag).
  - write chunks index every 10mins, #8503.
    this makes sure progress is not totally lost when a backup is interrupted.
  - write to repo/cache/chunks.<HASH> to enable parallel updates.
- mount: fix check_pending_archive to give correct root dir, #8528

Other changes:

- repo-compress: reduce memory consumption (F_COMPRESS flag)
- files cache: reduce memory consumption, #5756
- check: rename --undelete-archives to --find-lost-archives
- check: rebuild_archives_directory: accelerate by only reading metadata
- shell completions: adapt zsh for borg 2.0.0b13 - needs more work!
- chunk index: rename .refcount to .flags, use it for user and system flags.
- vagrant:

  - add bookworm32 box for 32bit platform testing
  - fix pythons on freebsd14
  - simplify openindiana box setup
- docs:

  - remove --bypass-lock, small changes regarding compression
  - FAQ: clean up entries regarding SSH settings


Version 2.0.0b13 (2024-10-31)
-----------------------------

New features:

- implement special tags, @PROT tag for protecting archives, #953.

  borg won't delete/prune/recreate protected archives.
- prune: add quarterly pruning strategy, #8337.
- import-tar/export-tar: add xattr support for PAX format, #2521.

Fixes:

- simple error msgs for existing / non-existing repo, no tracebacks, #8475.
- mount: create unique directory names, #8461.
- diff: suppress modified changes for files which weren't actually modified.
- diff: do not test for ctime difference on windows.
- prune: fix exception when NAME is given, #8486
- repo-create: build and cache an empty ChunkIndex.
- work around missing size/nfiles archive metadata, #8491
- lock after checking repo exists, #8485

Other changes:

- new file:, rclone:, ssh:, sftp: URLs, #8372, #8446.

  new way to deal with absolute vs. relative paths.
- require borgstore ~= 0.1.0, require borghash ~= 0.0.1.
- new hashtable code based on borghash project:

  - borghash replaces old / hard to maintain _hashindex.c code.
  - implement ChunkIndex, NSIndex1, FuseVersionsIndex using borghash.HashTableNT.
  - rewrite NSIndex1 (borg 1.x) on-disk format read/write methods in Cython.
  - remove NSIndex (early borg2) data structure / serialization code for repo index.
  - change xxh64 seed for ChunkIndex to invalidate old cache contents.
  - chunks index: show hashtable stats at debug log level, #506.
- check (repository part): build and cache a ChunkIndex.

  check (archives part): use cached ChunkIndex from check (repository part).
- export-tar: switch default to PAX format.
- docs:

  - update URL docs
  - mount: document on-demand loading, perf tips, #7173.
  - borg/borgfs detects internally under which name it was invoked, #8207.
  - better link modern return codes, #8370.
  - binary: using the directory build is faster, #8008.
  - update "Running the tests (using the pypi package)", #6386.
- github CI:

  - temporarily disabled windows CI, #8474.
  - msys2: use pyinstaller 6.10.0.
  - msys2: install rclone.
- tests:

  - rename test files so that pytest default discovery finds them.
  - call register_assert_rewrite before importing borg.testsuite.
  - move conftest.py one directory level higher.
  - remove hashindex tests from selftests (borghash project has own tests).


Version 2.0.0b12 (2024-10-03)
-----------------------------

New features:

- tag: new command to set, add, remove tags.
- repo-list: add tags/hostname/username/comment to default format, reorder, adjust.

  Idea: not putting these into the archive name, but keeping them separate.
- repo-list --short: only print archive IDs (unique IDs, used for scripting).
- implement --match-archives user:USERNAME host:HOSTNAME tags:TAG1,TAG2,...
- allow -a / --match-archives multiple times (logical AND).

  E.g.: borg delete -a home -a user:kenny -a host:kenny-pc
- analyze: list changed chunks' sizes per directory.

Fixes:

- locking: also refresh the lock in other repo methods. avoid repo lock
  getting stale when processing lots of unchanged files, #8442.
- make sure the store gets closed in case of exceptions, #8413.
- msgpack: increase max_buffer_size to ~4GiB, #8440.
- Location.canonical_path: fix protocol and host display, #8446.

Other changes:

- give borgstore.Store a complete levels configuration, #8432.
- add BORG_STORE_DATA_LEVELS=2 env var.
- check: also display archive timestamp.
- vagrant:

  - use python 3.12.6 for binary builds.
  - new testing box based on bento/ubuntu-24.04.
  - install Rust on BSD.


Version 2.0.0b11 (2024-09-26)
-----------------------------

New features:

- Support rclone:// URLs for borg repositories.

  This enables 70+ cloud storage products, including Amazon S3, Backblaze B2,
  Ceph, Dropbox, ftp(s), Google Cloud Storage, Google Drive, Microsoft Azure,
  Microsoft OneDrive, OpenStack Swift, pCloud, Seafile, sftp, SMB / CIFS and
  WebDAV!

  See https://rclone.org/ for more details.
- Parallel operations in same repo from same client (same user/machine).
- Archive series feature, #7930.

  TL;DR: a NAME now identifies a series of identically named archives,
  to identify a specific single archive, use aid:<archive hash>.

  in borg 1.x, we used to put a timestamp into the archive name, because borg1
  required unique archive names.

  borg2 does not require unique archive names, but it encourages you to even
  use a identical archive names within the same SERIES of archives, e.g. you
  could backup user files to archives named "user-files" and system files to
  archives named "system-files".
  that makes matching (e.g. for prune, for the files cache, ...) much simpler
  and borg now KNOWS which archives belong to the same series (because they all
  have the same name).
- info/delete/prune: allow positional NAME argument, e.g.:

  - borg prune --keep-daily 30 <seriesname>
  - borg delete aid:<archive hash>
- create: also archive inode number, #8362

  Borg can use this when using archive series to rebuild the local files cache
  from the previous archive (of the same series) in the repository.

Fixes:

- Remove superfluous repository.list() call. for high latency repos
  (like sftp, cloud), this improves performance of borg check and compact.
- repository.list: refresh lock more frequently
- misc. commands fixed for non-unique archive names
- remote: allow get_manifest method
- files cache: fix rare race condition with data loss potential, #3536
- storelocking: misc. fixes / cleanups

Other changes:

- Cache the chunks index in the repository, #8397.
  Improves high latency repo performance for most commands compared to b10.
- repo-compress: faster by using chunks index rather than repository.list().
- Files cache entries now have both ctime AND mtime.
- Borg updates the ctime and mtime of known and "unchanged" files, #4915.
- Rebuild files cache from previous archive in same series, #8385.
- Reduce RAM usage by splitting the files cache by archive series, #5658.
- Remove AdHocCache, remove BORG_CACHE_IMPL (we only have one implementation).
- Docs: user@ and :port are optional in sftp and ssh URLs.
- CI: re-enable windows build after fixing it.
- Upgrade pyinstaller to 6.10.0.
- Increase IDS_PER_CHUNK, #6945.


Version 2.0.0b10 (2024-09-09)
-----------------------------

New features:

- borgstore based repository, file:, ssh: and sftp: for now, more possible.
- repository stores objects separately now, not using segment files.
  this has more fs overhead, but needs much less I/O because no segment
  files compaction is required anymore. also, no repository index is
  needed anymore because we can directly find the objects by their ID.
- locking: new borgstore based repository locking with automatic stale
  lock removal (if lock does not get refreshed, if lock owner process is dead).
- simultaneous repository access for many borg commands except check/compact.
  the cache lock for adhocwithfiles is still exclusive though, so use
  BORG_CACHE_IMPL=adhoc if you want to try that out using only 1 machine
  and 1 user (that implementation doesn't use a cache lock). When using
  multiple client machines or users, it also works with the default cache.
- delete/prune: much quicker now and can be undone.
- check --repair --undelete-archives: bring archives back from the dead.
- repo-space: manage reserved space in repository (avoid dead-end situation if
  repository filesystem runs full).

Bugs/issues fixed:

- a lot! all linked from PR #8332.

Other changes:

- repository: remove transactions, solved differently and much simpler now
  (convergence and write order primarily).
- repository: replaced precise reference counting with "object exists in repo?"
  and "garbage collection of unused objects".
- cache: remove transactions, remove chunks cache.
  removed LocalCache, BORG_CACHE_IMPL=local, solving all related issues.
  as in beta 9, adhowwithfiles is the default implementation.
- compact: needs the borg key now (run it clientside), -v gives nice stats.
- transfer: archive transfers from borg 1.x need the --from-borg1 option
- check: reimplemented / bigger changes.
- code: got rid of a metric ton of not needed complexity.
  when borg does not need to read borg 1.x repos/archives anymore, after
  users have transferred their archives, even much more can be removed.
- docs: updated / removed outdated stuff
- renamed r* commands to repo-*


Version 2.0.0b9 (2024-07-20)
----------------------------

New features:

- add BORG_CACHE_IMPL, default is "adhocwithfiles" to test the new cache
  implementation, featuring an adhoc non-persistent chunks cache and a
  persistent files cache. See the docs for other values.

  Requires to run "borg check --repair --archives-only" to delete orphaned
  chunks before running "borg compact" to free space! These orphans are
  expected due to the simplified refcounting with the AdHocFilesCache.
- make BORG_EXIT_CODES="modern" the default, #8110
- add BORG_USE_CHUNKS_ARCHIVE env var, #8280
- automatically rebuild cache on exception, #5213

Bug fixes:

- fix Ctrl-C / SIGINT behaviour for pyinstaller-made binaries, #8155
- delete: fix error handling with Ctrl-C
- rcompress: fix error handling with Ctrl-C
- delete: fix error handling when no archive is specified, #8256
- setup.py: fix import error reporting for cythonize import, see #8208
- create: deal with EBUSY, #8123
- benchmark: inherit options --rsh --remote-path, #8099
- benchmark: fix return value, #8113
- key export: fix crash when no path is given, fix exception handling

Other changes:

- setup.py: detect noexec build fs issue, see #8208
- improve acl_get / acl_set error handling (forward port from 1.4-maint)
- allow msgpack 1.1.0
- vagrant: use pyinstaller 6.7.0
- use Python 3.11.9 for binary builds
- require Cython 3.0.3 at least, #8133
- docs: add non-root deployment strategy


Version 2.0.0b8 (2024-02-20)
----------------------------

New features:

- create: add the slashdot hack, update docs, #4685
- BORG_EXIT_CODES=modern: optional more specific return codes (for errors and warnings).

  The default value of this new environment variable is "legacy", which should result in
  a behaviour similar to borg 1.2 and older (only using rc 0, 1 and 2).
  "modern" exit codes are much more specific (see the internals/frontends docs).
- implement "borg version" (shows client and server version), #7829

Fixes:

- docs: CVE-2023-36811 upgrade steps: consider checkpoint archives, #7802
- check/compact: fix spurious reappearance of orphan chunks since borg 1.2, #6687 -
  this consists of 2 fixes:

  - for existing chunks: check --repair: recreate shadow index, #7897 #6687
  - for newly created chunks: update shadow index when doing a double-put, #7896 #5661

  If you have experienced issue #6687, you may want to run borg check --repair
  after upgrading to borg 1.2.7 to recreate the shadow index and get rid of the
  issue for existing chunks.
- check: fix return code for index entry value discrepancies
- LockRoster.modify: no KeyError if element was already gone, #7937
- create --X-from-command: run subcommands with a clean environment, #7916
- list --sort-by: support "archive" as alias of "name", #7873
- fix rc and msg if arg parsing throws an exception, #7885
- PATH: do not accept empty strings, #4221
- fix invalid pattern argument error msg
- zlib legacy decompress fixes, #7883

Other changes:

- replace archive/manifest TAMs by typed repo objects (ro_type), docs, #7670
- crypto: use a one-step kdf for session keys, #7953
- remove recreate --recompress option, use the more efficient repo-wide "rcompress".
- include unistd.h in _chunker.c (fix for Python 3.13)
- allow msgpack 1.0.7
- allow platformdirs 4, #7950
- use and require cython3
- move conftest.py to src/borg/testsuite, #6386
- use less setup.py, use pip and build
- linux: use pkgconfig to find libacl
- borg.logger: use same method params as python logging
- create and use Brewfile, document "brew bundle" install (macOS)
- blacken master branch
- prevent CLI argument issues in scripts/glibc_check.py
- pyproject.toml: exclude source files which have been compiled, #7828
- sdist: dynamically compute readme (long_description)
- init: better borg key export instructions
- scripts/make.py: move clean, build_man, build_usage to there,
  so we do not need to invoke setup.py directly, update docs
- vagrant:

  - use openssl 3.0 on macOS
  - add script for fetching borg binaries from VMs, #7989
  - use generic/openbsd7 box
  - netbsd: test on py311 only
  - remove debian 9 "stretch" box
  - use freebsd 14, #6871
  - use python 3.9.4 for tests, latest python 3.11.7 for binary builds
  - use pyinstaller 6.3.0
- docs:

  - add typical PR workflow to development docs, #7495
  - improve docs for borg with-lock, add example #8024
  - create disk/partition sector backup by disk serial number
  - Add "check.rebuild_refcounts" message
  - not only attack/unsafe, can also be a fs issue, #7853
  - use virtualenv on Cygwin
  - readthedocs: also build offline docs, #7835
  - do not refer to setup.py installation method
  - how to run the testsuite using the dist package
  - requirements are defined in pyproject.toml


Version 2.0.0b7 (2023-09-14)
----------------------------

New features:

- BORG_WORKAROUNDS=authenticated_no_key to extract from authenticated repos
  without having the borg key, #7700

Fixes:

- archive tam verify security fix, fixes CVE-2023-36811
- remote logging/progress: use callback to send queued records, #7662
- make_path_safe: remove test for backslashes, #7651
- benchmark cpu: use sanitized path, #7654
- create: do not try to read parent dir of recursion root, #7746

Other changes:

- always implicitly require archive TAMs (all archives have TAMs since borg 1.2.6)
- always implicitly require manifest TAMs (manifests have TAMs since borg 1.0.9)
- rlist: remove support for {tam} placeholder, archives are now always TAM-authenticated.
- support / test on Python 3.12
- allow msgpack 1.0.6 (which has py312 wheels), #7810
- manifest: move item_keys into config dict (manifest.version == 2 now), #7710
- replace "datetime.utcfromtimestamp" to avoid deprecation warnings with Python 3.12
- properly normalise paths on Windows (forward slashes, integrate drive letter into path)
- Docs:

  - move upgrade / compat. notes to own section, see #7546
  - fix borg delete examples, #7759
  - improve rcreate / related repos docs
  - automated-local.rst: use UUID for consistent udev rule
  - rewrite `borg check` docs, #7578
  - misc. other docs updates
- Tests / CI / Vagrant:

  - major testsuite refactoring: a lot more tests now use pytest, #7626
  - freebsd: add some ACL tests, #7745
  - fix test_disk_full, #7617
  - fix failing test_get_runtime_dir test on OpenBSD, #7719
  - CI: run on ubuntu 22.04
  - CI: test building the docs
  - simplify flake8 config, fix some complaints
  - use pyinstaller 5.13.1 to build the borg binaries


Version 2.0.0b6 (2023-06-11)
----------------------------

New features:

- diff: include changes in ctime and mtime, #7248
- diff: sort JSON output alphabetically
- diff --content-only: option added to ignore metadata changes
- diff: add --format option, #4634
- import-tar --ignore-zeros: new option to support importing concatenated tars, #7432
- debug id-hash / parse-obj / format-obj: new debug commands, #7406
- transfer --compression=C --recompress=M: recompress while transferring, #7529
- extract --continue: continue a previously interrupted extraction, #1356
- prune --list-kept/--list-pruned: only list the kept (or pruned) archives, #7511
- prune --short/--format: enable users to format the list output, #3238
- implement BORG_<CMD>_FORMAT env vars for prune, list, rlist, #5166
- rlist: size and nfiles format keys
- implement unix domain (ipc) socket support, #6183::

      borg serve --socket  # server side (not started automatically!)
      borg -r socket:///path/to/repo ...  # client side
- add get_runtime_dir / BORG_RUNTIME_DIR (contains e.g. .sock and .pid file)
- support shell-style alternatives, like: sh:image.{png,jpg}, #7602

Fixes:

- do not retry on permission errors (pointless)
- transfer: verify chunks we get using assert_id, #7383
- fix config/cache dir compatibility issues, #7445
- xattrs: fix namespace processing on FreeBSD, #6997
- ProgressIndicatorPercent: fix space computation for wide chars, #3027
- delete: remove --cache-only option, #7440.
  for deleting the cache only, use: borg rdelete --cache-only
- borg debug get-obj/put-obj: fixed chunk id
- create: ignore empty paths, print warning, #5637
- extract: support extraction of atime/mtime on win32
- benchmark crud: use TemporaryDirectory below given path, #4706
- Ensure that cli options specified with action=Highlander can only be set once, even
  if the set value is a default value. Add tests for action=Highlander, #7500, #6269.
- Fix argparse error messages from misc. validators (being more specific).
- put security infos into data dir, add BORG_DATA_DIR env var, #5760
- setup.cfg: remove setup_requires (we have a pyproject.toml for that), #7574
- do not crash for empty archives list in borg rlist date based matching, #7522
- sanitize paths during archive creation and extraction, #7108 #7099
- make sure we do not get backslashes into item paths

Other changes:

- allow msgpack 1.0.5 also
- development.lock.txt: upgrade cython to 0.29.35, misc. other upgrades
- clarify platformdirs requirements, #7393.
  3.0.0 is only required for macOS due to breaking changes.
  2.6.0 was the last breaking change for Linux/UNIX.
- mount: improve mountpoint error msgs, see #7496
- more Highlander options, #6269
- Windows: simplify building (just use pip)
- refactor toplevel exception handling, #6018
- remove nonce management, related repo methods (not needed for borg2)
- borg.remote: remove support for borg < 1.1.0
  ($LOG, logging setup, exceptions, rpc tuple data format, version)
- new remote and progress logging, #7604
- borg.logger: add logging debugging functionality
- add function to clear empty directories at end of compact process
- unify scanning and listing of segment dirs / segment files, #7597
- replace `LRUCache` internals with `OrderedDict`
- docs:

  - add installation instructions for Windows
  - improve --one-file-system help and docs (macOS APFS), #5618 #4876
  - BORG_KEY_FILE: clarify docs, #7444
  - installation: add link to OS dependencies, #7356
  - update FAQ about locale/unicode issues, #6999
  - improve mount options rendering, #7359
  - make timestamps in manual pages reproducible.
  - describe performing pull-backups via ssh remote forwarding
  - suggest to use forced command when using remote-forwarding via ssh
  - fix some -a / --match-archives docs issues
  - incl./excl. options header, clarify --path-from-stdin exclusive control
  - add note about MAX_DATA_SIZE
  - update security support docs
  - improve patterns help

- CI / tests / vagrant:

  - added pre-commit for linting purposes, #7476
  - resolved mode bug and added sleep clause for darwin systems, #7470
  - "auto" compressor tests: do not assume zlib is better than lz4, #7363
  - add stretch64 VM with deps built from source
  - misc. other CI / test fixes and updates
  - vagrant: add lunar64 VM, fix packages_netbsd
  - avoid long ids in pytest output
  - tox: package = editable-legacy, #7580
  - tox under fakeroot: fix finding setup_docs, #7391
  - check buzhash chunksize distribution, #7586
  - use debian/bookworm64 box


Version 2.0.0b5 (2023-02-27)
----------------------------

New features:

- create: implement retries for individual fs files
  (e.g. if a file changed while we read it, if a file had an OSError)
- info: add used storage quota, #7121
- transfer: support --progress
- create/recreate/import-tar: add --checkpoint-volume option
- support date-based matching for archive selection,
  add --newer/--older/--newest/--oldest options, #7062 #7296

Fixes:

- disallow --list with --progress, #7219
- create: fix --list --dry-run output for directories, #7209
- do no assume hardlink_master=True if not present, #7175
- fix item_ptrs orphaned chunks of checkpoint archives
- avoid orphan content chunks on BackupOSError, #6709
- transfer: fix bug in obfuscated data upgrade code
- fs.py: fix bug in f-string (thanks mypy!)
- recreate: when --target is given, do not detect "nothing to do", #7254
- locking (win32): deal with os.rmdir/listdir PermissionErrors
- locking: thread id must be parsed as hex from lock file name
- extract: fix mtime when ResourceFork xattr is set (macOS specific), #7234
- recreate: without --chunker-params borg shall not rechunk, #7336
- allow mixing --progress and --list in log-json mode
- add "files changed while reading" to Statistics class, #7354
- fixed keys determination in Statistics.__add__(), #7355

Other changes:

- use local time / local timezone to output timestamps, #7283
- update development.lock.txt, including a setuptools security fix, #7227
- remove --save-space option (does not change behaviour)
- remove part files from final archive
- remove --consider-part-files, related stats code, update docs
- transfer: drop part files
- check: show id of orphaned chunks
- ArchiveItem.cmdline list-of-str -> .command_line str, #7246
- Item: symlinks: rename .source to .target, #7245
- Item: make user/group/uid/gid optional
- create: do not store user/group for stdin data by default, #7249
- extract: chown only if we have u/g info in archived item, #7249
- export-tar: for items w/o uid/gid, default to 0/0, #7249
- fix some uid/gid lookup code / tests for win32
- cache.py: be less verbose during cache sync
- update bash completion script commands and options, #7273
- require and use platformdirs 3.x.x package, tests
- better included/excluded status chars, docs, #7321
- undef NDEBUG for chunker and hashindex (make assert() work)
- assert_id: better be paranoid (add back same crypto code as in old borg), #7362
- check --verify_data: always decompress and call assert_id(), #7362
- make hashindex_compact simpler and probably faster, minor fixes, cleanups, more tests
- hashindex minor fixes, refactor, tweaks, tests
- pyinstaller: remove icon
- validation / placeholders / JSON:

  - implement (text|binary)_to_json: key (text), key_b64 (base64(binary))
  - remove bpath, barchive, bcomment placeholders / JSON keys
  - archive metadata: make sure hostname and username have no surrogate escapes
  - text attributes (like archive name, comment): validate more strictly, #2290
  - transfer: validate archive names and comment before transfer
  - json output: use text_to_json (path, target), #6151
- docs:

  - docs and comments consistency, readability and spelling fixes
  - fix --progress display description, #7180
  - document how borg deals with non-unicode bytes in JSON output
  - document another way to get UTF-8 encoding on stdin/stdout/stderr, #2273
  - pruning interprets timestamps in the local timezone where borg prune runs
  - shellpattern: add license, use copyright/license markup
  - key change-passphrase: fix --encryption value in examples
  - remove BORG_LIBB2_PREFIX (not used any more)
  - Installation: Update Fedora in distribution list, #7357
  - add .readthedocs.yaml (use py311, use non-shallow clone)
- tests:

  - fix archiver tests on Windows, add running the tests to Windows CI
  - fix tox4 passenv issue, #7199
  - github actions updates (fix deprecation warnings)
  - add tests for borg transfer/upgrade
  - fix test hanging reading FIFO when `borg create` failed
  - mypy inspired fixes / updates
  - fix prune tests, prune in localtime
  - do not look up uid 0 / gid 0, but current process uid/gid
  - safe_unlink tests: use os.link to support win32 also
  - fix test_size_on_disk_accurate for large st_blksize, #7250
  - relaxed timestamp comparisons, use same_ts_ns
  - add test for extracted directory mtime
  - use "fail" chunker to test erroneous input file skipping


Version 2.0.0b4 (2022-11-27)
----------------------------

Fixes:

- transfer/upgrade: fix borg < 1.2 chunker_params, #7079
- transfer/upgrade: do not access Item._dict, #7077
- transfer/upgrade: fix crash in borg transfer, #7156
- archive.save(): always use metadata from stats, #7072
- benchmark: fixed TypeError in compression benchmarks, #7075
- fix repository.scan api minimum requirement
- fix args.paths related argparsing, #6994

Other changes:

- tar_filter: recognize .tar.zst as zstd, #7093
- adding performance statistics to borg create, #6991
- docs: add rcompress to usage index
- tests:

  - use github and MSYS2 for Windows CI, #7097
  - win32 and cygwin: test fixes / skip hanging test
  - vagrant / github CI: use python 3.11.0 / 3.10.8
- vagrant:

  - upgrade pyinstaller to 5.6.2 (supports python 3.11)
  - use python 3.11 to build the borg binary

Version 2.0.0b3 (2022-10-02)
----------------------------

Fixes:

- transfer: fix user/group == None crash with borg1 archives
- compressors: avoid memoryview related TypeError
- check: fix uninitialised variable if repo is completely empty, #7034
- do not use version_tuple placeholder in setuptools_scm template, #7024
- get_chunker: fix missing sparse=False argument, #7056

New features:

- rcompress: do a repo-wide (re)compression, #7037
- implement pattern support for --match-archives, #6504
- BORG_LOCK_WAIT=n env var to set default for --lock-wait option, #5279

Other:

- repository.scan: misc. fixes / improvements
- metadata: differentiate between empty/zero and unknown, #6908
- CI: test pyfuse3 with python 3.11
- use more relative imports
- make borg.testsuite.archiver a package, split archiver tests into many modules
- support reading new, improved hashindex header format, #6960.
  added version number and num_empty to the HashHeader, fixed alignment.
- vagrant: upgrade pyinstaller 4.10 -> 5.4.1, use python 3.9.14 for binary build
- item.pyx: use more Cython (faster, uses less memory), #5763


Version 2.0.0b2 (2022-09-10)
----------------------------

Bug fixes:

- xattrs / extended stat: improve exception handling, #6988
- fix and refactor replace_placeholders, #6966

New features:

- support archive timestamps with utc offsets, adapt them when using
  borg transfer to transfer from borg 1.x repos (append +00:00 for UTC).
- create/recreate/import-tar --timestamp: accept giving timezone via
  its utc offset. defaults to local timezone, if no utc offset is given.

Other changes:

- chunks: have separate encrypted metadata (ctype, clevel, csize, size)

  chunk = enc_meta_len16 + encrypted(msgpacked(meta)) + encrypted(compressed(data)).

  this breaks repo format compatibility, you need to create fresh repos!
- repository api: flags support, #6982
- OpenBSD only - statically link OpenSSL, #6474.
  Avoid conflicting with shared libcrypto from the base OS pulled in via dependencies.
- restructured source code
- update diagrams to odg format, #6928

Version 2.0.0b1 (2022-08-08)
----------------------------

New features:

- massively increase archive metadata stream size limit, #1473.
  currently rather testing the code, scalability will improve later, see #6945.
- rcreate --copy-crypt-key: copy crypt_key from key of other repo, #6710.
  default: create new, random authenticated encryption key.
- prune/delete --checkpoint-interval=1800 and ctrl-c/SIGINT support, #6284

Fixes:

- ctrl-c must not kill important subprocesses, #6912
- transfer: check whether ID hash method and chunker secret are same.
  add PlaintextKey and AuthenticatedKey support to uses_same_id_hash function.
- check: try harder to create the key, #5719
- SaveFile: use a custom mkstemp with mode support, #6933, #6400
- make setuptools happy, #6874
- fix misc. compiler warnings
- list: fix {flags:<WIDTH>} formatting, #6081

Other changes:

- new crypto does not need to call ._assert_id(), update code and docs.
  https://github.com/borgbackup/borg/pull/6463#discussion_r925436156
- check: --verify-data does not need to decompress with new crypto modes
- Key: crypt_key instead of enc_key + enc_hmac_key, #6611
- misc. docs updates and improvements
- CI: test on macOS 12 without fuse / fuse tests
- repository: add debug logging for issue #6687
- _version.py: remove trailing blank, add LF at EOF (make pep8 checker happy)


Version 2.0.0a4 (2022-07-17)
----------------------------

New features:

- recreate: consider level for recompression, #6698, #3622

Other changes:

- stop using libdeflate
- CI: add mypy (if we add type hints, it can do type checking)
- big changes to the source code:

  - split up archiver module, transform it into a package
  - use Black for automated code formatting
  - remove some legacy code
  - adapt/fix code for mypy
- use language_level = 3str for cython (this will be the default in cython 3)
- docs: document HardLinkManager and hlid, #2388


Version 2.0.0a3 (2022-07-04)
----------------------------

Fixes:

- check repo version, accept old repos only for --other-repo (e.g. rcreate/transfer).
  v2 is the default repo version for borg 2.0. v1 repos must only be used in a
  read-only way, e.g. for --other-repo=V1_REPO with borg init and borg transfer!

New features:

- transfer: --upgrader=NoOp is the default.
  This is to support general-purpose transfer of archives between related borg2
  repos.
- transfer: --upgrader=From12To20 must be used to transfer (and convert) archives
  from borg 1.2 repos to borg 2.0 repos.

Other changes:

- removed some deprecated options
- removed -P (aka --prefix) option, #6806. The option -a (aka --glob-archives)
  can be used for same purpose and is more powerful, e.g.: -a 'PREFIX*'
- rcreate: always use argon2 kdf for new repos, #6820
- rcreate: remove legacy encryption modes for new repos, #6490


Version 2.0.0a2 (2022-06-26)
----------------------------

Changes:

- split repo and archive name into separate args, #948

  - use -r or --repo or BORG_REPO env var to give the repository
  - use --other-repo or BORG_OTHER_REPO to give another repo (e.g. borg transfer)
  - use positional argument for archive name or `-a ARCH_GLOB`
- remove support for scp-style repo specification, use ssh://...
- simplify stats output: repo ops -> repo stats, archive ops -> archive stats
- repository index: add payload size (==csize) and flags to NSIndex entries
- repository index: set/query flags, iteration over flagged items (NSIndex)
- repository: sync write file in get_fd
- stats: deduplicated size now, was deduplicated compressed size in borg 1.x
- remove csize support at most places in the code (chunks index, stats, get_size,
  Item.chunks)
- replace problematic/ugly hardlink_master approach of borg 1.x by:

  - symmetric hlid (all hardlinks pointing to same inode have same hlid)
  - all archived hardlinked regular files have a chunks list
- borg rcreate --other-repo=OTHER_REPO: reuse key material from OTHER_REPO, #6554.
  This is useful if you want to use borg transfer to transfer archives from an
  existing borg 1.1/1.2 repo. If the chunker secret and the id key and algorithm
  stay the same, the deduplication will also work between past and future backups.
- borg transfer:

  - efficiently copy archives from a borg 1.1/1.2 repo to a new repo.
    uses deduplication and does not decompress/recompress file content data.
  - does some cleanups / fixes / conversions:

    - disallow None value for .user/group/chunks/chunks_healthy
    - cleanup msgpack related str/bytes mess, use new msgpack spec, #968
    - obfuscation: fix byte order for size, #6701
    - compression: use the 2 bytes for type and level, #6698
    - use version 2 for new archives
    - convert timestamps int/bigint -> msgpack.Timestamp, see #2323
    - all hardlinks have chunks, maybe chunks_healthy, hlid
    - remove the zlib type bytes hack
    - make sure items with chunks have precomputed size
    - removes the csize element from the tuples in the Item.chunks list
    - clean item of attic 0.13 'acl' bug remnants
- crypto: see 1.3.0a1 log entry
- removed "borg upgrade" command (not needed any more)
- compact: removed --cleanup-commits option
- docs: fixed quickstart and usage docs with new cli command syntax
- docs: removed the parts talking about potential AES-CTR mode issues
  (we will not use that any more).


Version 1.3.0a1 (2022-04-15)
----------------------------

Although this was released as 1.3.0a1, it can be also seen as 2.0.0a1 as it was
later decided to do breaking changes and thus the major release number had to
be increased (thus, there will not be a 1.3.0 release, but 2.0.0).

New features:

- init: new --encryption=(repokey|keyfile)-[blake2-](aes-ocb|chacha20-poly1305)

  - New, better, faster crypto (see encryption-aead diagram in the docs), #6463.
  - New AEAD cipher suites: AES-OCB and CHACHA20-POLY1305.
  - Session keys are derived via HKDF from random session id and master key.
  - Nonces/MessageIVs are counters starting from 0 for each session.
  - AAD: chunk id, key type, messageIV, sessionID are now authenticated also.
  - Solves the potential AES-CTR mode counter management issues of the legacy crypto.
- init: --key-algorithm=argon2 (new default KDF, older pbkdf2 also still available)

  borg key change-passphrase / change-location keeps the key algorithm unchanged.
- key change-algorithm: to upgrade existing keys to argon2 or downgrade to pbkdf2.

  We recommend you to upgrade unless you have to keep the key compatible with older versions of borg.
- key change-location: usable for repokey <-> keyfile location change
- benchmark cpu: display benchmarks of cpu bound stuff
- export-tar: new --tar-format=PAX (default: GNU)
- import-tar/export-tar: can use PAX format for ctime and atime support
- import-tar/export-tar: --tar-format=BORG: roundtrip ALL item metadata, #5830
- repository: create and use version 2 repos only for now
- repository: implement PUT2: header crc32, overall xxh64, #1704

Other changes:

- require python >= 3.9, #6315
- simplify libs setup, #6482
- unbundle most bundled 3rd party code, use libs, #6316
- use libdeflate.crc32 (Linux and all others) or zlib.crc32 (macOS)
- repository: code cleanups / simplifications
- internal crypto api: speedups / cleanups / refactorings / modernisation
- remove "borg upgrade" support for "attic backup" repos
- remove PassphraseKey code and borg key migrate-to-repokey command
- OpenBSD: build borg with OpenSSL (not: LibreSSL), #6474
- remove support for LibreSSL, #6474
- remove support for OpenSSL < 1.1.1
