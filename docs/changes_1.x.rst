.. _important_notes_1x:

Important notes 1.x
===================

This section provides information about security and corruption issues.

.. _hashindex_set_bug:

Pre-1.1.11 potential index corruption / data loss issue
-------------------------------------------------------

A bug was discovered in our hashtable code, see issue #4829.
The code is used for the client-side chunks cache and the server-side repo index.

Although borg uses the hashtables very heavily, the index corruption did not
happen too frequently, because it needed specific conditions to happen.

Data loss required even more specific conditions, so it should be rare (and
also detectable via borg check).

You might be affected if borg crashed with / complained about:

- AssertionError: Corrupted segment reference count - corrupted index or hints
- ObjectNotFound: Object with key ... not found in repository ...
- Index mismatch for key b'...'. (..., ...) != (-1, -1)
- ValueError: stats_against: key contained in self but not in master_index.

Advised procedure to fix any related issue in your indexes/caches:

- install fixed borg code (on client AND server)
- for all of your clients and repos remove the cache by:

  borg delete --cache-only YOURREPO

  (later, the cache will be re-built automatically)
- for all your repos, rebuild the repo index by:

  borg check --repair YOURREPO

  This will also check all archives and detect if there is any data-loss issue.

Affected branches / releases:

- fd06497 introduced the bug into 1.1-maint branch - it affects all borg 1.1.x since 1.1.0b4.
- fd06497 introduced the bug into master branch - it affects all borg 1.2.0 alpha releases.
- c5cd882 introduced the bug into 1.0-maint branch - it affects all borg 1.0.x since 1.0.11rc1.

The bug was fixed by:

- 701159a fixes the bug in 1.1-maint branch - will be released with borg 1.1.11.
- fa63150 fixes the bug in master branch - will be released with borg 1.2.0a8.
- 7bb90b6 fixes the bug in 1.0-maint branch. Branch is EOL, no new release is planned as of now.

.. _broken_validator:

Pre-1.1.4 potential data corruption issue
-----------------------------------------

A data corruption bug was discovered in borg check --repair, see issue #3444.

This is a 1.1.x regression, releases < 1.1 (e.g. 1.0.x) are not affected.

To avoid data loss, you must not run borg check --repair using an unfixed version
of borg 1.1.x. The first official release that has the fix is 1.1.4.

Package maintainers may have applied the fix to updated packages of 1.1.x (x<4)
though, see the package maintainer's package changelog to make sure.

If you never had missing item metadata chunks, the bug has not affected you
even if you did run borg check --repair with an unfixed version.

When borg check --repair tried to repair corrupt archives that miss item metadata
chunks, the resync to valid metadata in still present item metadata chunks
malfunctioned. This was due to a broken validator that considered all (even valid)
item metadata as invalid. As they were considered invalid, borg discarded them.
Practically, that means the affected files, directories or other fs objects were
discarded from the archive.

Due to the malfunction, the process was extremely slow, but if you let it
complete, borg would have created a "repaired" archive that has lost a lot of items.
If you interrupted borg check --repair because it was so strangely slow (killing
borg somehow, e.g. Ctrl-C) the transaction was rolled back and no corruption occurred.

The log message indicating the precondition for the bug triggering looks like:

    item metadata chunk missing [chunk: 001056_bdee87d...a3e50d]

If you never had that in your borg check --repair runs, you're not affected.

But if you're unsure or you actually have seen that, better check your archives.
By just using "borg list repo::archive" you can see if all expected filesystem
items are listed.

.. _tam_vuln:

Pre-1.0.9 manifest spoofing vulnerability (CVE-2016-10099)
----------------------------------------------------------

A flaw in the cryptographic authentication scheme in Borg allowed an attacker
to spoof the manifest. The attack requires an attacker to be able to

1. insert files (with no additional headers) into backups
2. gain write access to the repository

This vulnerability does not disclose plaintext to the attacker, nor does it
affect the authenticity of existing archives.

The vulnerability allows an attacker to create a spoofed manifest (the list of archives).
Creating plausible fake archives may be feasible for small archives, but is unlikely
for large archives.

The fix adds a separate authentication tag to the manifest. For compatibility
with prior versions this authentication tag is *not* required by default
for existing repositories. Repositories created with 1.0.9 and later require it.

Steps you should take:

1. Upgrade all clients to 1.0.9 or later.
2. Run ``borg upgrade --tam <repository>`` *on every client* for *each* repository.
3. This will list all archives, including archive IDs, for easy comparison with your logs.
4. Done.

Prior versions can access and modify repositories with this measure enabled, however,
to 1.0.9 or later their modifications are indiscernible from an attack and will
raise an error until the below procedure is followed. We are aware that this can
be annoying in some circumstances, but don't see a way to fix the vulnerability
otherwise.

In case a version prior to 1.0.9 is used to modify a repository where above procedure
was completed, and now you get an error message from other clients:

1. ``borg upgrade --tam --force <repository>`` once with *any* client suffices.

This attack is mitigated by:

- Noting/logging ``borg list``, ``borg info``, or ``borg create --stats``, which
  contain the archive IDs.

We are not aware of others having discovered, disclosed or exploited this vulnerability.

Vulnerability time line:

* 2016-11-14: Vulnerability and fix discovered during review of cryptography by Marian Beermann (@enkore)
* 2016-11-20: First patch
* 2016-12-20: Released fixed version 1.0.9
* 2017-01-02: CVE was assigned
* 2017-01-15: Released fixed version 1.1.0b3 (fix was previously only available from source)

.. _attic013_check_corruption:

Pre-1.0.9 potential data loss
-----------------------------

If you have archives in your repository that were made with attic <= 0.13
(and later migrated to borg), running borg check would report errors in these
archives. See issue #1837.

The reason for this is a invalid (and useless) metadata key that was
always added due to a bug in these old attic versions.

If you run borg check --repair, things escalate quickly: all archive items
with invalid metadata will be killed. Due to that attic bug, that means all
items in all archives made with these old attic versions.


Pre-1.0.4 potential repo corruption
-----------------------------------

Some external errors (like network or disk I/O errors) could lead to
corruption of the backup repository due to issue #1138.

A sign that this happened is if "E" status was reported for a file that can
not be explained by problems with the source file. If you still have logs from
"borg create -v --list", you can check for "E" status.

Here is what could cause corruption and what you can do now:

1) I/O errors (e.g. repo disk errors) while writing data to repo.

This could lead to corrupted segment files.

Fix::

    # check for corrupt chunks / segments:
    borg check -v --repository-only REPO

    # repair the repo:
    borg check -v --repository-only --repair REPO

    # make sure everything is fixed:
    borg check -v --repository-only REPO

2) Unreliable network / unreliable connection to the repo.

This could lead to archive metadata corruption.

Fix::

    # check for corrupt archives:
    borg check -v --archives-only REPO

    # delete the corrupt archives:
    borg delete --force REPO::CORRUPT_ARCHIVE

    # make sure everything is fixed:
    borg check -v --archives-only REPO

3) In case you want to do more intensive checking.

The best check that everything is ok is to run a dry-run extraction::

    borg extract -v --dry-run REPO::ARCHIVE

.. _changelog_1x:

Change Log 1.x
==============

Version 1.3.0a1 (2022-04-15)
----------------------------

Please note:

This is an alpha release, only for testing - do not use this with production repos.

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


Version 1.2.0 (2022-02-22 22:02:22 :-)
--------------------------------------

Please note:

This is the first borg 1.2 release, so be careful and read the notes below.

Upgrade notes:

Strictly taken, nothing special is required for upgrading to 1.2, but some
things can be recommended:

- do you already want to upgrade? 1.1.x also will get fixes for a while.
- be careful, first upgrade your less critical / smaller repos.
- first upgrade to a recent 1.1.x release - especially if you run some older
  1.1.* or even 1.0.* borg release.
- using that, run at least one `borg create` (your normal backup), `prune`
  and especially a `check` to see everything is in a good state.
- check the output of `borg check` - if there is anything special, consider
  a `borg check --repair` followed by another `borg check`.
- if everything is fine so far (borg check reports no issues), you can consider
  upgrading to 1.2.0. if not, please first fix any already existing issue.
- if you want to play safer, first **create a backup of your borg repository**.
- upgrade to latest borg 1.2.x release (you could use the fat binary from
  github releases page)
- run `borg compact --cleanup-commits` to clean up a ton of 17 bytes long files
  in your repo caused by a borg 1.1 bug
- run `borg check` again (now with borg 1.2.x) and check if there is anything
  special.
- run `borg info` (with borg 1.2.x) to build the local pre12-meta cache (can
  take significant time, but after that it will be fast) - for more details
  see below.
- check the compatibility notes (see below) and adapt your scripts, if needed.
- if you run into any issues, please check the github issue tracker before
  posting new issues there or elsewhere.

If you follow this procedure, you can help avoiding that we get a lot of
"borg 1.2" issue reports that are not really 1.2 issues, but existed before
and maybe just were not noticed.

Compatibility notes:

- matching of path patterns has been aligned with borg storing relative paths.
  Borg archives file paths without leading slashes. Previously, include/exclude
  patterns could contain leading slashes. You should check your patterns and
  remove leading slashes.
- dropped support / testing for older Pythons, minimum requirement is 3.8.
  In case your OS does not provide Python >= 3.8, consider using our binary,
  which does not need an external Python interpreter. Or continue using
  borg 1.1.x, which is still supported.
- freeing repository space only happens when "borg compact" is invoked.
- mount: the default for --numeric-ids is False now (same as borg extract)
- borg create --noatime is deprecated. Not storing atime is the default behaviour
  now (use --atime if you want to store the atime).
- list: corrected mix-up of "isomtime" and "mtime" formats.
  Previously, "isomtime" was the default but produced a verbose human format,
  while "mtime" produced a ISO-8601-like format.
  The behaviours have been swapped (so "mtime" is human, "isomtime" is ISO-like),
  and the default is now "mtime".
  "isomtime" is now a real ISO-8601 format ("T" between date and time, not a space).
- create/recreate --list: file status for all files used to get announced *AFTER*
  the file (with borg < 1.2). Now, file status is announced *BEFORE* the file
  contents are processed. If the file status changes later (e.g. due to an error
  or a content change), the updated/final file status will be printed again.
- removed deprecated-since-long stuff (deprecated since):

  - command "borg change-passphrase" (2017-02), use "borg key ..."
  - option "--keep-tag-files" (2017-01), use "--keep-exclude-tags"
  - option "--list-format" (2017-10), use "--format"
  - option "--ignore-inode" (2017-09), use "--files-cache" w/o "inode"
  - option "--no-files-cache" (2017-09), use "--files-cache=disabled"
- removed BORG_HOSTNAME_IS_UNIQUE env var.
  to use borg you must implement one of these 2 scenarios:

  - 1) the combination of FQDN and result of uuid.getnode() must be unique
       and stable (this should be the case for almost everybody, except when
       having duplicate FQDN *and* MAC address or all-zero MAC address)
  - 2) if you are aware that 1) is not the case for you, you must set
       BORG_HOST_ID env var to something unique.
- exit with 128 + signal number, #5161.
  if you have scripts expecting rc == 2 for a signal exit, you need to update
  them to check for >= 128.

Fixes:

- diff: reduce memory consumption, fix is_hardlink_master, #6295
- compact: fix / improve freeable / freed space log output

  - derive really freed space from quota use before/after, #5679
  - do not say "freeable", but "maybe freeable" (based on hint, unsure)
- fix race conditions in internal SaveFile function, #6306 #6028
- implement internal safe_unlink (was: truncate_and_unlink) function more safely:
  usually it does not truncate any more, only under "disk full" circumstances
  and only if there is only one hardlink.
  see: https://github.com/borgbackup/borg/discussions/6286

Other changes:

- info: use a pre12-meta cache to accelerate stats for borg < 1.2 archives.
  the first time borg info is invoked on a borg 1.1 repo, it can take a
  rather long time computing and caching some stats values for 1.1 archives,
  which borg 1.2 archives have in their archive metadata structure.
  be patient, esp. if you have lots of old archives.
  following invocations are much faster due to the cache.
  related change: add archive name to calc_stats progress display.
- docs:

  - add borg 1.2 upgrade notes, #6217
  - link to borg placeholders and borg patterns help
  - init: explain the encryption modes better
  - clarify usage of patternfile roots
  - put import-tar docs into same file as export-tar docs
  - explain the difference between a path that ends with or without a slash,
    #6297


Version 1.2.0rc1 (2022-02-05)
-----------------------------

Fixes:

- repo::archive location placeholder expansion fixes, #5826, #5998
- repository: fix intermediate commits, shall be at end of current segment
- delete: don't commit if nothing was deleted, avoid cache sync, #6060
- argument parsing: accept some options only once, #6026
- disallow overwriting of existing keyfiles on init, #6036
- if ensure_dir() fails, give more informative error message, #5952

New features:

- delete --force: do not ask when deleting a repo, #5941

Other changes:

- requirements: exclude broken or incompatible-with-pyinstaller setuptools
- add a requirements.d/development.lock.txt and use it for vagrant
- tests:

  - added nonce-related tests
  - refactor: remove assert_true
  - vagrant: macos box tuning, netbsd box fixes, #5370, #5922
- docs:

  - update install docs / requirements docs, #6180
  - borg mount / FUSE "versions" view is not experimental any more
  - --pattern* is not experimental any more, #6134
  - impact of deleting path/to/repo/nonce, #5858
  - key export: add examples, #6204
  - ~/.config/borg/keys is not used for repokey keys, #6107
  - excluded parent dir's metadata can't restore


Version 1.2.0b4 (2022-01-23)
----------------------------

Fixes:

- create: fix passing device nodes and symlinks to --paths-from-stdin, #6009
- create --dry-run: fix display of kept tagfile, #5834
- check --repair: fix missing parameter in "did not consistently fail" msg, #5822
- fix hardlinkable file type check, #6037
- list: remove placeholders for shake_* hashes, #6082
- prune: handle case of calling prune_split when there are no archives, #6015
- benchmark crud: make sure cleanup of borg-test-data files/dir happens, #5630
- do not show archive name in repository-related error msgs, #6014
- prettier error msg (no stacktrace) if exclude file is missing, #5734
- do not require BORG_CONFIG_DIR if BORG_{SECURITY,KEYS}_DIR are set, #5979
- fix pyinstaller detection for dir-mode, #5897
- atomically create the CACHE_TAG file, #6028
- deal with the SaveFile/SyncFile race, docs, see #6056 708a5853
- avoid expanding path into LHS of formatting operation + tests, #6064 #6063
- repository: quota / compactable computation fixes
- info: emit repo info even if repo has 0 archives + test, #6120

New features:

- check --repair: significantly speed up search for next valid object in segment, #6022
- check: add progress indicator for archive check, #5809
- create: add retry_erofs workaround for O_NOATIME issue on volume shadow copies in WSL1, #6024
- create: allow --files-cache=size (this is potentially dangerous, use on your own risk), #5686
- import-tar: implement import-tar to complement export-tar, #2233
- implement BORG_SELFTEST env variable (can be carefully used to speedup borg hosting), #5871
- key export: print key if path is '-' or not given, #6092
- list --format: Add command_line to format keys

Other changes:

- pypi metadata: alpha -> beta
- require python 3.8+, #5975
- use pyinstaller 4.7
- allow msgpack 1.0.3
- upgrade to bundled xxhash to 0.8.1
- import-tar / export-tar: tar file related changes:

  - check for short tarfile extensions
  - add .lz4 and .zstd
  - fix docs about extensions and decompression commands
- add github codeql analysis, #6148
- vagrant:

  - box updates / add new boxes / remove outdated and broken boxes
  - use Python 3.9.10 (incl. binary builds) and 3.10.0
  - fix pyenv initialisation, #5798
  - fix vagrant scp on macOS, #5921
  - use macfuse instead of osxfuse
- shell completions:

  - update shell completions to 1.1.17, #5923
  - remove BORG_LIBC completion, since 9914968 borg no longer uses find_library().
- docs:

  - fixed readme.rst irc webchat link (we use libera chat now, not freenode)
  - fix exceptions thrown by `setup.py build_man`
  - check --repair: recommend checking hw before check --repair, #5855
  - check --verify-data: clarify and document conflict with --repository-only, #5808
  - serve: improve ssh forced commands docs, #6083
  - list: improve docs for `borg list` --format, #6061
  - list: remove --list-format from borg list
  - FAQ: fix manifest-timestamp path (inside security dir)
  - fix the broken link to .nix file
  - document behavior for filesystems with inconsistent inodes, #5770
  - clarify user_id vs uid for fuse, #5723
  - clarify pattern usage with commands, #5176
  - clarify pp vs. pf pattern type, #5300
  - update referenced freebsd/macOS versions used for binary build, #5942
  - pull mode: add some warnings, #5827
  - clarify "you will need key and passphrase" borg init warning, #4622
  - add missing leading slashes in help patterns, #5857
  - add info on renaming repositories, #5240
  - check: add notice about defective hardware, #5753
  - mention tar --compare (compare archive to fs files), #5880
  - add note about grandfather-father-son backup retention policy / rotation scheme, #6006
  - permissions note rewritten to make it less confusing
  - create github security policy
  - remove leftovers of BORG_HOSTNAME_IS_UNIQUE
  - excluded parent dir's metadata can't restore. (#6062)
  - if parent dir is not extracted, we do not have its metadata
  - clarify who starts the remote agent


Version 1.2.0b3 (2021-05-12)
----------------------------

Fixes:

- create: fix --progress --log-json, #4360#issuecomment-774580052
- do not load files cache for commands not using it, #5673
- fix repeated cache tag file writing bug

New features:

- create/recreate: print preliminary file status early, #5417
- create/extract: add --noxattrs and --noacls options, #3955
- create: verbose files cache logging via --debug-topic=files_cache, #5659
- mount: implement --numeric-ids (default: False!), #2377
- diff: add --json-lines option
- info / create --stats: add --iec option to print sizes in powers of 1024.

Other changes:

- create: add --upload-(ratelimit|buffer), deprecate --remote-* options, #5611
- create/extract/mount: add --numeric-ids, deprecate --numeric-owner option, #5724
- config: accept non-int value for max_segment_size / storage_quota
- use PyInstaller v4.3, #5671
- vagrant: use Python 3.9.5 to build binaries
- tox.ini: modernize and enable execution without preinstalling deps
- cleanup code style checks
- get rid of distutils, use setuptools+packaging
- github CI: test on Python 3.10-dev
- check: missing / healed chunks: always tell chunk ID, #5704
- docs:

  - remove bad /var/cache exclusion in example commands, #5625
  - misc. fixes and improvements, esp. for macOS
  - add unsafe workaround to use an old repo copy, #5722


Version 1.2.0b2 (2021-02-06)
----------------------------

Fixes:

- create: do not recurse into duplicate roots, #5603
- create: only print stats if not ctrl-c'ed, fixes traceback, #5668
- extract:
  improve exception handling when setting xattrs, #5092.
  emit a warning message giving the path, xattr key and error message.
  continue trying to restore other xattrs and bsdflags of the same file
  after an exception with xattr-setting happened.
- export-tar:
  fix memory leak with ssh: remote repository, #5568.
  fix potential memory leak with ssh: remote repository with partial extraction.
- remove empty shadowed_segments lists, #5275
- fix bad default: manifest.archives.list(consider_checkpoints=False),
  fixes tracebacks / KeyErros for missing objects in ChunkIndex, #5668

New features:

- create: improve sparse file support

  - create --sparse (detect sparse file holes) and file map support,
    only for the "fixed" chunker, #14
  - detect all-zero chunks in read data in "buzhash" and "fixed" chunkers
  - cached_hash: use a small LRU cache to accelerate all-zero chunks hashing
  - use cached_hash also to generate all-zero replacement chunks
- create --remote-buffer, add a upload buffer for remote repos, #5574
- prune: keep oldest archive when retention target not met

Other changes:

- use blake2 from python 3.6+ hashlib
  (this removes the requirement for libb2 and the bundled blake2 code)
- also accept msgpack up to 1.0.2.
  exclude 1.0.1 though, which had some issues (not sure they affect borg).
- create: add repository location to --stats output, #5491
- check: debug log the segment filename
- delete: add a --list switch to borg delete, #5116
- borg debug dump-hints - implemented to e.g. to look at shadow_index
- Tab completion support for additional archives for 'borg delete'
- refactor: have one borg.constants.zero all-zero bytes object
- refactor shadow_index updating repo.put/delete, #5661, #5636.
- docs:

  - add another case of attempted hardlink usage
  - fix description of borg upgrade hardlink usage, #5518
  - use HTTPS everywhere
  - add examples for --paths-from-stdin, --paths-from-command, --paths-separator, #5644
  - fix typos/grammar
  - update docs for dev environment installation instructions
  - recommend running tests only on installed versions for setup
  - add badge with current status of package
- vagrant:

  - use brew install --cask ..., #5557
  - use Python 3.9.1 and PyInstaller 4.1 to build the borg binary


Version 1.2.0b1 (2020-12-06)
----------------------------

Fixes:

- BORG_CACHE_DIR crashing borg if empty, atomic handling of
  recursive directory creation, #5216
- fix --dry-run and --stats coexistence, #5415
- allow EIO with warning when trying to hardlink, #4336
- export-tar: set tar format to GNU_FORMAT explicitly, #5274
- use --timestamp for {utcnow} and {now} if given, #5189
- make timestamp helper timezone-aware

New features:

- create: implement --paths-from-stdin and --paths-from-command, see #5492.
  These switches read paths to archive from stdin. Delimiter can specified
  by --paths-delimiter=DELIM. Paths read will be added honoring every
  option but exclusion options and --one-file-system. borg won't recurse
  into directories.
- 'obfuscate' pseudo compressor obfuscates compressed chunk size in repo
- add pyfuse3 (successor of llfuse) as an alternative lowlevel fuse
  implementation to llfuse (deprecated), #5407.
  FUSE implementation can be switched via env var BORG_FUSE_IMPL.
- allow appending to the files cache filename with BORG_FILES_CACHE_SUFFIX
- create: implement --stdin-mode, --stdin-user and --stdin-group, #5333

Other changes:

- split recursive directory walking/processing into directory walking and
  item processing.
- fix warning by importing setuptools before distutils.
- debug info: include infos about FUSE implementation, #5546
- testing:

  - add a test for the hashindex corruption bug, #5531 #4829
  - move away from travis-ci, use github actions, #5528 #5467
  - test both on fuse2 and fuse3
  - upload coverage reports to codecov
  - fix spurious failure in test_cache_files, #5438
  - add tests for Location.with_timestamp
  - tox: add a non-fuse env to the envlist
- vagrant:

  - use python 3.7.latest and pyinstaller 4.0 for binary creation
  - pyinstaller: compute basepath from spec file location
  - vagrant: updates/fixes for archlinux box, #5543
- docs:

  - "filename with spaces" example added to exclude file, #5236
  - add a hint about sleeping computer, #5301
  - how to adjust macOS >= Catalina security settings, #5303
  - process/policy for adding new compression algorithms
  - updated docs about hacked backup client, #5480
  - improve ansible deployment docs, make it more generic
  - how to approach borg speed issues, give speed example, #5371
  - fix mathematical inaccuracy about chunk size, #5336
  - add example for excluding content using --pattern cli option
  - clarify borg create's '--one-file-system' option, #4009
  - improve docs/FAQ about append-only remote repos, #5497
  - fix reST markup issues, labels
  - add infos about contributor retirement status


Version 1.2.0a9 (2020-10-05)
----------------------------

Fixes:

- fix memory leak related to preloading, #5202
- check --repair: fix potential data loss, #5325
- persist shadow_index in between borg runs, #4830
- fix hardlinked CACHEDIR.TAG processing, #4911
- --read-special: .part files also should be regular files, #5217
- allow server side enforcing of umask, --umask is for the local borg
  process only (see docs), #4947
- exit with 128 + signal number, #5161
- borg config --list does not show last_segment_checked, #5159
- locking:

  - fix ExclusiveLock race condition bug, #4923
  - fix race condition in lock migration, #4953
  - fix locking on openindiana, #5271

New features:

- --content-from-command: create archive using stdout of given command, #5174
- allow key-import + BORG_KEY_FILE to create key files
- build directory-based binary for macOS to avoid Gatekeeper delays

Other changes:

- upgrade bundled zstd to 1.4.5
- upgrade bundled xxhash to 0.8.0, #5362
- if self test fails, also point to OS and hardware, #5334
- misc. shell completions fixes/updates, rewrite zsh completion
- prettier error message when archive gets too big, #5307
- stop relying on `false` exiting with status code 1
- rephrase some warnings, #5164
- parseformat: unnecessary calls removed, #5169
- testing:

  - enable Python3.9 env for test suite and VMs, #5373
  - drop python 3.5, #5344
  - misc. vagrant fixes/updates
  - misc. testing fixes, #5196
- docs:

  - add ssh-agent pull backup method to doc, #5288
  - mention double --force in prune docs
  - update Homebrew install instructions, #5185
  - better description of how cache and rebuilds of it work
    and how the workaround applies to that
  - point to borg create --list item flags in recreate usage, #5165
  - add a note to create from stdin regarding files cache, #5180
  - add security faq explaining AES-CTR crypto issues, #5254
  - clarify --exclude-if-present in recreate, #5193
  - add socat pull mode, #5150, #900
  - move content of resources doc page to community project, #2088
  - explain hash collision, #4884
  - clarify --recompress option, #5154


Version 1.2.0a8 (2020-04-22)
----------------------------

Fixes:

- fixed potential index corruption / data loss issue due to bug in hashindex_set, #4829.
  Please read and follow the more detailed notes close to the top of this document.
- fix crash when upgrading erroneous hints file, #4922
- commit-time free space calc: ignore bad compact map entries, #4796
- info: if the archive doesn't exist, print a pretty message, #4793
- --prefix / -P: fix processing, avoid argparse issue, #4769
- ignore EACCES (errno 13) when hardlinking, #4730
- add a try catch when formatting the info string, #4818
- check: do not stumble over invalid item key, #4845
- update prevalence of env vars to set config and cache paths
- mount: fix FUSE low linear read speed on large files, #5032
- extract: fix confusing output of borg extract --list --strip-components, #4934
- recreate: support --timestamp option, #4745
- fix ProgressIndicator msgids (JSON output), #4935
- fuse: set f_namemax in statfs result, #2684
- accept absolute paths on windows
- pyinstaller: work around issue with setuptools > 44

New features:

- chunker speedup (plus regression test)
- added --consider-checkpoints and related test, #4788
- added --noflags option, deprecate --nobsdflags option, #4489
- compact: add --threshold option, #4674
- mount: add birthtime to FUSE entries
- support platforms with no os.link, #4901 - if we don't have os.link,
  we just extract another copy instead of making a hardlink.
- move sync_file_range to its own extension for better platform compatibility.
- new --bypass-lock option to bypass locking, e.g. for read-only repos
- accept absolute paths by removing leading slashes in patterns of all
  sorts but re: style, #4029
- delete: new --keep-security-info option

Other changes:

- support msgpack 0.6.2 and 1.0.0, #5065
- upgrade bundled zstd to 1.4.4
- upgrade bundled lz4 to 1.9.2
- upgrade xxhash to 0.7.3
- require recent enough llfuse for birthtime support, #5064
- only store compressed data if the result actually is smaller, #4516
- check: improve error output for matching index size, see #4829
- ignore --stats when given with --dry-run, but continue, #4373
- replaced usage of os.statvfs with shutil.disk_usage (better cross-platform support).
- fuse: remove unneeded version check and compat code, micro opts
- docs:

  - improve description of path variables
  - document how to completely delete data, #2929
  - add FAQ about Borg config dir, #4941
  - add docs about errors not printed as JSON, #4073
  - update usage_general.rst.inc
  - added "Will move with BORG_CONFIG_DIR variable unless specified." to BORG_SECURITY_DIR info.
  - put BORG_SECURITY_DIR immediately below BORG_CONFIG_DIR (and moved BORG_CACHE_DIR up before them).
  - add paragraph regarding cache security assumptions, #4900
  - tell about borg cache security precautions
  - add FAQ describing difference between a local repo vs. repo on a server.
  - document how to test exclusion patterns without performing an actual backup
  - create: tell that "Calculating size" time and space needs are caused by --progress
  - fix/improve documentation for @api decorator, #4674
  - add a pull backup / push restore how-to, #1552
  - fix man pages creation, #4752
  - more general FAQ for backup and retain original paths, #4532
  - explain difference between --exclude and --pattern, #4118
  - add FAQ for preventing SSH timeout in extract, #3866
  - improve password FAQ (decrease pw length, add -w 0 option to base64 to prevent line wrap), #4591
  - add note about patterns and stored paths, #4160
  - add upgrade of tools to pip installation how-to, #5090
  - document one cause of orphaned chunks in check command, #2295
  - clean up the whole check usage paragraph
  - FAQ: linked recommended restrictions to ssh public keys on borg servers, #4946
  - fixed "doc downplays severity of Nonce reuse issue", #4883
  - borg repo restore instructions needed, #3428
  - new FAQ: A repo is corrupt and must be replaced with an older repo.
  - clarify borg init's encryption modes
- native windows port:

  - update README_WINDOWS.rst
  - updated pyinstaller spec file to support windows builds
- testing / CI:

  - improved travis config / install script, improved macOS builds
  - allow osx builds to fail, #4955
  - Windows 10 build on Appveyor CI
- vagrant:

  - upgrade pyinstaller to v3.5 + patch
  - use py369 for binary build, add py380 for tests
  - fix issue in stretch VM hanging at grub installation
  - add a debian buster and a ubuntu focal VM
  - update darwin box to 10.12
  - upgrade FreeBSD box to 12.1
  - fix debianoid virtualenv packages
  - use pyenv in freebsd64 VM
  - remove the flake8 test
  - darwin: avoid error if pkg is already installed
  - debianoid: don't interactively ask questions


Version 1.2.0a7 (2019-09-07)
----------------------------

Fixes:

- slave hardlinks extraction issue, see #4350
- extract: fix KeyError for "partial" extraction, #4607
- preload chunks for hardlink slaves w/o preloaded master, #4350
- fix preloading for old remote servers, #4652
- fix partial extract for hardlinked contentless file types, #4725
- Repository.open: use stat() to check for repo dir, #4695
- Repository.check_can_create_repository: use stat() to check, ~ #4695.
- SecurityManager.known(): check all files, #4614
- after double-force delete, warn about necessary repair, #4704
- cope with ANY error when importing pytest into borg.testsuite, #4652
- fix invalid archive error message
- setup.py: fix detection of missing Cython
- filter out selinux xattrs, #4574
- location arg - should it be optional? #4541
- enable placeholder usage in --comment, #4559
- use whitelist approach for borg serve, #4097

New features:

- minimal native Windows support, see windows readme (work in progress)
- create: first ctrl-c (SIGINT) triggers checkpoint and abort, #4606
- new BORG_WORKAROUNDS mechanism, basesyncfile, #4710
- remove WSL autodetection. if WSL still has this problem, you need to
  set BORG_WORKAROUNDS=basesyncfile in the borg process environment to
  work around it.
- support xxh64 checksum in addition to the hashlib hashes in borg list
- enable placeholder usage in all extra archive arguments
- enable placeholder usage in --comment, #4559
- enable placeholder usage in --glob-archives, #4495
- ability to use a system-provided version of "xxhash"
- create:

  - changed the default behaviour to not store the atime of fs items. atime is
    often rather not interesting and fragile - it easily changes even if nothing
    else has changed and, if stored into the archive, spoils deduplication of
    the archive metadata stream.
  - if you give the --noatime option, borg will output a deprecation warning
    because it is currently ignored / does nothing.
    Please remove the --noatime option when using borg 1.2.
  - added a --atime option for storing files' atime into an archive

Other changes:

- argparser: always use REPOSITORY in metavar
- do not check python/libc for borg serve, #4483
- small borg compact improvements, #4522
- compact: log freed space at INFO level
- tests:

  - tox / travis: add testing on py38-dev
  - fix broken test that relied on improper zlib assumptions
  - pure-py msgpack warning shall not make a lot of tests fail, #4558
  - rename test_mount_hardlinks to test_fuse_mount_hardlinks (master)
  - vagrant: add up-to-date openindiana box (py35, openssl10)
  - get rid of confusing coverage warning, #2069
- docs:

  - reiterate that 'file cache names are absolute' in FAQ,
    mention bind mount solution, #4738
  - add restore docs, #4670
  - updated docs to cover use of temp directory on remote, #4545
  - add a push-style example to borg-create(1), #4613
  - timestamps in the files cache are now usually ctime, #4583
  - benchmark crud: clarify that space is used until compact
  - update documentation of borg create,
    corrects a mention of borg 1.1 as a future version.
  - fix osxfuse github link in installation docs
  - how to supply a passphrase, use crypto devices, #4549
  - extract: document limitation "needs empty destination",  #4598
  - update macOS Brew link
  - add note about software for automating backup
  - compact: improve docs,
  - README: new URL for funding options


Version 1.2.0a6 (2019-04-22)
----------------------------

Fixes:

- delete / prune: consider part files correctly for stats, #4507
- fix "all archives" stats considering part files, #4329
- create: only run stat_simple_attrs() once
- create: --stats does not work with --dry-run, exit with error msg, #4373
- give "invalid repo" error msg if repo config not found, #4411

New features:

- display msgpack version as part of sysinfo (e.g. in tracebacks)

Other changes:

- docs:

  - sdd "SSH Configuration" section, #4493, #3988, #636, #4485
  - better document borg check --max-duration, #4473
  - sorted commands help in multiple steps, #4471
- testing:

  - travis: use py 3.5.3 and 3.6.7 on macOS to get a pyenv-based python
    build with openssl 1.1
  - vagrant: use py 3.5.3 and 3.6.8 on darwin64 VM to build python and
    borg with openssl 1.1
  - pytest: -v and default XDISTN to 1, #4481


Version 1.2.0a5 (2019-03-21)
----------------------------

Fixes:

- warn if a file has changed while being backed up, #1750
- lrucache: regularly remove old FDs, #4427
- borg command shall terminate with rc 2 for ImportErrors, #4424
- make freebsd xattr platform code api compatible with linux, #3952

Other changes:

- major setup code refactoring (especially how libraries like openssl, liblz4,
  libzstd, libb2 are discovered and how it falls back to code bundled with
  borg), new: uses pkg-config now (and needs python "pkgconfig" package
  installed), #1925

  if you are a borg package maintainer, please try packaging this
  (see comments in setup.py).
- Vagrantfile: add zstd, reorder, build env vars, #4444
- travis: install script improvements
- update shell completions
- docs:

  - add a sample logging.conf in docs/misc, #4380
  - fix spelling errors
  - update requirements / install docs, #4374


Version 1.2.0a4 (2019-03-11)
----------------------------

Fixes:

- do not use O_NONBLOCK for special files, like FIFOs, block and char devices
  when using --read-special. fixes backing up FIFOs. fixes to test. #4394
- more LibreSSL build fixes: LibreSSL has HMAC_CTX_free and HMAC_CTX_new

New features:

- check: incremental repo check (only checks crc32 for segment entries), #1657
  borg check --repository-only --max-duration SECONDS ...
- delete: timestamp for borg delete --info added, #4359

Other changes:

- redo stale lock handling, #3986
  drop BORG_HOSTNAME_IS_UNIQUE (please use BORG_HOST_ID if needed).
  borg now always assumes it has a unique host id - either automatically
  from fqdn plus uuid.getnode() or overridden via BORG_HOST_ID.
- docs:

  - added Alpine Linux to distribution list
  - elaborate on append-only mode docs
- vagrant:

  - darwin: new 10.12 box
  - freebsd: new 12.0 box
  - openbsd: new 6.4 box
  - misc. updates / fixes


Version 1.2.0a3 (2019-02-26)
----------------------------

Fixes:

- LibreSSL build fixes, #4403
- dummy ACL/xattr code fixes (used by OpenBSD and others), #4403
- create: fix openat/statat issues for root directory, #4405


Version 1.2.0a2 and earlier (2019-02-24)
----------------------------------------

New features:

- compact: "borg compact" needs to be used to free repository space by
  compacting the segments (reading sparse segments, rewriting still needed
  data to new segments, deleting the sparse segments).
  Borg < 1.2 invoked compaction automatically at the end of each repository
  writing command.
  Borg >= 1.2 does not do that any more to give better speed, more control,
  more segment file stability (== less stuff moving to newer segments) and
  more robustness.
  See the docs about "borg compact" for more details.
- "borg compact --cleanup-commits" is to cleanup the tons of 17byte long
  commit-only segment files caused by borg 1.1.x issue #2850.
  Invoke this once after upgrading (the server side) borg to 1.2.
  Compaction now automatically removes unneeded commit-only segment files.
- prune: Show which rule was applied to keep archive, #2886
- add fixed blocksize chunker (see --chunker-params docs), #1086

Fixes:

- avoid stale filehandle issues, #3265
- use more FDs, avoid race conditions on active fs, #906, #908, #1038
- add O_NOFOLLOW to base flags, #908
- compact:

  - require >10% freeable space in a segment, #2985
  - repository compaction now automatically removes unneeded 17byte
    commit-only segments, #2850
- make swidth available on all posix platforms, #2667

Other changes:

- repository: better speed and less stuff moving around by using separate
  segment files for manifest DELETEs and PUTs, #3947
- use pyinstaller v3.3.1 to build binaries
- update bundled zstd code to 1.3.8, #4210
- update bundled lz4 code to 1.8.3, #4209
- msgpack:

  - switch to recent "msgpack" pypi pkg name, #3890
  - wrap msgpack to avoid future compat complications, #3632, #2738
  - support msgpack 0.6.0 and 0.6.1, #4220, #4308

- llfuse: modernize / simplify llfuse version requirements
- code refactorings / internal improvements:

  - include size/csize/nfiles[_parts] stats into archive, #3241
  - calc_stats: use archive stats metadata, if available
  - crypto: refactored crypto to use an AEAD style API
  - crypto: new AES-OCB, CHACHA20-POLY1305
  - create: use less syscalls by not using a python file obj, #906, #3962
  - diff: refactor the diff functionality to new ItemDiff class, #2475
  - archive: create FilesystemObjectProcessors class
  - helpers: make a package, split into smaller modules
  - xattrs: move to platform package, use cython instead ctypes, #2495
  - xattrs/acls/bsdflags: misc. code/api optimizations
  - FUSE: separate creation of filesystem from implementation of llfuse funcs, #3042
  - FUSE: use unpacker.tell() instead of deprecated write_bytes, #3899
  - setup.py: move build_man / build_usage code to setup_docs.py
  - setup.py: update to use a newer Cython/setuptools API for compiling .pyx -> .c, #3788
  - use python 3.5's os.scandir / os.set_blocking
  - multithreading preparations (not used yet):

    - item.to_optr(), Item.from_optr()
    - fix chunker holding the GIL during blocking I/O
  - C code portability / basic MSC compatibility, #4147, #2677
- testing:

  - vagrant: new VMs for linux/bsd/darwin, most with OpenSSL 1.1 and py36


Version 1.1.18 (2022-06-05)
---------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.
- 1.1.11 removes WSL autodetection (Windows 10 Subsystem for Linux).
  If WSL still has a problem with sync_file_range, you need to set
  BORG_WORKAROUNDS=basesyncfile in the borg process environment to
  work around the WSL issue.
- 1.1.14 changes return codes due to a bug fix:
  In case you have scripts expecting rc == 2 for a signal exit, you need to
  update them to check for >= 128 (as documented since long).
- 1.1.15 drops python 3.4 support, minimum requirement is 3.5 now.
- 1.1.17 install_requires the "packaging" pypi package now.

New features:

- check --repair: significantly speed up search for next valid object in segment, #6022
- create: add retry_erofs workaround for O_NOATIME issue on volume shadow copies in WSL1, #6024
- key export: display key if path is '-' or not given, #6092
- list --format: add command_line to format keys, #6108

Fixes:

- check: improve error handling for corrupt archive metadata block,
  make robust_iterator more robust, #4777
- diff: support presence change for blkdev, chrdev and fifo items, #6483
- diff: reduce memory consumption, fix is_hardlink_master
- init: disallow overwriting of existing keyfiles
- info: fix authenticated mode repo to show "Encrypted: No", #6462
- info: emit repo info even if repo has 0 archives, #6120
- list: remove placeholders for shake_* hashes, #6082
- mount -o versions: give clear error msg instead of crashing
- show_progress: add finished=true/false to archive_progress json, #6570
- fix hardlinkable file type check, #6037
- do not show archive name in error msgs referring to the repository, #6023
- prettier error msg (no stacktrace) if exclude file is missing, #5734
- do not require BORG_CONFIG_DIR if BORG_{SECURITY,KEYS}_DIR are set, #5979
- atomically create the CACHE_TAG file, #6028
- deal with the SaveFile/SyncFile race, docs, see #6176 5c5b59bc9
- avoid expanding path into LHS of formatting operation + tests, #6064 #6063
- repository: quota / compactable computation fixes, #6119.
  This is mainly to keep the repo code in sync with borg 1.2. As borg 1.1
  compacts immediately, there was not really an issue with this in 1.1.
- fix transaction rollback: use files cache filename as found in txn.active, #6353
- do not load files cache for commands not using it, fixes #5673
- fix scp repo url parsing for ip v6 addrs, #6526
- repo::archive location placeholder expansion fixes, #5826, #5998

  - use expanded location for log output
  - support placeholder expansion for BORG_REPO env var
- respect umask for created directory and file modes, #6400
- safer truncate_and_unlink implementation

Other changes:

- upgrade bundled xxhash code to 0.8.1
- fix xxh64 related build (setup.py and post-0.8.1 patch for static_assert).
  The patch was required to build the bundled xxhash code on FreeBSD, see
  https://github.com/Cyan4973/xxHash/pull/670
- msgpack build: remove endianness macro, #6105
- update and fix shell completions
- fuse: remove unneeded version check and compat code
- delete --force: do not ask when deleting a repo, #5941
- delete: don't commit if nothing was deleted, avoid cache sync, #6060
- delete: add repository id and location to prompt
- compact segments: improve freeable / freed space log output, #5679
- if ensure_dir() fails, give more informative error message, #5952
- load_key: no key is same as empty key, #6441
- better error msg for defect or unsupported repo configs, #6566
- use hmac.compare_digest instead of ==, #6470
- implement more standard hashindex.setdefault behaviour
- remove stray punctuation from secure-erase message
- add development.lock.txt, use a real python 3.5 to generate frozen reqs
- setuptools 60.7.0 breaks pyinstaller, #6246
- setup.py clean2 was added to work around some setuptools customizability limitation.
- allow extra compiler flags for every extension build
- C code: make switch fallthrough explicit
- Cython code: fix "useless trailing comma" cython warnings
- requirements.lock.txt: use the latest cython 0.29.30
- fix compilation warnings: ‘PyUnicode_AsUnicode’ is deprecated
- docs:

  - ~/.config/borg/keys is not used for repokey keys, #6107
  - excluded parent dir's metadata can't restore, #6062
  - permissions note rewritten to make it less confusing, #5490
  - add note about grandfather-father-son backup retention policy / rotation scheme
  - clarify who starts the remote agent (borg serve)
  - test/improve pull backup docs, #5903
  - document the socat pull mode described in #900 #515ß
  - borg serve: improve ssh forced commands docs, #6083
  - improve docs for borg list --format, #6080
  - fix the broken link to .nix file
  - clarify pattern usage with commands, #5176
  - clarify user_id vs uid for fuse, #5723
  - fix binary build freebsd/macOS version, #5942
  - FAQ: fix manifest-timestamp path, #6016
  - remove duplicate faq entries, #5926
  - fix sphinx warnings, #5919
  - virtualisation speed tips
  - fix values of TAG bytes, #6515
  - recommend umask for passphrase file perms
  - update link to ubuntu packages, #6485
  - clarify on-disk order and size of log entry fields, #6357
  - do not transform --/--- to unicode dashes
  - improve linking inside docs, link to borg_placeholders, link to borg_patterns
  - use same phrasing in misc. help texts
  - borg init: explain the encryption modes better
  - explain the difference between a path that ends with or without a slash, #6297
  - clarify usage of patternfile roots, #6242
  - borg key export: add examples
  - updates about features not experimental any more: FUSE "versions" view, --pattern*, #6134
  - fix/update cygwin package requirements
  - impact of deleting path/to/repo/nonce, #5858
  - warn about tampered server nonce
  - mention BORG_FILES_CACHE_SUFFIX as alternative to BORG_FILES_CACHE_TTL, #5602
  - add a troubleshooting note about "is not a valid repository" to the FAQ
- vagrant / CI / testing:

  - misc. fixes and updates, new python versions
  - macOS on github: re-enable fuse2 testing by downgrading to older macOS, #6099
  - fix OpenBSD symlink mode test failure, #2055
  - use the generic/openbsd6 box
  - strengthen the test: we can read data w/o nonces
  - add tests for path/to/repo/nonce deletion
  - darwin64: backport some tunings from master
  - darwin64: remove fakeroot, #6314
  - darwin64: fix vagrant scp, #5921
  - darwin64: use macfuse instead of osxfuse
  - add ubuntu "jammy" 22.04 LTS VM
  - adapt memory for openindiana64 and darwin64


Version 1.1.17 (2021-07-12)
---------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.
- 1.1.11 removes WSL autodetection (Windows 10 Subsystem for Linux).
  If WSL still has a problem with sync_file_range, you need to set
  BORG_WORKAROUNDS=basesyncfile in the borg process environment to
  work around the WSL issue.
- 1.1.14 changes return codes due to a bug fix:
  In case you have scripts expecting rc == 2 for a signal exit, you need to
  update them to check for >= 128 (as documented since long).
- 1.1.15 drops python 3.4 support, minimum requirement is 3.5 now.
- 1.1.17 install_requires the "packaging" pypi package now.

Fixes:

- pyinstaller dir-mode: fix pyi detection / LIBPATH treatment, #5897
- handle crash due to kill stale lock race, #5828
- fix BORG_CACHE_DIR crashing borg if empty, #5216
- create --dry-run: fix display of kept tagfile, #5834
- fix missing parameter in "did not consistently fail" msg, #5822
- missing / healed chunks: always tell chunk ID, #5704
- benchmark: make sure cleanup happens even on exceptions, #5630

New features:

- implement BORG_SELFTEST env variable, #5871.
  this can be used to accelerate borg startup a bit. not recommended for
  normal usage, but borg mass hosters with a lot of borg invocations can
  save some resources with this. on my laptop, this saved ~100ms cpu time
  (sys+user) per borg command invocation.
- implement BORG_LIBC env variable to give the libc filename, #5870.
  you can use this if a borg does not find your libc.
- check: add progress indicator for archive check.
- allow --files-cache=size (not recommended, make sure you know what you do)

Other changes:

- Python 3.10 now officially supported!
  we test on py310-dev on github CI since a while and now also on the vagrant
  machines, so it should work ok.
- github CI: test on py310 (again)
- get rid of distutils, use packaging and setuptools.
  distutils is deprecated and gives warnings on py 3.10.
- setup.py: rename "clean" to "clean2" to avoid shadowing the "clean" command.
- remove libc filename fallback for the BSDs (there is no "usual" name)
- cleanup flake8 checks, fix some pep8 violations.
- docs building: replace deprecated function ".add_stylesheet()" for Sphinx 4 compatibility
- docs:

  - add a hint on sleeping computer and ssh connections, #5301
  - update the documentation on hacked backup client, #5480
  - improve docs/FAQ about append-only remote repos, #5497
  - complement the documentation for pattern files and exclude files, #5520
  - "filename with spaces" example added to exclude file, #5236
    note: no whitespace escaping needed, processed by borg.
  - add info on renaming repositories, #5240
  - clarify borg check --verify-data, #5808
  - add notice about defective hardware to check documentation, #5753
  - add paragraph added in #5855 to utility documentation source
  - add missing leading slashes in help patterns, #5857
  - clarify "you will need key and passphrase" borg init warning, #4622
  - pull mode: add some warnings, #5827
  - mention tar --compare (compare archive to fs files), #5880
  - fix typos, backport of #5597
- vagrant:

  - add py3.7.11 for binary build, also add 3.10-dev.
  - use latest Cython 0.29.23 for py310 compat fixes.
  - more RAM for openindiana upgrade plan resolver, it just hangs (swaps?) if
    there is too little RAM.
  - fix install_pyenv to adapt to recent changes in pyenv (same as in master now).
  - use generic/netbsd9 box, copied from master branch.


Version 1.1.16 (2021-03-23)
---------------------------

Fixes:

- setup.py: add special openssl prefix for Apple M1 compatibility
- do not recurse into duplicate roots, #5603
- remove empty shadowed_segments lists, #5275, #5614
- fix libpython load error when borg fat binary / dir-based binary is invoked
  via a symlink by upgrading pyinstaller to v4.2, #5688
- config: accept non-int value (like 500M or 100G) for max_segment_size or
  storage_quota, #5639.
  please note: when setting a non-int value for this in a repo config,
  using the repo will require borg >= 1.1.16.

New features:

- bundled msgpack: drop support for old buffer protocol to support Python 3.10
- verbose files cache logging via --debug-topic=files_cache, #5659.
  Use this if you suspect that borg does not detect unmodified files as expected.
- create/extract: add --noxattrs and --noacls option, #3955.
  when given with borg create, borg will not get xattrs / ACLs from input files
  (and thus, it will not archive xattrs / ACLs). when given with borg extract,
  borg will not read xattrs / ACLs from archive and will not set xattrs / ACLs
  on extracted files.
- diff: add --json-lines option, #3765
- check: debug log segment filename
- borg debug dump-hints

Other changes:

- Tab completion support for additional archives for 'borg delete'
- repository: deduplicate code of put and delete, no functional change
- tests: fix result order issue (sporadic test failure on openindiana)
- vagrant:

  - upgrade pyinstaller to v4.2, #5671
  - avoid grub-install asking interactively for device
  - remove the xenial box
  - update freebsd box to 12.1
- docs:

  - update macOS install instructions, #5677
  - use macFUSE (not osxfuse) for Apple M1 compatibility
  - update docs for dev environment installation instructions, #5643
  - fix grammar in faq
  - recommend running tests only on installed versions for setup
  - add link back to git-installation
  - remove /var/cache exclusion in example commands, #5625.
    This is generally a poor idea and shouldn't be promoted through examples.
  - add repology.org badge with current packaging status
  - explain hash collision
  - add unsafe workaround to use an old repo copy, #5722


Version 1.1.15 (2020-12-25)
---------------------------

Fixes:

- extract:

  - improve exception handling when setting xattrs, #5092.
  - emit a warning message giving the path, xattr key and error message.
  - continue trying to restore other xattrs and bsdflags of the same file
    after an exception with xattr-setting happened.
- export-tar:

  - set tar format to GNU_FORMAT explicitly, #5274
  - fix memory leak with ssh: remote repository, #5568
  - fix potential memory leak with ssh: remote repository with partial extraction
- create: fix --dry-run and --stats coexistence, #5415
- use --timestamp for {utcnow} and {now} if given, #5189

New features:

- create: implement --stdin-mode, --stdin-user and --stdin-group, #5333
- allow appending the files cache filename with BORG_FILES_CACHE_SUFFIX env var

Other changes:

- drop python 3.4 support, minimum requirement is 3.5 now.
- enable using libxxhash instead of bundled xxh64 code
- update llfuse requirements (1.3.8)
- set cython language_level in some files to fix warnings
- allow EIO with warning when trying to hardlink
- PropDict: fail early if internal_dict is not a dict
- update shell completions
- tests / CI

  - add a test for the hashindex corruption bug, #5531 #4829
  - fix spurious failure in test_cache_files, #5438
  - added a github ci workflow
  - reduce testing on travis, no macOS, no py3x-dev, #5467
  - travis: use newer dists, native py on dist
- vagrant:

  - remove jessie and trusty boxes, #5348 #5383
  - pyinstaller 4.0, build on py379
  - binary build on stretch64, #5348
  - remove easy_install based pip installation
- docs:

  - clarify '--one-file-system' for btrfs, #5391
  - add example for excluding content using the --pattern cmd line arg
  - complement the documentation for pattern files and exclude files, #5524
  - made ansible playbook more generic, use package instead of pacman. also
    change state from "latest" to "present".
  - complete documentation on append-only remote repos, #5497
  - internals: rather talk about target size than statistics, #5336
  - new compression algorithm policy, #1633 #5505
  - faq: add a hint on sleeping computer, #5301
  - note requirements for full disk access on macOS Catalina, #5303
  - fix/improve description of borg upgrade hardlink usage, #5518
- modernize 1.1 code:

  - drop code/workarounds only needed to support Python 3.4
  - remove workaround for pre-release py37 argparse bug
  - removed some outdated comments/docstrings
  - requirements: remove some restrictions, lock on current versions


Version 1.1.14 (2020-10-07)
---------------------------

Fixes:

- check --repair: fix potential data loss when interrupting it, #5325
- exit with 128 + signal number (as documented) when borg is killed by a signal, #5161
- fix hardlinked CACHEDIR.TAG processing, #4911
- create --read-special: .part files also should be regular files, #5217
- llfuse dependency: choose least broken 1.3.6/1.3.7.
  1.3.6 is broken on python 3.9, 1.3.7 is broken on FreeBSD.

Other changes:

- upgrade bundled xxhash to 0.7.4
- self test: if it fails, also point to OS and hardware, #5334
- pyinstaller: compute basepath from spec file location
- prettier error message when archive gets too big, #5307
- check/recreate are not "experimental" any more (but still potentially dangerous):

  - recreate: remove extra confirmation
  - rephrase some warnings, update docs, #5164
- shell completions:

  - misc. updates / fixes
  - support repositories in fish tab completion, #5256
  - complete $BORG_RECREATE_I_KNOW_WHAT_I_AM_DOING
  - rewrite zsh completion:

    - completion for almost all optional and positional arguments
    - completion for Borg environment variables (parameters)
- use "allow/deny list" instead of "white/black list" wording
- declare "allow_cache_wipe" marker in setup.cfg to avoid pytest warning
- vagrant / tests:

  - misc. fixes / updates
  - use python 3.5.10 for binary build
  - build directory-based binaries additionally to the single file binaries
  - add libffi-dev, required to build python
  - use cryptography<3.0, more recent versions break the jessie box
  - test on python 3.9
  - do brew update with /dev/null redirect to avoid "too much log output" on travis-ci
- docs:

  - add ssh-agent pull backup method docs, #5288
  - how to approach borg speed issues, #5371
  - mention double --force in prune docs
  - update Homebrew install instructions, #5185
  - better description of how cache and rebuilds of it work
  - point to borg create --list item flags in recreate usage, #5165
  - add security faq explaining AES-CTR crypto issues, #5254
  - add a note to create from stdin regarding files cache, #5180
  - fix borg.1 manpage generation regression, #5211
  - clarify how exclude options work in recreate, #5193
  - add section for retired contributors
  - hint about not misusing private email addresses of contributors for borg support


Version 1.1.13 (2020-06-06)
---------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.
- 1.1.11 removes WSL autodetection (Windows 10 Subsystem for Linux).
  If WSL still has a problem with sync_file_range, you need to set
  BORG_WORKAROUNDS=basesyncfile in the borg process environment to
  work around the WSL issue.

Fixes:

- rebuilt using a current Cython version, compatible with python 3.8, #5214


Version 1.1.12 (2020-06-06)
---------------------------

Fixes:

- fix preload-related memory leak, #5202.
- mount / borgfs (FUSE filesystem):

  - fix FUSE low linear read speed on large files, #5067
  - fix crash on old llfuse without birthtime attrs, #5064 - accidentally
    we required llfuse >= 1.3. Now also old llfuse works again.
  - set f_namemax in statfs result, #2684
- update precedence of env vars to set config and cache paths, #4894
- correctly calculate compression ratio, taking header size into account, too

New features:

- --bypass-lock option to bypass locking with read-only repositories

Other changes:

- upgrade bundled zstd to 1.4.5
- travis: adding comments and explanations to Travis config / install script,
  improve macOS builds.
- tests: test_delete_force: avoid sporadic test setup issues, #5196
- misc. vagrant fixes
- the binary for macOS is now built on macOS 10.12
- the binaries for Linux are now built on Debian 8 "Jessie", #3761
- docs:

  - PlaceholderError not printed as JSON, #4073
  - "How important is Borg config?", #4941
  - make Sphinx warnings break docs build, #4587
  - some markup / warning fixes
  - add "updating borgbackup.org/releases" to release checklist, #4999
  - add "rendering docs" to release checklist, #5000
  - clarify borg init's encryption modes
  - add note about patterns and stored paths, #4160
  - add upgrade of tools to pip installation how-to
  - document one cause of orphaned chunks in check command, #2295
  - linked recommended restrictions to ssh public keys on borg servers in faq, #4946


Version 1.1.11 (2020-03-08)
---------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.
- 1.1.11 removes WSL autodetection (Windows 10 Subsystem for Linux).
  If WSL still has a problem with sync_file_range, you need to set
  BORG_WORKAROUNDS=basesyncfile in the borg process environment to
  work around the WSL issue.

Fixes:

- fixed potential index corruption / data loss issue due to bug in hashindex_set, #4829.
  Please read and follow the more detailed notes close to the top of this document.
- upgrade bundled xxhash to 0.7.3, #4891.
  0.7.2 is the minimum requirement for correct operations on ARMv6 in non-fixup
  mode, where unaligned memory accesses cause bus errors.
  0.7.3 adds some speedups and libxxhash 0.7.3 even has a pkg-config file now.
- upgrade bundled lz4 to 1.9.2
- upgrade bundled zstd to 1.4.4
- fix crash when upgrading erroneous hints file, #4922
- extract:

  - fix KeyError for "partial" extraction, #4607
  - fix "partial" extract for hardlinked contentless file types, #4725
  - fix preloading for old (0.xx) remote servers, #4652
  - fix confusing output of borg extract --list --strip-components, #4934
- delete: after double-force delete, warn about necessary repair, #4704
- create: give invalid repo error msg if repo config not found, #4411
- mount: fix FUSE mount missing st_birthtime, #4763 #4767
- check: do not stumble over invalid item key, #4845
- info: if the archive doesn't exist, print a pretty message, #4793
- SecurityManager.known(): check all files, #4614
- Repository.open: use stat() to check for repo dir, #4695
- Repository.check_can_create_repository: use stat() to check, #4695
- fix invalid archive error message
- fix optional/non-optional location arg, #4541
- commit-time free space calc: ignore bad compact map entries, #4796
- ignore EACCES (errno 13) when hardlinking the old config, #4730
- --prefix / -P: fix processing, avoid argparse issue, #4769

New features:

- enable placeholder usage in all extra archive arguments
- new BORG_WORKAROUNDS mechanism, basesyncfile, #4710
- recreate: support --timestamp option, #4745
- support platforms without os.link (e.g. Android with Termux), #4901.
  if we don't have os.link, we just extract another copy instead of making a hardlink.
- support linux platforms without sync_file_range (e.g. Android 7 with Termux), #4905

Other:

- ignore --stats when given with --dry-run, but continue, #4373
- add some ProgressIndicator msgids to code / fix docs, #4935
- elaborate on "Calculating size" message
- argparser: always use REPOSITORY in metavar, also use more consistent help phrasing.
- check: improve error output for matching index size, see #4829
- docs:

  - changelog: add advisory about hashindex_set bug #4829
  - better describe BORG_SECURITY_DIR, BORG_CACHE_DIR, #4919
  - infos about cache security assumptions, #4900
  - add FAQ describing difference between a local repo vs. repo on a server.
  - document how to test exclusion patterns without performing an actual backup
  - timestamps in the files cache are now usually ctime, #4583
  - fix bad reference to borg compact (does not exist in 1.1), #4660
  - create: borg 1.1 is not future any more
  - extract: document limitation "needs empty destination", #4598
  - how to supply a passphrase, use crypto devices, #4549
  - fix osxfuse github link in installation docs
  - add example of exclude-norecurse rule in help patterns
  - update macOS Brew link
  - add note about software for automating backups, #4581
  - AUTHORS: mention copyright+license for bundled msgpack
  - fix various code blocks in the docs, #4708
  - updated docs to cover use of temp directory on remote, #4545
  - add restore docs, #4670
  - add a pull backup / push restore how-to, #1552
  - add FAQ how to retain original paths, #4532
  - explain difference between --exclude and --pattern, #4118
  - add FAQs for SSH connection issues, #3866
  - improve password FAQ, #4591
  - reiterate that 'file cache names are absolute' in FAQ
- tests:

  - cope with ANY error when importing pytest into borg.testsuite, #4652
  - fix broken test that relied on improper zlib assumptions
  - test_fuse: filter out selinux xattrs, #4574
- travis / vagrant:

  - misc python versions removed / changed (due to openssl 1.1 compatibility)
    or added (3.7 and 3.8, for better borg compatibility testing)
  - binary building is on python 3.5.9 now
- vagrant:

  - add new boxes: ubuntu 18.04 and 20.04, debian 10
  - update boxes: openindiana, darwin, netbsd
  - remove old boxes: centos 6
  - darwin: updated osxfuse to 3.10.4
  - use debian/ubuntu pip/virtualenv packages
  - rather use python 3.6.2 than 3.6.0, fixes coverage/sqlite3 issue
  - use requirements.d/development.lock.txt to avoid compat issues
- travis:

  - darwin: backport some install code / order from master
  - remove deprecated keyword "sudo" from travis config
  - allow osx builds to fail, #4955
    this is due to travis-ci frequently being so slow that the OS X builds
    just fail because they exceed 50 minutes and get killed by travis.


Version 1.1.10 (2019-05-16)
---------------------------

Fixes:

- extract: hang on partial extraction with ssh: repo, when hardlink master
  is not matched/extracted and borg hangs on related slave hardlink, #4350
- lrucache: regularly remove old FDs, #4427
- avoid stale filehandle issues, #3265
- freebsd: make xattr platform code api compatible with linux, #3952
- use whitelist approach for borg serve, #4097
- borg command shall terminate with rc 2 for ImportErrors, #4424
- create: only run stat_simple_attrs() once, this increases
  backup with lots of unchanged files performance by ~ 5%.
- prune: fix incorrect borg prune --stats output with --dry-run, #4373
- key export: emit user-friendly error if repo key is exported to a directory,
  #4348

New features:

- bundle latest supported msgpack-python release (0.5.6), remove msgpack-python
  from setup.py install_requires - by default we use the bundled code now.
  optionally, we still support using an external msgpack (see hints in
  setup.py), but this requires solid requirements management within
  distributions and is not recommended.
  borgbackup will break if you upgrade msgpack to an unsupported version.
- display msgpack version as part of sysinfo (e.g. in tracebacks)
- timestamp for borg delete --info added, #4359
- enable placeholder usage in --comment and --glob-archives, #4559, #4495

Other:

- serve: do not check python/libc for borg serve, #4483
- shell completions: borg diff second archive
- release scripts: signing binaries with Qubes OS support
- testing:

  - vagrant: upgrade openbsd box to 6.4
  - travis-ci: lock test env to py 3.4 compatible versions, #4343
  - get rid of confusing coverage warning, #2069
  - rename test_mount_hardlinks to test_fuse_mount_hardlinks,
    so both can be excluded by "not test_fuse".
  - pure-py msgpack warning shall not make a lot of tests fail, #4558
- docs:

  - add "SSH Configuration" section to "borg serve", #3988, #636, #4485
  - README: new URL for funding options
  - add a sample logging.conf in docs/misc, #4380
  - elaborate on append-only mode docs, #3504
  - installation: added Alpine Linux to distribution list, #4415
  - usage.html: only modify window.location when redirecting, #4133
  - add msgpack license to docs/3rd_party/msgpack
- vagrant / binary builds:

  - use python 3.5.7 for builds
  - use osxfuse 3.8.3


Version 1.1.9 (2019-02-10)
--------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.

Fixes:

- security fix: configure FUSE with "default_permissions", #3903
  "default_permissions" is now enforced by borg by default to let the
  kernel check uid/gid/mode based permissions.
  "ignore_permissions" can be given to not enforce "default_permissions".
- make "hostname" short, even on misconfigured systems, #4262
- fix free space calculation on macOS (and others?), #4289
- config: quit with error message when no key is provided, #4223
- recover_segment: handle too small segment files correctly, #4272
- correctly release memoryview, #4243
- avoid diaper pattern in configparser by opening files, #4263
- add "# cython: language_level=3" directive to .pyx files, #4214
- info: consider part files for "This archive" stats, #3522
- work around Microsoft WSL issue #645 (sync_file_range), #1961

New features:

- add --rsh command line option to complement BORG_RSH env var, #1701
- init: --make-parent-dirs parent1/parent2/repo_dir, #4235

Other:

- add archive name to check --repair output, #3447
- check for unsupported msgpack versions
- shell completions:

  - new shell completions for borg 1.1.9
  - more complete shell completions for borg mount -o
  - added shell completions for borg help
  - option arguments for zsh tab completion
- docs:

  - add FAQ regarding free disk space check, #3905
  - update BORG_PASSCOMMAND example and clarify variable expansion, #4249
  - FAQ regarding change of compression settings, #4222
  - add note about BSD flags to changelog, #4246
  - improve logging in example automation script
  - add note about files changing during backup, #4081
  - work around the backslash issue, #4280
  - update release workflow using twine (docs, scripts), #4213
  - add warnings on repository copies to avoid future problems, #4272
- tests:

  - fix the homebrew 1.9 issues on travis-ci, #4254
  - fix duplicate test method name, #4311


Version 1.1.8 (2018-12-09)
--------------------------

Fixes:

- enforce storage quota if set by serve-command, #4093
- invalid locations: give err msg containing parsed location, #4179
- list repo: add placeholders for hostname and username, #4130
- on linux, symlinks can't have ACLs, so don't try to set any, #4044

New features:

- create: added PATH::archive output on INFO log level
- read a passphrase from a file descriptor specified in the
  BORG_PASSPHRASE_FD environment variable.

Other:

- docs:

  - option --format is required for some expensive-to-compute values for json

    borg list by default does not compute expensive values except when
    they are needed. whether they are needed is determined by the format,
    in standard mode as well as in --json mode.
  - tell that our binaries are x86/x64 amd/intel, bauerj has ARM
  - fixed wrong archive name pattern in CRUD benchmark help
  - fixed link to cachedir spec in docs, #4140
- tests:

  - stop using fakeroot on travis, avoids sporadic EISDIR errors, #2482
  - xattr key names must start with "user." on linux
  - fix code so flake8 3.6 does not complain
  - explicitly convert environment variable to str, #4136
  - fix DeprecationWarning: Flags not at the start of the expression, #4137
  - support pytest4, #4172
- vagrant:

  - use python 3.5.6 for builds


Version 1.1.7 (2018-08-11)
--------------------------

Compatibility notes:

- added support for Python 3.7

Fixes:

- cache lock: use lock_wait everywhere to fix infinite wait, see #3968
- don't archive tagged dir when recursing an excluded dir, #3991
- py37 argparse: work around bad default in py 3.7.0a/b/rc, #3996
- py37 remove loggerDict.clear() from tearDown method, #3805
- some fixes for bugs which likely did not result in problems in practice:

  - fixed logic bug in platform module API version check
  - fixed xattr/acl function prototypes, added missing ones

New features:

- init: add warning to store both key and passphrase at safe place(s)
- BORG_HOST_ID env var to work around all-zero MAC address issue, #3985
- borg debug dump-repo-objs --ghost (dump everything from segment files,
  including deleted or superseded objects or commit tags)
- borg debug search-repo-objs (search in repo objects for hex bytes or strings)

Other changes:

- add Python 3.7 support
- updated shell completions
- call socket.gethostname only once
- locking: better logging, add some asserts
- borg debug dump-repo-objs:

  - filename layout improvements
  - use repository.scan() to get on-disk order
- docs:

  - update installation instructions for macOS
  - added instructions to install fuse via homebrew
  - improve diff docs
  - added note that checkpoints inside files requires 1.1+
  - add link to tempfile module
  - remove row/column-spanning from docs source, #4000 #3990
- tests:

  - fetch less data via os.urandom
  - add py37 env for tox
  - travis: add 3.7, remove 3.6-dev (we test with -dev in master)
- vagrant / binary builds:

  - use osxfuse 3.8.2
  - use own (uptodate) openindiana box


Version 1.1.6 (2018-06-11)
--------------------------

Compatibility notes:

- 1.1.6 changes:

  - also allow msgpack-python 0.5.6.

Fixes:

- fix borg exception handling on ENOSPC error with xattrs, #3808
- prune: fix/improve overall progress display
- borg config repo ... does not need cache/manifest/key, #3802
- debug dump-repo-objs should not depend on a manifest obj
- pypi package:

  - include .coveragerc, needed by tox.ini
  - fix package long description, #3854

New features:

- mount: add uid, gid, umask mount options
- delete:

  - only commit once, #3823
  - implement --dry-run, #3822
- check:

  - show progress while rebuilding missing manifest, #3787
  - more --repair output
- borg config --list <repo>, #3612

Other changes:

- update msgpack requirement, #3753
- update bundled zstd to 1.3.4, #3745
- update bundled lz4 code to 1.8.2, #3870
- docs:

  - describe what BORG_LIBZSTD_PREFIX does
  - fix and deduplicate encryption quickstart docs, #3776
- vagrant:

  - FUSE for macOS: upgrade 3.7.1 to 3.8.0
  - exclude macOS High Sierra upgrade on the darwin64 machine
  - remove borgbackup.egg-info dir in fs_init (after rsync)
  - use pyenv-based build/test on jessie32/62
  - use local 32 and 64bit debian jessie boxes
  - use "vagrant" as username for new xenial box
- travis OS X: use xcode 8.3 (not broken)


Version 1.1.5 (2018-04-01)
--------------------------

Compatibility notes:

- 1.1.5 changes:

  - require msgpack-python >= 0.4.6 and < 0.5.0.
    0.5.0+ dropped python 3.4 testing and also caused some other issues because
    the python package was renamed to msgpack and emitted some FutureWarning.

Fixes:

- create --list: fix that it was never showing M status, #3492
- create: fix timing for first checkpoint (read files cache early, init
  checkpoint timer after that), see #3394
- extract: set rc=1 when extracting damaged files with all-zero replacement
  chunks or with size inconsistencies, #3448
- diff: consider an empty file as different to a non-existing file, #3688
- files cache: improve exception handling, #3553
- ignore exceptions in scandir_inorder() caused by an implicit stat(),
  also remove unneeded sort, #3545
- fixed tab completion problem where a space is always added after path even
  when it shouldn't
- build: do .h file content checks in binary mode, fixes build issue for
  non-ascii header files on pure-ascii locale platforms, #3544 #3639
- borgfs: fix patterns/paths processing, #3551
- config: add some validation, #3566
- repository config: add validation for max_segment_size, #3592
- set cache previous_location on load instead of save
- remove platform.uname() call which caused library mismatch issues, #3732
- add exception handler around deprecated platform.linux_distribution() call
- use same datetime object for {now} and {utcnow}, #3548

New features:

- create: implement --stdin-name, #3533
- add chunker_params to borg archive info (--json)
- BORG_SHOW_SYSINFO=no to hide system information from exceptions

Other changes:

- updated zsh completions for borg 1.1.4
- files cache related code cleanups
- be more helpful when parsing invalid --pattern values, #3575
- be more clear in secure-erase warning message, #3591
- improve getpass user experience, #3689
- docs build: unicode problem fixed when using a py27-based sphinx
- docs:

  - security: explicitly note what happens OUTSIDE the attack model
  - security: add note about combining compression and encryption
  - security: describe chunk size / proximity issue, #3687
  - quickstart: add note about permissions, borg@localhost, #3452
  - quickstart: add introduction to repositories & archives, #3620
  - recreate --recompress: add missing metavar, clarify description, #3617
  - improve logging docs, #3549
  - add an example for --pattern usage, #3661
  - clarify path semantics when matching, #3598
  - link to offline documentation from README, #3502
  - add docs on how to verify a signed release with GPG, #3634
  - chunk seed is generated per repository (not: archive)
  - better formatting of CPU usage documentation, #3554
  - extend append-only repo rollback docs, #3579
- tests:

  - fix erroneously skipped zstd compressor tests, #3606
  - skip a test if argparse is broken, #3705
- vagrant:

  - xenial64 box now uses username 'vagrant', #3707
  - move cleanup steps to fs_init, #3706
  - the boxcutter wheezy boxes are 404, use local ones
  - update to Python 3.5.5 (for binary builds)


Version 1.1.4 (2017-12-31)
--------------------------

Compatibility notes:

- When upgrading from borg 1.0.x to 1.1.x, please note:

  - read all the compatibility notes for 1.1.0*, starting from 1.1.0b1.
  - borg upgrade: you do not need to and you also should not run it.
  - borg might ask some security-related questions once after upgrading.
    You can answer them either manually or via environment variable.
    One known case is if you use unencrypted repositories, then it will ask
    about a unknown unencrypted repository one time.
  - your first backup with 1.1.x might be significantly slower (it might
    completely read, chunk, hash a lot files) - this is due to the
    --files-cache mode change (and happens every time you change mode).
    You can avoid the one-time slowdown by using the pre-1.1.0rc4-compatible
    mode (but that is less safe for detecting changed files than the default).
    See the --files-cache docs for details.
- borg 1.1.4 changes:

  - zstd compression is new in borg 1.1.4, older borg can't handle it.
  - new minimum requirements for the compression libraries - if the required
    versions (header and lib) can't be found at build time, bundled code will
    be used:

    - added requirement: libzstd >= 1.3.0 (bundled: 1.3.2)
    - updated requirement: liblz4 >= 1.7.0 / r129 (bundled: 1.8.0)

Fixes:

- check: data corruption fix: fix for borg check --repair malfunction, #3444.
  See the more detailed notes close to the top of this document.
- delete: also delete security dir when deleting a repo, #3427
- prune: fix building the "borg prune" man page, #3398
- init: use given --storage-quota for local repo, #3470
- init: properly quote repo path in output
- fix startup delay with dns-only own fqdn resolving, #3471

New features:

- added zstd compression. try it!
- added placeholder {reverse-fqdn} for fqdn in reverse notation
- added BORG_BASE_DIR environment variable, #3338

Other changes:

- list help topics when invalid topic is requested
- fix lz4 deprecation warning, requires lz4 >= 1.7.0 (r129)
- add parens for C preprocessor macro argument usages (did not cause malfunction)
- exclude broken pytest 3.3.0 release
- updated fish/bash completions
- init: more clear exception messages for borg create, #3465
- docs:

  - add auto-generated docs for borg config
  - don't generate HTML docs page for borgfs, #3404
  - docs update for lz4 b2 zstd changes
  - add zstd to compression help, readme, docs
  - update requirements and install docs about bundled lz4 and zstd
- refactored build of the compress and crypto.low_level extensions, #3415:

  - move some lib/build related code to setup_{zstd,lz4,b2}.py
  - bundle lz4 1.8.0 (requirement: >= 1.7.0 / r129)
  - bundle zstd 1.3.2 (requirement: >= 1.3.0)
  - blake2 was already bundled
  - rename BORG_LZ4_PREFIX env var to BORG_LIBLZ4_PREFIX for better consistency:
    we also have BORG_LIBB2_PREFIX and BORG_LIBZSTD_PREFIX now.
  - add prefer_system_lib* = True settings to setup.py - by default the build
    will prefer a shared library over the bundled code, if library and headers
    can be found and meet the minimum requirements.


Version 1.1.3 (2017-11-27)
--------------------------

Fixes:

- Security Fix for CVE-2017-15914: Incorrect implementation of access controls
  allows remote users to override repository restrictions in Borg servers.
  A user able to access a remote Borg SSH server is able to circumvent access
  controls post-authentication.
  Affected releases: 1.1.0, 1.1.1, 1.1.2. Releases 1.0.x are NOT affected.
- crc32: deal with unaligned buffer, add tests - this broke borg on older ARM
  CPUs that can not deal with unaligned 32bit memory accesses and raise a bus
  error in such cases. the fix might also improve performance on some CPUs as
  all 32bit memory accesses by the crc32 code are properly aligned now. #3317
- mount: fixed support of --consider-part-files and do not show .borg_part_N
  files by default in the mounted FUSE filesystem. #3347
- fixed cache/repo timestamp inconsistency message, highlight that information
  is obtained from security dir (deleting the cache will not bypass this error
  in case the user knows this is a legitimate repo).
- borgfs: don't show sub-command in borgfs help, #3287
- create: show an error when --dry-run and --stats are used together, #3298

New features:

- mount: added exclusion group options and paths, #2138

  Reused some code to support similar options/paths as borg extract offers -
  making good use of these to only mount a smaller subset of dirs/files can
  speed up mounting a lot and also will consume way less memory.

  borg mount [options] repo_or_archive mountpoint path [paths...]

  paths: you can just give some "root paths" (like for borg extract) to
  only partially populate the FUSE filesystem.

  new options: --exclude[-from], --pattern[s-from], --strip-components
- create/extract: support st_birthtime on platforms supporting it, #3272
- add "borg config" command for querying/setting/deleting config values, #3304

Other changes:

- clean up and simplify packaging (only package committed files, do not install
  .c/.h/.pyx files)
- docs:

  - point out tuning options for borg create, #3239
  - add instructions for using ntfsclone, zerofree, #81
  - move image backup-related FAQ entries to a new page
  - clarify key aliases for borg list --format, #3111
  - mention break-lock in checkpointing FAQ entry, #3328
  - document sshfs rename workaround, #3315
  - add FAQ about removing files from existing archives
  - add FAQ about different prune policies
  - usage and man page for borgfs, #3216
  - clarify create --stats duration vs. wall time, #3301
  - clarify encrypted key format for borg key export, #3296
  - update release checklist about security fixes
  - document good and problematic option placements, fix examples, #3356
  - add note about using --nobsdflags to avoid speed penalty related to
    bsdflags, #3239
  - move most of support section to www.borgbackup.org


Version 1.1.2 (2017-11-05)
--------------------------

Fixes:

- fix KeyError crash when talking to borg server < 1.0.7, #3244
- extract: set bsdflags last (include immutable flag), #3263
- create: don't do stat() call on excluded-norecurse directory, fix exception
  handling for stat() call, #3209
- create --stats: do not count data volume twice when checkpointing, #3224
- recreate: move chunks_healthy when excluding hardlink master, #3228
- recreate: get rid of chunks_healthy when rechunking (does not match), #3218
- check: get rid of already existing not matching chunks_healthy metadata, #3218
- list: fix stdout broken pipe handling, #3245
- list/diff: remove tag-file options (not used), #3226

New features:

- bash, zsh and fish shell auto-completions, see scripts/shell_completions/
- added BORG_CONFIG_DIR env var, #3083

Other changes:

- docs:

  - clarify using a blank passphrase in keyfile mode
  - mention "!" (exclude-norecurse) type in "patterns" help
  - document to first heal before running borg recreate to re-chunk stuff,
    because that will have to get rid of chunks_healthy metadata.
  - more than 23 is not supported for CHUNK_MAX_EXP, #3115
  - borg does not respect nodump flag by default any more
  - clarify same-filesystem requirement for borg upgrade, #2083
  - update / rephrase cygwin / WSL status, #3174
  - improve docs about --stats, #3260
- vagrant: openindiana new clang package

Already contained in 1.1.1 (last minute fix):

- arg parsing: fix fallback function, refactor, #3205. This is a fixup
  for #3155, which was broken on at least python <= 3.4.2.


Version 1.1.1 (2017-10-22)
--------------------------

Compatibility notes:

- The deprecated --no-files-cache is not a global/common option any more,
  but only available for borg create (it is not needed for anything else).
  Use --files-cache=disabled instead of --no-files-cache.
- The nodump flag ("do not backup this file") is not honoured any more by
  default because this functionality (esp. if it happened by error or
  unexpected) was rather confusing and unexplainable at first to users.
  If you want that "do not backup NODUMP-flagged files" behaviour, use:
  borg create --exclude-nodump ...
- If you are on Linux and do not need bsdflags archived, consider using
  ``--nobsdflags`` with ``borg create`` to avoid additional syscalls and
  speed up backup creation.

Fixes:

- borg recreate: correctly compute part file sizes. fixes cosmetic, but
  annoying issue as borg check complains about size inconsistencies of part
  files in affected archives. you can solve that by running borg recreate on
  these archives, see also #3157.
- bsdflags support: do not open BLK/CHR/LNK files, avoid crashes and
  slowness, #3130
- recreate: don't crash on attic archives w/o time_end, #3109
- don't crash on repository filesystems w/o hardlink support, #3107
- don't crash in first part of truncate_and_unlink, #3117
- fix server-side IndexError crash with clients < 1.0.7, #3192
- don't show traceback if only a global option is given, show help, #3142
- cache: use SaveFile for more safety, #3158
- init: fix wrong encryption choices in command line parser, fix missing
  "authenticated-blake2", #3103
- move --no-files-cache from common to borg create options, #3146
- fix detection of non-local path (failed on ..filename), #3108
- logging with fileConfig: set json attr on "borg" logger, #3114
- fix crash with relative BORG_KEY_FILE, #3197
- show excluded dir with "x" for tagged dirs / caches, #3189

New features:

- create: --nobsdflags and --exclude-nodump options, #3160
- extract: --nobsdflags option, #3160

Other changes:

- remove annoying hardlinked symlinks warning, #3175
- vagrant: use self-made FreeBSD 10.3 box, #3022
- travis: don't brew update, hopefully fixes #2532
- docs:

  - readme: -e option is required in borg 1.1
  - add example showing --show-version --show-rc
  - use --format rather than --list-format (deprecated) in example
  - update docs about hardlinked symlinks limitation


Version 1.1.0 (2017-10-07)
--------------------------

Compatibility notes:

- borg command line: do not put options in between positional arguments

  This sometimes works (e.g. it worked in borg 1.0.x), but can easily stop
  working if we make positional arguments optional (like it happened for
  borg create's "paths" argument in 1.1). There are also places in borg 1.0
  where we do that, so it doesn't work there in general either. #3356

  Good: borg create -v --stats repo::archive path
  Good: borg create repo::archive path -v --stats
  Bad:  borg create repo::archive -v --stats path

Fixes:

- fix LD_LIBRARY_PATH restoration for subprocesses, #3077
- "auto" compression: make sure expensive compression is actually better,
  otherwise store lz4 compressed data we already computed.

Other changes:

- docs:

  - FAQ: we do not implement futile attempts of ETA / progress displays
  - manpage: fix typos, update homepage
  - implement simple "issue" role for manpage generation, #3075


Version 1.1.0rc4 (2017-10-01)
-----------------------------

Compatibility notes:

- A borg server >= 1.1.0rc4 does not support borg clients 1.1.0b3-b5. #3033
- The files cache is now controlled differently and has a new default mode:

  - the files cache now uses ctime by default for improved file change
    detection safety. You can still use mtime for more speed and less safety.
  - --ignore-inode is deprecated (use --files-cache=... without "inode")
  - --no-files-cache is deprecated (use --files-cache=disabled)

New features:

- --files-cache - implement files cache mode control, #911
  You can now control the files cache mode using this option:
  --files-cache={ctime,mtime,size,inode,rechunk,disabled}
  (only some combinations are supported). See the docs for details.

Fixes:

- remote progress/logging: deal with partial lines, #2637
- remote progress: flush json mode output
- fix subprocess environments, #3050 (and more)

Other changes:

- remove client_supports_log_v3 flag, #3033
- exclude broken Cython 0.27(.0) in requirements, #3066
- vagrant:

  - upgrade to FUSE for macOS 3.7.1
  - use Python 3.5.4 to build the binaries
- docs:

  - security: change-passphrase only changes the passphrase, #2990
  - fixed/improved borg create --compression examples, #3034
  - add note about metadata dedup and --no[ac]time, #2518
  - twitter account @borgbackup now, better visible, #2948
  - simplified rate limiting wrapper in FAQ


Version 1.1.0rc3 (2017-09-10)
-----------------------------

New features:

- delete: support naming multiple archives, #2958

Fixes:

- repo cleanup/write: invalidate cached FDs, #2982
- fix datetime.isoformat() microseconds issues, #2994
- recover_segment: use mmap(), lower memory needs, #2987

Other changes:

- with-lock: close segment file before invoking subprocess
- keymanager: don't depend on optional readline module, #2976
- docs:

  - fix macOS keychain integration command
  - show/link new screencasts in README, #2936
  - document utf-8 locale requirement for json mode, #2273
- vagrant: clean up shell profile init, user name, #2977
- test_detect_attic_repo: don't test mount, #2975
- add debug logging for repository cleanup


Version 1.1.0rc2 (2017-08-28)
-----------------------------

Compatibility notes:

- list: corrected mix-up of "isomtime" and "mtime" formats. Previously,
  "isomtime" was the default but produced a verbose human format,
  while "mtime" produced a ISO-8601-like format.
  The behaviours have been swapped (so "mtime" is human, "isomtime" is ISO-like),
  and the default is now "mtime".
  "isomtime" is now a real ISO-8601 format ("T" between date and time, not a space).

New features:

- None.

Fixes:

- list: fix weird mixup of mtime/isomtime
- create --timestamp: set start time, #2957
- ignore corrupt files cache, #2939
- migrate locks to child PID when daemonize is used
- fix exitcode of borg serve, #2910
- only compare contents when chunker params match, #2899
- umount: try fusermount, then try umount, #2863

Other changes:

- JSON: use a more standard ISO 8601 datetime format, #2376
- cache: write_archive_index: truncate_and_unlink on error, #2628
- detect non-upgraded Attic repositories, #1933
- delete various nogil and threading related lines
- coala / pylint related improvements
- docs:

  - renew asciinema/screencasts, #669
  - create: document exclusion through nodump, #2949
  - minor formatting fixes
  - tar: tarpipe example
  - improve "with-lock" and "info" docs, #2869
  - detail how to use macOS/GNOME/KDE keyrings for repo passwords, #392
- travis: only short-circuit docs-only changes for pull requests
- vagrant:

  - netbsd: bash is already installed
  - fix netbsd version in PKG_PATH
  - add exe location to PATH when we build an exe


Version 1.1.0rc1 (2017-07-24)
-----------------------------

Compatibility notes:

- delete: removed short option for --cache-only

New features:

- support borg list repo --format {comment} {bcomment} {end}, #2081
- key import: allow reading from stdin, #2760

Fixes:

- with-lock: avoid creating segment files that might be overwritten later, #1867
- prune: fix checkpoints processing with --glob-archives
- FUSE: versions view: keep original file extension at end, #2769
- fix --last, --first: do not accept values <= 0,
  fix reversed archive ordering with --last
- include testsuite data (attic.tar.gz) when installing the package
- use limited unpacker for outer key, for manifest (both security precautions),
  #2174 #2175
- fix bashism in shell scripts, #2820, #2816
- cleanup endianness detection, create _endian.h,
  fixes build on alpine linux, #2809
- fix crash with --no-cache-sync (give known chunk size to chunk_incref), #2853

Other changes:

- FUSE: versions view: linear numbering by archive time
- split up interval parsing from filtering for --keep-within, #2610
- add a basic .editorconfig, #2734
- use archive creation time as mtime for FUSE mount, #2834
- upgrade FUSE for macOS (osxfuse) from 3.5.8 to 3.6.3, #2706
- hashindex: speed up by replacing modulo with "if" to check for wraparound
- coala checker / pylint: fixed requirements and .coafile, more ignores
- borg upgrade: name backup directories as 'before-upgrade', #2811
- add .mailmap
- some minor changes suggested by lgtm.com
- docs:

  - better explanation of the --ignore-inode option relevance, #2800
  - fix openSUSE command and add openSUSE section
  - simplify ssh authorized_keys file using "restrict", add legacy note, #2121
  - mount: show usage of archive filters
  - mount: add repository example, #2462
  - info: update and add examples, #2765
  - prune: include example
  - improved style / formatting
  - improved/fixed segments_per_dir docs
  - recreate: fix wrong "remove unwanted files" example
  - reference list of status chars in borg recreate --filter description
  - update source-install docs about doc build dependencies, #2795
  - cleanup installation docs
  - file system requirements, update segs per dir
  - fix checkpoints/parts reference in FAQ, #2859
- code:

  - hashindex: don't pass side effect into macro
  - crypto low_level: don't mutate local bytes()
  - use dash_open function to open file or "-" for stdin/stdout
  - archiver: argparse cleanup / refactoring
  - shellpattern: add match_end arg
- tests: added some additional unit tests, some fixes, #2700 #2710
- vagrant: fix setup of cygwin, add Debian 9 "stretch"
- travis: don't perform full travis build on docs-only changes, #2531


Version 1.1.0b6 (2017-06-18)
----------------------------

Compatibility notes:

- Running "borg init" via a "borg serve --append-only" server will *not* create
  an append-only repository anymore. Use "borg init --append-only" to initialize
  an append-only repository.

- Repositories in the "repokey" and "repokey-blake2" modes with an empty passphrase
  are now treated as unencrypted repositories for security checks (e.g.
  BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK).

  Previously there would be no prompts nor messages if an unknown repository
  in one of these modes with an empty passphrase was encountered. This would
  allow an attacker to swap a repository, if one assumed that the lack of
  password prompts was due to a set BORG_PASSPHRASE.

  Since the "trick" does not work if BORG_PASSPHRASE is set, this does generally
  not affect scripts.

- Repositories in the "authenticated" mode are now treated as the unencrypted
  repositories they are.

- The client-side temporary repository cache now holds unencrypted data for better speed.

- borg init: removed the short form of --append-only (-a).

- borg upgrade: removed the short form of --inplace (-i).

New features:

- reimplemented the RepositoryCache, size-limited caching of decrypted repo
  contents, integrity checked via xxh64. #2515
- reduced space usage of chunks.archive.d. Existing caches are migrated during
  a cache sync. #235 #2638
- integrity checking using xxh64 for important files used by borg, #1101:

  - repository: index and hints files
  - cache: chunks and files caches, chunks.archive.d
- improve cache sync speed, #1729
- create: new --no-cache-sync option
- add repository mandatory feature flags infrastructure, #1806
- Verify most operations against SecurityManager. Location, manifest timestamp
  and key types are now checked for almost all non-debug commands. #2487
- implement storage quotas, #2517
- serve: add --restrict-to-repository, #2589
- BORG_PASSCOMMAND: use external tool providing the key passphrase, #2573
- borg export-tar, #2519
- list: --json-lines instead of --json for archive contents, #2439
- add --debug-profile option (and also "borg debug convert-profile"), #2473
- implement --glob-archives/-a, #2448
- normalize authenticated key modes for better naming consistency:

  - rename "authenticated" to "authenticated-blake2" (uses blake2b)
  - implement "authenticated" mode (uses hmac-sha256)

Fixes:

- hashindex: read/write indices >2 GiB on 32bit systems, better error
  reporting, #2496
- repository URLs: implement IPv6 address support and also more informative
  error message when parsing fails.
- mount: check whether llfuse is installed before asking for passphrase, #2540
- mount: do pre-mount checks before opening repository, #2541
- FUSE:

  - fix crash if empty (None) xattr is read, #2534
  - fix read(2) caching data in metadata cache
  - fix negative uid/gid crash (fix crash when mounting archives
    of external drives made on cygwin), #2674
  - redo ItemCache, on top of object cache
  - use decrypted cache
  - remove unnecessary normpaths
- serve: ignore --append-only when initializing a repository (borg init), #2501
- serve: fix incorrect type of exception_short for Errors, #2513
- fix --exclude and --exclude-from recursing into directories, #2469
- init: don't allow creating nested repositories, #2563
- --json: fix encryption[mode] not being the cmdline name
- remote: propagate Error.traceback correctly
- fix remote logging and progress, #2241

  - implement --debug-topic for remote servers
  - remote: restore "Remote:" prefix (as used in 1.0.x)
  - rpc negotiate: enable v3 log protocol only for supported clients
  - fix --progress and logging in general for remote
- fix parse_version, add tests, #2556
- repository: truncate segments (and also some other files) before unlinking, #2557
- recreate: keep timestamps as in original archive, #2384
- recreate: if single archive is not processed, exit 2
- patterns: don't recurse with ! / --exclude for pf:, #2509
- cache sync: fix n^2 behaviour in lookup_name
- extract: don't write to disk with --stdout (affected non-regular-file items), #2645
- hashindex: implement KeyError, more tests

Other changes:

- remote: show path in PathNotAllowed
- consider repokey w/o passphrase == unencrypted, #2169
- consider authenticated mode == unencrypted, #2503
- restrict key file names, #2560
- document follow_symlinks requirements, check libc, use stat and chown
  with follow_symlinks=False, #2507
- support common options on the main command, #2508
- support common options on mid-level commands (e.g. borg *key* export)
- make --progress a common option
- increase DEFAULT_SEGMENTS_PER_DIR to 1000
- chunker: fix invalid use of types (function only used by tests)
- chunker: don't do uint32_t >> 32
- FUSE:

  - add instrumentation (--debug and SIGUSR1/SIGINFO)
  - reduced memory usage for repository mounts by lazily instantiating archives
  - improved archive load times
- info: use CacheSynchronizer & HashIndex.stats_against (better performance)
- docs:

  - init: document --encryption as required
  - security: OpenSSL usage
  - security: used implementations; note python libraries
  - security: security track record of OpenSSL and msgpack
  - patterns: document denial of service (regex, wildcards)
  - init: note possible denial of service with "none" mode
  - init: document SHA extension is supported in OpenSSL and thus SHA is
    faster on AMD Ryzen than blake2b.
  - book: use A4 format, new builder option format.
  - book: create appendices
  - data structures: explain repository compaction
  - data structures: add chunk layout diagram
  - data structures: integrity checking
  - data structures: demingle cache and repo index
  - Attic FAQ: separate section for attic stuff
  - FAQ: I get an IntegrityError or similar - what now?
  - FAQ: Can I use Borg on SMR hard drives?, #2252
  - FAQ: specify "using inline shell scripts"
  - add systemd warning regarding placeholders, #2543
  - xattr: document API
  - add docs/misc/borg-data-flow data flow chart
  - debugging facilities
  - README: how to help the project, #2550
  - README: add bountysource badge, #2558
  - fresh new theme + tweaking
  - logo: vectorized (PDF and SVG) versions
  - frontends: use headlines - you can link to them
  - mark --pattern, --patterns-from as experimental
  - highlight experimental features in online docs
  - remove regex based pattern examples, #2458
  - nanorst for "borg help TOPIC" and --help
  - split deployment
  - deployment: hosting repositories
  - deployment: automated backups to a local hard drive
  - development: vagrant, windows10 requirements
  - development: update docs remarks
  - split usage docs, #2627
  - usage: avoid bash highlight, [options] instead of <options>
  - usage: add benchmark page
  - helpers: truncate_and_unlink doc
  - don't suggest to leak BORG_PASSPHRASE
  - internals: columnize rather long ToC [webkit fixup]
    internals: manifest & feature flags
  - internals: more HashIndex details
  - internals: fix ASCII art equations
  - internals: edited obj graph related sections a bit
  - internals: layers image + description
  - fix way too small figures in pdf
  - index: disable syntax highlight (bash)
  - improve options formatting, fix accidental block quotes

- testing / checking:

  - add support for using coala, #1366
  - testsuite: add ArchiverCorruptionTestCase
  - do not test logger name, #2504
  - call setup_logging after destroying logging config
  - testsuite.archiver: normalise pytest.raises vs. assert_raises
  - add test for preserved intermediate folder permissions, #2477
  - key: add round-trip test
  - remove attic dependency of the tests, #2505
  - enable remote tests on cygwin
  - tests: suppress tar's future timestamp warning
  - cache sync: add more refcount tests
  - repository: add tests, including corruption tests

- vagrant:

  - control VM cpus and pytest workers via env vars VMCPUS and XDISTN
  - update cleaning workdir
  - fix openbsd shell
  - add OpenIndiana

- packaging:

  - binaries: don't bundle libssl
  - setup.py clean to remove compiled files
  - fail in borg package if version metadata is very broken (setuptools_scm)

- repo / code structure:

  - create borg.algorithms and borg.crypto packages
  - algorithms: rename crc32 to checksums
  - move patterns to module, #2469
  - gitignore: complete paths for src/ excludes
  - cache: extract CacheConfig class
  - implement IntegrityCheckedFile + Detached variant, #2502 #1688
  - introduce popen_with_error_handling to handle common user errors


Version 1.1.0b5 (2017-04-30)
----------------------------

Compatibility notes:

- BORG_HOSTNAME_IS_UNIQUE is now on by default.
- removed --compression-from feature
- recreate: add --recompress flag, unify --always-recompress and
  --recompress

Fixes:

- catch exception for os.link when hardlinks are not supported, #2405
- borg rename / recreate: expand placeholders, #2386
- generic support for hardlinks (files, devices, FIFOs), #2324
- extract: also create parent dir for device files, if needed, #2358
- extract: if a hardlink master is not in the to-be-extracted subset,
  the "x" status was not displayed for it, #2351
- embrace y2038 issue to support 32bit platforms: clamp timestamps to int32,
  #2347
- verify_data: fix IntegrityError handling for defect chunks, #2442
- allow excluding parent and including child, #2314

Other changes:

- refactor compression decision stuff
- change global compression default to lz4 as well, to be consistent
  with --compression defaults.
- placeholders: deny access to internals and other unspecified stuff
- clearer error message for unrecognized placeholder
- more clear exception if borg check does not help, #2427
- vagrant: upgrade FUSE for macOS to 3.5.8, #2346
- linux binary builds: get rid of glibc 2.13 dependency, #2430
- docs:

  - placeholders: document escaping
  - serve: env vars in original commands are ignored
  - tell what kind of hardlinks we support
  - more docs about compression
  - LICENSE: use canonical formulation
    ("copyright holders and contributors" instead of "author")
  - document borg init behaviour via append-only borg serve, #2440
  - be clear about what buzhash is used for, #2390
  - add hint about chunker params, #2421
  - clarify borg upgrade docs, #2436
  - FAQ to explain warning when running borg check --repair, #2341
  - repository file system requirements, #2080
  - pre-install considerations
  - misc. formatting / crossref fixes
- tests:

  - enhance travis setuptools_scm situation
  - add extra test for the hashindex
  - fix invalid param issue in benchmarks

These belong to 1.1.0b4 release, but did not make it into changelog by then:

- vagrant: increase memory for parallel testing
- lz4 compress: lower max. buffer size, exception handling
- add docstring to do_benchmark_crud
- patterns help: mention path full-match in intro


Version 1.1.0b4 (2017-03-27)
----------------------------

Compatibility notes:

- init: the --encryption argument is mandatory now (there are several choices)
- moved "borg migrate-to-repokey" to "borg key migrate-to-repokey".
- "borg change-passphrase" is deprecated, use "borg key change-passphrase"
  instead.
- the --exclude-if-present option now supports tagging a folder with any
  filesystem object type (file, folder, etc), instead of expecting only files
  as tags, #1999
- the --keep-tag-files option has been deprecated in favor of the new
  --keep-exclude-tags, to account for the change mentioned above.
- use lz4 compression by default, #2179

New features:

- JSON API to make developing frontends and automation easier
  (see :ref:`json_output`)

  - add JSON output to commands: `borg create/list/info --json ...`.
  - add --log-json option for structured logging output.
  - add JSON progress information, JSON support for confirmations (yes()).
- add two new options --pattern and --patterns-from as discussed in #1406
- new path full match pattern style (pf:) for very fast matching, #2334
- add 'debug dump-manifest' and 'debug dump-archive' commands
- add 'borg benchmark crud' command, #1788
- new 'borg delete --force --force' to delete severely corrupted archives, #1975
- info: show utilization of maximum archive size, #1452
- list: add dsize and dcsize keys, #2164
- paperkey.html: Add interactive html template for printing key backups.
- key export: add qr html export mode
- securely erase config file (which might have old encryption key), #2257
- archived file items: add size to metadata, 'borg extract' and 'borg check' do
  check the file size for consistency, FUSE uses precomputed size from Item.

Fixes:

- fix remote speed regression introduced in 1.1.0b3, #2185
- fix regression handling timestamps beyond 2262 (revert bigint removal),
  introduced in 1.1.0b3, #2321
- clamp (nano)second values to unproblematic range, #2304
- hashindex: rebuild hashtable if we have too little empty buckets
  (performance fix), #2246
- Location regex: fix bad parsing of wrong syntax
- ignore posix_fadvise errors in repository.py, #2095
- borg rpc: use limited msgpack.Unpacker (security precaution), #2139
- Manifest: Make sure manifest timestamp is strictly monotonically increasing.
- create: handle BackupOSError on a per-path level in one spot
- create: clarify -x option / meaning of "same filesystem"
- create: don't create hard link refs to failed files
- archive check: detect and fix missing all-zero replacement chunks, #2180
- files cache: update inode number when --ignore-inode is used, #2226
- fix decompression exceptions crashing ``check --verify-data`` and others
  instead of reporting integrity error, #2224 #2221
- extract: warning for unextracted big extended attributes, #2258, #2161
- mount: umount on SIGINT/^C when in foreground
- mount: handle invalid hard link refs
- mount: fix huge RAM consumption when mounting a repository (saves number of
  archives * 8 MiB), #2308
- hashindex: detect mingw byte order #2073
- hashindex: fix wrong skip_hint on hashindex_set when encountering tombstones,
  the regression was introduced in #1748
- fix ChunkIndex.__contains__ assertion  for big-endian archs
- fix borg key/debug/benchmark crashing without subcommand, #2240
- Location: accept //servername/share/path
- correct/refactor calculation of unique/non-unique chunks
- extract: fix missing call to ProgressIndicator.finish
- prune: fix error msg, it is --keep-within, not --within
- fix "auto" compression mode bug (not compressing), #2331
- fix symlink item fs size computation, #2344

Other changes:

- remote repository: improved async exception processing, #2255 #2225
- with --compression auto,C, only use C if lz4 achieves at least 3% compression
- PatternMatcher: only normalize path once, #2338
- hashindex: separate endian-dependent defs from endian detection
- migrate-to-repokey: ask using canonical_path() as we do everywhere else.
- SyncFile: fix use of fd object after close
- make LoggedIO.close_segment reentrant
- creating a new segment: use "xb" mode, #2099
- redo key_creator, key_factory, centralise key knowledge, #2272
- add return code functions, #2199
- list: only load cache if needed
- list: files->items, clarifications
- list: add "name" key for consistency with info cmd
- ArchiveFormatter: add "start" key for compatibility with "info"
- RemoteRepository: account rx/tx bytes
- setup.py build_usage/build_man/build_api fixes
- Manifest.in: simplify, exclude .so, .dll and .orig, #2066
- FUSE: get rid of chunk accounting, st_blocks = ceil(size / blocksize).
- tests:

  - help python development by testing 3.6-dev
  - test for borg delete --force
- vagrant:

  - freebsd: some fixes, #2067
  - darwin64: use osxfuse 3.5.4 for tests / to build binaries
  - darwin64: improve VM settings
  - use python 3.5.3 to build binaries, #2078
  - upgrade pyinstaller from 3.1.1+ to 3.2.1
  - pyinstaller: use fixed AND freshly compiled bootloader, #2002
  - pyinstaller: automatically builds bootloader if missing
- docs:

  - create really nice man pages
  - faq: mention --remote-ratelimit in bandwidth limit question
  - fix caskroom link, #2299
  - docs/security: reiterate that RPC in Borg does no networking
  - docs/security: counter tracking, #2266
  - docs/development: update merge remarks
  - address SSH batch mode in docs, #2202 #2270
  - add warning about running build_usage on Python >3.4, #2123
  - one link per distro in the installation page
  - improve --exclude-if-present and --keep-exclude-tags, #2268
  - improve automated backup script in doc, #2214
  - improve remote-path description
  - update docs for create -C default change (lz4)
  - document relative path usage, #1868
  - document snapshot usage, #2178
  - corrected some stuff in internals+security
  - internals: move toctree to after the introduction text
  - clarify metadata kind, manifest ops
  - key enc: correct / clarify some stuff, link to internals/security
  - datas: enc: 1.1.x mas different MACs
  - datas: enc: correct factual error -- no nonce involved there.
  - make internals.rst an index page and edit it a bit
  - add "Cryptography in Borg" and "Remote RPC protocol security" sections
  - document BORG_HOSTNAME_IS_UNIQUE, #2087
  - FAQ by categories as proposed by @anarcat in #1802
  - FAQ: update Which file types, attributes, etc. are *not* preserved?
  - development: new branching model for git repository
  - development: define "ours" merge strategy for auto-generated files
  - create: move --exclude note to main doc
  - create: move item flags to main doc
  - fix examples using borg init without -e/--encryption
  - list: don't print key listings in fat (html + man)
  - remove Python API docs (were very incomplete, build problems on RTFD)
  - added FAQ section about backing up root partition


Version 1.1.0b3 (2017-01-15)
----------------------------

Compatibility notes:

- borg init: removed the default of "--encryption/-e", #1979
  This was done so users do a informed decision about -e mode.

Bug fixes:

- borg recreate: don't rechunkify unless explicitly told so
- borg info: fixed bug when called without arguments, #1914
- borg init: fix free space check crashing if disk is full, #1821
- borg debug delete/get obj: fix wrong reference to exception
- fix processing of remote ~/ and ~user/ paths (regressed since 1.1.0b1), #1759
- posix platform module: only build / import on non-win32 platforms, #2041

New features:

- new CRC32 implementations that are much faster than the zlib one used previously, #1970
- add blake2b key modes (use blake2b as MAC). This links against system libb2,
  if possible, otherwise uses bundled code
- automatically remove stale locks - set BORG_HOSTNAME_IS_UNIQUE env var
  to enable stale lock killing. If set, stale locks in both cache and
  repository are deleted. #562 #1253
- borg info <repo>: print general repo information, #1680
- borg check --first / --last / --sort / --prefix, #1663
- borg mount --first / --last / --sort / --prefix, #1542
- implement "health" item formatter key, #1749
- BORG_SECURITY_DIR to remember security related infos outside the cache.
  Key type, location and manifest timestamp checks now survive cache
  deletion. This also means that you can now delete your cache and avoid
  previous warnings, since Borg can still tell it's safe.
- implement BORG_NEW_PASSPHRASE, #1768

Other changes:

- borg recreate:

  - remove special-cased --dry-run
  - update --help
  - remove bloat: interruption blah, autocommit blah, resuming blah
  - re-use existing checkpoint functionality
  - archiver tests: add check_cache tool - lints refcounts

- fixed cache sync performance regression from 1.1.0b1 onwards, #1940
- syncing the cache without chunks.archive.d (see :ref:`disable_archive_chunks`)
  now avoids any merges and is thus faster, #1940
- borg check --verify-data: faster due to linear on-disk-order scan
- borg debug-xxx commands removed, we use "debug xxx" subcommands now, #1627
- improve metadata handling speed
- shortcut hashindex_set by having hashindex_lookup hint about address
- improve / add progress displays, #1721
- check for index vs. segment files object count mismatch
- make RPC protocol more extensible: use named parameters.
- RemoteRepository: misc. code cleanups / refactors
- clarify cache/repository README file

- docs:

  - quickstart: add a comment about other (remote) filesystems
  - quickstart: only give one possible ssh url syntax, all others are
    documented in usage chapter.
  - mention file://
  - document repo URLs / archive location
  - clarify borg diff help, #980
  - deployment: synthesize alternative --restrict-to-path example
  - improve cache / index docs, esp. files cache docs, #1825
  - document using "git merge 1.0-maint -s recursive -X rename-threshold=20%"
    for avoiding troubles when merging the 1.0-maint branch into master.

- tests:

  - FUSE tests: catch ENOTSUP on freebsd
  - FUSE tests: test troublesome xattrs last
  - fix byte range error in test, #1740
  - use monkeypatch to set env vars, but only on pytest based tests.
  - point XDG_*_HOME to temp dirs for tests, #1714
  - remove all BORG_* env vars from the outer environment


Version 1.1.0b2 (2016-10-01)
----------------------------

Bug fixes:

- fix incorrect preservation of delete tags, leading to "object count mismatch"
  on borg check, #1598. This only occurred with 1.1.0b1 (not with 1.0.x) and is
  normally fixed by running another borg create/delete/prune.
- fix broken --progress for double-cell paths (e.g. CJK), #1624
- borg recreate: also catch SIGHUP
- FUSE:

  - fix hardlinks in versions view, #1599
  - add parameter check to ItemCache.get to make potential failures more clear

New features:

- Archiver, RemoteRepository: add --remote-ratelimit (send data)
- borg help compression, #1582
- borg check: delete chunks with integrity errors, #1575, so they can be
  "repaired" immediately and maybe healed later.
- archives filters concept (refactoring/unifying older code)

  - covers --first/--last/--prefix/--sort-by options
  - currently used for borg list/info/delete

Other changes:

- borg check --verify-data slightly tuned (use get_many())
- change {utcnow} and {now} to ISO-8601 format ("T" date/time separator)
- repo check: log transaction IDs, improve object count mismatch diagnostic
- Vagrantfile: use TW's fresh-bootloader pyinstaller branch
- fix module names in api.rst
- hashindex: bump api_version


Version 1.1.0b1 (2016-08-28)
----------------------------

New features:

- new commands:

  - borg recreate: re-create existing archives, #787 #686 #630 #70, also see
    #757, #770.

    - selectively remove files/dirs from old archives
    - re-compress data
    - re-chunkify data, e.g. to have upgraded Attic / Borg 0.xx archives
      deduplicate with Borg 1.x archives or to experiment with chunker-params.
  - borg diff: show differences between archives
  - borg with-lock: execute a command with the repository locked, #990
- borg create:

  - Flexible compression with pattern matching on path/filename,
    and LZ4 heuristic for deciding compressibility, #810, #1007
  - visit files in inode order (better speed, esp. for large directories and rotating disks)
  - in-file checkpoints, #1217
  - increased default checkpoint interval to 30 minutes (was 5 minutes), #896
  - added uuid archive format tag, #1151
  - save mountpoint directories with --one-file-system, makes system restore easier, #1033
  - Linux: added support for some BSD flags, #1050
  - add 'x' status for excluded paths, #814

    - also means files excluded via UF_NODUMP, #1080
- borg check:

  - will not produce the "Checking segments" output unless new --progress option is passed, #824.
  - --verify-data to verify data cryptographically on the client, #975
- borg list, #751, #1179

  - removed {formatkeys}, see "borg list --help"
  - --list-format is deprecated, use --format instead
  - --format now also applies to listing archives, not only archive contents, #1179
  - now supports the usual [PATH [PATHS…]] syntax and excludes
  - new keys: csize, num_chunks, unique_chunks, NUL
  - supports guaranteed_available hashlib hashes
    (to avoid varying functionality depending on environment),
    which includes the SHA1 and SHA2 family as well as MD5
- borg prune:

  - to better visualize the "thinning out", we now list all archives in
    reverse time order. rephrase and reorder help text.
  - implement --keep-last N via --keep-secondly N, also --keep-minutely.
    assuming that there is not more than 1 backup archive made in 1s,
    --keep-last N and --keep-secondly N are equivalent, #537
  - cleanup checkpoints except the latest, #1008
- borg extract:

  - added --progress, #1449
  - Linux: limited support for BSD flags, #1050
- borg info:

  - output is now more similar to borg create --stats, #977
- borg mount:

  - provide "borgfs" wrapper for borg mount, enables usage via fstab, #743
  - "versions" mount option - when used with a repository mount, this gives
    a merged, versioned view of the files in all archives, #729
- repository:

  - added progress information to commit/compaction phase (often takes some time when deleting/pruning), #1519
  - automatic recovery for some forms of repository inconsistency, #858
  - check free space before going forward with a commit, #1336
  - improved write performance (esp. for rotating media), #985

    - new IO code for Linux
    - raised default segment size to approx 512 MiB
  - improved compaction performance, #1041
  - reduced client CPU load and improved performance for remote repositories, #940

- options that imply output (--show-rc, --show-version, --list, --stats,
  --progress) don't need -v/--info to have that output displayed, #865
- add archive comments (via borg (re)create --comment), #842
- borg list/prune/delete: also output archive id, #731
- --show-version: shows/logs the borg version, #725
- added --debug-topic for granular debug logging, #1447
- use atomic file writing/updating for configuration and key files, #1377
- BORG_KEY_FILE environment variable, #1001
- self-testing module, #970


Bug fixes:

- list: fixed default output being produced if --format is given with empty parameter, #1489
- create: fixed overflowing progress line with CJK and similar characters, #1051
- prune: fixed crash if --prefix resulted in no matches, #1029
- init: clean up partial repo if passphrase input is aborted, #850
- info: quote cmdline arguments that have spaces in them
- fix hardlinks failing in some cases for extracting subtrees, #761

Other changes:

- replace stdlib hmac with OpenSSL, zero-copy decrypt (10-15% increase in
  performance of hash-lists and extract).
- improved chunker performance, #1021
- open repository segment files in exclusive mode (fail-safe), #1134
- improved error logging, #1440
- Source:

  - pass meta-data around, #765
  - move some constants to new constants module
  - better readability and fewer errors with namedtuples, #823
  - moved source tree into src/ subdirectory, #1016
  - made borg.platform a package, #1113
  - removed dead crypto code, #1032
  - improved and ported parts of the test suite to py.test, #912
  - created data classes instead of passing dictionaries around, #981, #1158, #1161
  - cleaned up imports, #1112
- Docs:

  - better help texts and sphinx reproduction of usage help:

    - Group options
    - Nicer list of options in Sphinx
    - Deduplicate 'Common options' (including --help)
  - chunker: added some insights by "Voltara", #903
  - clarify what "deduplicated size" means
  - fix / update / add package list entries
  - added a SaltStack usage example, #956
  - expanded FAQ
  - new contributors in AUTHORS!
- Tests:

  - vagrant: add ubuntu/xenial 64bit - this box has still some issues
  - ChunkBuffer: add test for leaving partial chunk in buffer, fixes #945


Version 1.0.13 (2019-02-15)
---------------------------

Please note: this is very likely the last 1.0.x release, please upgrade to 1.1.x.

Bug fixes:

- security fix: configure FUSE with "default_permissions", #3903.
  "default_permissions" is now enforced by borg by default to let the
  kernel check uid/gid/mode based permissions.
  "ignore_permissions" can be given to not enforce "default_permissions".
- xattrs: fix borg exception handling on ENOSPC error, #3808.

New features:

- Read a passphrase from a file descriptor specified in the
  BORG_PASSPHRASE_FD environment variable.

Other changes:

- acl platform code: fix acl set return type
- xattr:

  - add linux {list,get,set}xattr ctypes prototypes
  - fix darwin flistxattr ctypes prototype
- testing / travis-ci:

  - fix the homebrew 1.9 issues on travis-ci, #4254
  - travis OS X: use xcode 8.3 (not broken)
  - tox.ini: lock requirements
  - unbreak 1.0-maint on travis, fixes #4123
- vagrant:

  - misc. fixes
  - FUSE for macOS: upgrade 3.7.1 to 3.8.3
  - Python: upgrade 3.5.5 to 3.5.6
- docs:

  - Update installation instructions for macOS
  - update release workflow using twine (docs, scripts), #4213

Version 1.0.12 (2018-04-08)
---------------------------

Bug fixes:

- repository: cleanup/write: invalidate cached FDs, tests
- serve: fix exitcode, #2910
- extract: set bsdflags last (include immutable flag), #3263
- create --timestamp: set start time, #2957
- create: show excluded dir with "x" for tagged dirs / caches, #3189
- migrate locks to child PID when daemonize is used
- Buffer: fix wrong thread-local storage use, #2951
- fix detection of non-local path, #3108
- fix LDLP restoration for subprocesses, #3077
- fix subprocess environments (xattr module's fakeroot version check,
  borg umount, BORG_PASSCOMMAND), #3050
- remote: deal with partial lines, #2637
- get rid of datetime.isoformat, use safe parse_timestamp to parse
  timestamps, #2994
- build: do .h file content checks in binary mode, fixes build issue for
  non-ascii header files on pure-ascii locale platforms, #3544 #3639
- remove platform.uname() call which caused library mismatch issues, #3732
- add exception handler around deprecated platform.linux_distribution() call

Other changes:

- require msgpack-python >= 0.4.6 and < 0.5.0, see #3753
- add parens for C preprocessor macro argument usages (did not cause
  malfunction)
- ignore corrupt files cache, #2939
- replace "modulo" with "if" to check for wraparound in hashmap
- keymanager: don't depend on optional readline module, #2980
- exclude broken pytest 3.3.0 release
- exclude broken Cython 0.27(.0) release, #3066
- flake8: add some ignores
- docs:

  - create: document exclusion through nodump
  - document good and problematic option placements, fix examples, #3356
  - update docs about hardlinked symlinks limitation
  - faq: we do not implement futile attempts of ETA / progress displays
  - simplified rate limiting wrapper in FAQ
  - twitter account @borgbackup, #2948
  - add note about metadata dedup and --no[ac]time, #2518
  - change-passphrase only changes the passphrase, #2990
  - clarify encrypted key format for borg key export, #3296
  - document sshfs rename workaround, #3315
  - update release checklist about security fixes
  - docs about how to verify a signed release, #3634
  - chunk seed is generated per /repository/
- vagrant:

  - use FUSE for macOS 3.7.1 to build the macOS binary
  - use python 3.5.5 to build the binaries
  - add exe location to PATH when we build an exe
  - use https pypi url for wheezy
  - netbsd: bash is already installed
  - netbsd: fix netbsd version in PKG_PATH
  - use self-made FreeBSD 10.3 box, #3022
  - backport fs_init (including related updates) from 1.1
  - the boxcutter wheezy boxes are 404, use local ones
- travis:

  - don't perform full Travis build on docs-only changes, #2531
  - only short-circuit docs-only changes for pull requests


Version 1.0.11 (2017-07-21)
---------------------------

Bug fixes:

- use limited unpacker for outer key (security precaution), #2174
- fix paperkey import bug

Other changes:

- change --checkpoint-interval default from 600s to 1800s, #2841.
  this improves efficiency for big repositories a lot.
- docs: fix OpenSUSE command and add OpenSUSE section
- tests: add tests for split_lstring and paperkey
- vagrant:

  - fix openbsd shell
  - backport cpu/ram setup from master
  - add stretch64 VM

Version 1.0.11rc1 (2017-06-27)
------------------------------

Bug fixes:

- performance: rebuild hashtable if we have too few empty buckets, #2246.
  this fixes some sporadic, but severe performance breakdowns.
- Archive: allocate zeros when needed, #2308
  fixes huge memory usage of mount (8 MiB × number of archives)
- IPv6 address support
  also: Location: more informative exception when parsing fails
- borg single-file binary: use pyinstaller v3.2.1, #2396
  this fixes that the prelink cronjob on some distros kills the
  borg binary by stripping away parts of it.
- extract:

  - warning for unextracted big extended attributes, #2258
  - also create parent dir for device files, if needed.
  - don't write to disk with --stdout, #2645
- archive check: detect and fix missing all-zero replacement chunks, #2180
- fix (de)compression exceptions, #2224 #2221
- files cache: update inode number, #2226
- borg rpc: use limited msgpack.Unpacker (security precaution), #2139
- Manifest: use limited msgpack.Unpacker (security precaution), #2175
- Location: accept //servername/share/path
- fix ChunkIndex.__contains__ assertion  for big-endian archs (harmless)
- create: handle BackupOSError on a per-path level in one spot
- fix error msg, there is no --keep-last in borg 1.0.x, #2282
- clamp (nano)second values to unproblematic range, #2304
- fuse / borg mount:

  - fix st_blocks to be an integer (not float) value
  - fix negative uid/gid crash (they could come into archives e.g. when
    backing up external drives under cygwin), #2674
  - fix crash if empty (None) xattr is read
  - do pre-mount checks before opening repository
  - check llfuse is installed before asking for passphrase
- borg rename: expand placeholders, #2386
- borg serve: fix forced command lines containing BORG_* env vars
- fix error msg, it is --keep-within, not --within
- fix borg key/debug/benchmark crashing without subcommand, #2240
- chunker: fix invalid use of types, don't do uint32_t >> 32
- document follow_symlinks requirements, check libc, #2507

New features:

- added BORG_PASSCOMMAND environment variable, #2573
- add minimal version of in repository mandatory feature flags, #2134

  This should allow us to make sure older borg versions can be cleanly
  prevented from doing operations that are no longer safe because of
  repository format evolution. This allows more fine grained control than
  just incrementing the manifest version. So for example a change that
  still allows new archives to be created but would corrupt the repository
  when an old version tries to delete an archive or check the repository
  would add the new feature to the check and delete set but leave it out
  of the write set.
- borg delete --force --force to delete severely corrupted archives, #1975

Other changes:

- embrace y2038 issue to support 32bit platforms
- be more clear that this is a "beyond repair" case, #2427
- key file names: limit to 100 characters and remove colons from host name
- upgrade FUSE for macOS to 3.5.8, #2346
- split up parsing and filtering for --keep-within, better error message, #2610
- docs:

  - fix caskroom link, #2299
  - address SSH batch mode, #2202 #2270
  - improve remote-path description
  - document snapshot usage, #2178
  - document relative path usage, #1868
  - one link per distro in the installation page
  - development: new branching model in git repository
  - kill api page
  - added FAQ section about backing up root partition
  - add bountysource badge, #2558
  - create empty docs.txt reequirements, #2694
  - README: how to help the project
  - note -v/--verbose requirement on affected options, #2542
  - document borg init behaviour via append-only borg serve, #2440
  - be clear about what buzhash is used for (chunking) and want it is not
    used for (deduplication)- also say already in the readme that we use a
    cryptohash for dedupe, so people don't worry, #2390
  - add hint about chunker params to borg upgrade docs, #2421
  - clarify borg upgrade docs, #2436
  - quickstart: delete problematic BORG_PASSPHRASE use, #2623
  - faq: specify "using inline shell scripts"
  - document pattern denial of service, #2624
- tests:

  - remove attic dependency of the tests, #2505
  - travis:

    - enhance travis setuptools_scm situation
    - install fakeroot for Linux
  - add test for borg delete --force
  - enable remote tests on cygwin (the cygwin issue that caused these tests
    to break was fixed in cygwin at least since cygwin 2.8, maybe even since
    2.7.0).
  - remove skipping the noatime tests on GNU/Hurd, #2710
  - fix borg import issue, add comment, #2718
  - include attic.tar.gz when installing the package
    also: add include_package_data=True

Version 1.0.10 (2017-02-13)
---------------------------

Bug fixes:

- Manifest timestamps are now monotonically increasing,
  this fixes issues when the system clock jumps backwards
  or is set inconsistently across computers accessing the same repository, #2115
- Fixed testing regression in 1.0.10rc1 that lead to a hard dependency on
  py.test >= 3.0, #2112

New features:

- "key export" can now generate a printable HTML page with both a QR code and
  a human-readable "paperkey" representation (and custom text) through the
  ``--qr-html`` option.

  The same functionality is also available through `paperkey.html <paperkey.html>`_,
  which is the same HTML page generated by ``--qr-html``. It works with existing
  "key export" files and key files.

Other changes:

- docs:

  - language clarification - "borg create --one-file-system" option does not respect
    mount points, but considers different file systems instead, #2141
- setup.py: build_api: sort file list for determinism


Version 1.0.10rc1 (2017-01-29)
------------------------------

Bug fixes:

- borg serve: fix transmission data loss of pipe writes, #1268
  This affects only the cygwin platform (not Linux, BSD, OS X).
- Avoid triggering an ObjectiveFS bug in xattr retrieval, #1992
- When running out of buffer memory when reading xattrs, only skip the
  current file, #1993
- Fixed "borg upgrade --tam" crashing with unencrypted repositories. Since
  :ref:`the issue <tam_vuln>` is not relevant for unencrypted repositories,
  it now does nothing and prints an error, #1981.
- Fixed change-passphrase crashing with unencrypted repositories, #1978
- Fixed "borg check repo::archive" indicating success if "archive" does not exist, #1997
- borg check: print non-exit-code warning if --last or --prefix aren't fulfilled
- fix bad parsing of wrong repo location syntax
- create: don't create hard link refs to failed files,
  mount: handle invalid hard link refs, #2092
- detect mingw byte order, #2073
- creating a new segment: use "xb" mode, #2099
- mount: umount on SIGINT/^C when in foreground, #2082

Other changes:

- binary: use fixed AND freshly compiled pyinstaller bootloader, #2002
- xattr: ignore empty names returned by llistxattr(2) et al
- Enable the fault handler: install handlers for the SIGSEGV, SIGFPE, SIGABRT,
  SIGBUS and SIGILL signals to dump the Python traceback.
- Also print a traceback on SIGUSR2.
- borg change-passphrase: print key location (simplify making a backup of it)
- officially support Python 3.6 (setup.py: add Python 3.6 qualifier)
- tests:

  - vagrant / travis / tox: add Python 3.6 based testing
  - vagrant: fix openbsd repo, #2042
  - vagrant: fix the freebsd64 machine, #2037 #2067
  - vagrant: use python 3.5.3 to build binaries, #2078
  - vagrant: use osxfuse 3.5.4 for tests / to build binaries
    vagrant: improve darwin64 VM settings
  - travis: fix osxfuse install (fixes OS X testing on Travis CI)
  - travis: require succeeding OS X tests, #2028
  - travis: use latest pythons for OS X based testing
  - use pytest-xdist to parallelize testing
  - fix xattr test race condition, #2047
  - setup.cfg: fix pytest deprecation warning, #2050
- docs:

  - language clarification - VM backup FAQ
  - borg create: document how to backup stdin, #2013
  - borg upgrade: fix incorrect title levels
  - add CVE numbers for issues fixed in 1.0.9, #2106
- fix typos (taken from Debian package patch)
- remote: include data hexdump in "unexpected RPC data" error message
- remote: log SSH command line at debug level
- API_VERSION: use numberspaces, #2023
- remove .github from pypi package, #2051
- add pip and setuptools to requirements file, #2030
- SyncFile: fix use of fd object after close (cosmetic)
- Manifest.in: simplify, exclude \*.{so,dll,orig}, #2066
- ignore posix_fadvise errors in repository.py, #2095
  (works around issues with docker on ARM)
- make LoggedIO.close_segment reentrant, avoid reentrance


Version 1.0.9 (2016-12-20)
--------------------------

Security fixes:

- A flaw in the cryptographic authentication scheme in Borg allowed an attacker
  to spoof the manifest. See :ref:`tam_vuln` above for the steps you should
  take.

  CVE-2016-10099 was assigned to this vulnerability.
- borg check: When rebuilding the manifest (which should only be needed very rarely)
  duplicate archive names would be handled on a "first come first serve" basis, allowing
  an attacker to apparently replace archives.

  CVE-2016-10100 was assigned to this vulnerability.

Bug fixes:

- borg check:

  - rebuild manifest if it's corrupted
  - skip corrupted chunks during manifest rebuild
- fix TypeError in integrity error handler, #1903, #1894
- fix location parser for archives with @ char (regression introduced in 1.0.8), #1930
- fix wrong duration/timestamps if system clock jumped during a create
- fix progress display not updating if system clock jumps backwards
- fix checkpoint interval being incorrect if system clock jumps

Other changes:

- docs:

  - add python3-devel as a dependency for cygwin-based installation
  - clarify extract is relative to current directory
  - FAQ: fix link to changelog
  - markup fixes
- tests:

  - test_get\_(cache|keys)_dir: clean env state, #1897
  - get back pytest's pretty assertion failures, #1938
- setup.py build_usage:

  - fixed build_usage not processing all commands
  - fixed build_usage not generating includes for debug commands


Version 1.0.9rc1 (2016-11-27)
-----------------------------

Bug fixes:

- files cache: fix determination of newest mtime in backup set (which is
  used in cache cleanup and led to wrong "A" [added] status for unchanged
  files in next backup), #1860.

- borg check:

  - fix incorrectly reporting attic 0.13 and earlier archives as corrupt
  - handle repo w/o objects gracefully and also bail out early if repo is
    *completely* empty, #1815.
- fix tox/pybuild in 1.0-maint
- at xattr module import time, loggers are not initialized yet

New features:

- borg umount <mountpoint>
  exposed already existing umount code via the CLI api, so users can use it,
  which is more consistent than using borg to mount and fusermount -u (or
  umount) to un-mount, #1855.
- implement borg create --noatime --noctime, fixes #1853

Other changes:

- docs:

  - display README correctly on PyPI
  - improve cache / index docs, esp. files cache docs, fixes #1825
  - different pattern matching for --exclude, #1779
  - datetime formatting examples for {now} placeholder, #1822
  - clarify passphrase mode attic repo upgrade, #1854
  - clarify --umask usage, #1859
  - clarify how to choose PR target branch
  - clarify prune behavior for different archive contents, #1824
  - fix PDF issues, add logo, fix authors, headings, TOC
  - move security verification to support section
  - fix links in standalone README (:ref: tags)
  - add link to security contact in README
  - add FAQ about security
  - move fork differences to FAQ
  - add more details about resource usage
- tests: skip remote tests on cygwin, #1268
- travis:

  - allow OS X failures until the brew cask osxfuse issue is fixed
  - caskroom osxfuse-beta gone, it's osxfuse now (3.5.3)
- vagrant:

  - upgrade OSXfuse / FUSE for macOS to 3.5.3
  - remove llfuse from tox.ini at a central place
  - do not try to install llfuse on centos6
  - fix FUSE test for darwin, #1546
  - add windows virtual machine with cygwin
  - Vagrantfile cleanup / code deduplication


Version 1.0.8 (2016-10-29)
--------------------------

Bug fixes:

- RemoteRepository: Fix busy wait in call_many, #940

New features:

- implement borgmajor/borgminor/borgpatch placeholders, #1694
  {borgversion} was already there (full version string). With the new
  placeholders you can now also get e.g. 1 or 1.0 or 1.0.8.

Other changes:

- avoid previous_location mismatch, #1741

  due to the changed canonicalization for relative paths in PR #1711 / #1655
  (implement /./ relpath hack), there would be a changed repo location warning
  and the user would be asked if this is ok. this would break automation and
  require manual intervention, which is unwanted.

  thus, we automatically fix the previous_location config entry, if it only
  changed in the expected way, but still means the same location.

- docs:

  - deployment.rst: do not use bare variables in ansible snippet
  - add clarification about append-only mode, #1689
  - setup.py: add comment about requiring llfuse, #1726
  - update usage.rst / api.rst
  - repo url / archive location docs + typo fix
  - quickstart: add a comment about other (remote) filesystems

- vagrant / tests:

  - no chown when rsyncing (fixes boxes w/o vagrant group)
  - fix FUSE permission issues on linux/freebsd, #1544
  - skip FUSE test for borg binary + fakeroot
  - ignore security.selinux xattrs, fixes tests on centos, #1735


Version 1.0.8rc1 (2016-10-17)
-----------------------------

Bug fixes:

- fix signal handling (SIGINT, SIGTERM, SIGHUP), #1620 #1593
  Fixes e.g. leftover lock files for quickly repeated signals (e.g. Ctrl-C
  Ctrl-C) or lost connections or systemd sending SIGHUP.
- progress display: adapt formatting to narrow screens, do not crash, #1628
- borg create --read-special - fix crash on broken symlink, #1584.
  also correctly processes broken symlinks. before this regressed to a crash
  (5b45385) a broken symlink would've been skipped.
- process_symlink: fix missing backup_io()
  Fixes a chmod/chown/chgrp/unlink/rename/... crash race between getting
  dirents and dispatching to process_symlink.
- yes(): abort on wrong answers, saying so, #1622
- fixed exception borg serve raised when connection was closed before repository
  was opened. Add an error message for this.
- fix read-from-closed-FD issue, #1551
  (this seems not to get triggered in 1.0.x, but was discovered in master)
- hashindex: fix iterators (always raise StopIteration when exhausted)
  (this seems not to get triggered in 1.0.x, but was discovered in master)
- enable relative paths in ssh:// repo URLs, via /./relpath hack, #1655
- allow repo paths with colons, #1705
- update changed repo location immediately after acceptance, #1524
- fix debug get-obj / delete-obj crash if object not found and remote repo,
  #1684
- pyinstaller: use a spec file to build borg.exe binary, exclude osxfuse dylib
  on Mac OS X (avoids mismatch lib <-> driver), #1619

New features:

- add "borg key export" / "borg key import" commands, #1555, so users are able
  to backup / restore their encryption keys more easily.

  Supported formats are the keyfile format used by borg internally and a
  special "paper" format with by line checksums for printed backups. For the
  paper format, the import is an interactive process which checks each line as
  soon as it is input.
- add "borg debug-refcount-obj" to determine a repo objects' referrer counts,
  #1352

Other changes:

- add "borg debug ..." subcommands
  (borg debug-* still works, but will be removed in borg 1.1)
- setup.py: Add subcommand support to build_usage.
- remote: change exception message for unexpected RPC data format to indicate
  dataflow direction.
- improved messages / error reporting:

  - IntegrityError: add placeholder for message, so that the message we give
    appears not only in the traceback, but also in the (short) error message,
    #1572
  - borg.key: include chunk id in exception msgs, #1571
  - better messages for cache newer than repo, #1700
- vagrant (testing/build VMs):

  - upgrade OSXfuse / FUSE for macOS to 3.5.2
  - update Debian Wheezy boxes, #1686
  - openbsd / netbsd: use own boxes, fixes misc rsync installation and
    FUSE/llfuse related testing issues, #1695 #1696 #1670 #1671 #1728
- docs:

  - add docs for "key export" and "key import" commands, #1641
  - fix inconsistency in FAQ (pv-wrapper).
  - fix second block in "Easy to use" section not showing on GitHub, #1576
  - add bestpractices badge
  - link reference docs and faq about BORG_FILES_CACHE_TTL, #1561
  - improve borg info --help, explain size infos, #1532
  - add release signing key / security contact to README, #1560
  - add contribution guidelines for developers
  - development.rst: add sphinx_rtd_theme to the sphinx install command
  - adjust border color in borg.css
  - add debug-info usage help file
  - internals.rst: fix typos
  - setup.py: fix build_usage to always process all commands
  - added docs explaining multiple --restrict-to-path flags, #1602
  - add more specific warning about write-access debug commands, #1587
  - clarify FAQ regarding backup of virtual machines, #1672
- tests:

  - work around FUSE xattr test issue with recent fakeroot
  - simplify repo/hashindex tests
  - travis: test FUSE-enabled borg, use trusty to have a recent FUSE
  - re-enable FUSE tests for RemoteArchiver (no deadlocks any more)
  - clean env for pytest based tests, #1714
  - fuse_mount contextmanager: accept any options


Version 1.0.7 (2016-08-19)
--------------------------

Security fixes:

- borg serve: fix security issue with remote repository access, #1428
  If you used e.g. --restrict-to-path /path/client1/ (with or without trailing
  slash does not make a difference), it acted like a path prefix match using
  /path/client1 (note the missing trailing slash) - the code then also allowed
  working in e.g. /path/client13 or /path/client1000.

  As this could accidentally lead to major security/privacy issues depending on
  the paths you use, the behaviour was changed to be a strict directory match.
  That means --restrict-to-path /path/client1 (with or without trailing slash
  does not make a difference) now uses /path/client1/ internally (note the
  trailing slash here!) for matching and allows precisely that path AND any
  path below it. So, /path/client1 is allowed, /path/client1/repo1 is allowed,
  but not /path/client13 or /path/client1000.

  If you willingly used the undocumented (dangerous) previous behaviour, you
  may need to rearrange your --restrict-to-path paths now. We are sorry if
  that causes work for you, but we did not want a potentially dangerous
  behaviour in the software (not even using a for-backwards-compat option).

Bug fixes:

- fixed repeated LockTimeout exceptions when borg serve tried to write into
  a already write-locked repo (e.g. by a borg mount), #502 part b)
  This was solved by the fix for #1220 in 1.0.7rc1 already.
- fix cosmetics + file leftover for "not a valid borg repository", #1490
- Cache: release lock if cache is invalid, #1501
- borg extract --strip-components: fix leak of preloaded chunk contents
- Repository, when a InvalidRepository exception happens:

  - fix spurious, empty lock.roster
  - fix repo not closed cleanly

New features:

- implement borg debug-info, fixes #1122
  (just calls already existing code via cli, same output as below tracebacks)

Other changes:

- skip the O_NOATIME test on GNU Hurd, fixes #1315
  (this is a very minor issue and the GNU Hurd project knows the bug)
- document using a clean repo to test / build the release


Version 1.0.7rc2 (2016-08-13)
-----------------------------

Bug fixes:

- do not write objects to repository that are bigger than the allowed size,
  borg will reject reading them, #1451.

  Important: if you created archives with many millions of files or
  directories, please verify if you can open them successfully,
  e.g. try a "borg list REPO::ARCHIVE".
- lz4 compression: dynamically enlarge the (de)compression buffer, the static
  buffer was not big enough for archives with extremely many items, #1453
- larger item metadata stream chunks, raise archive item limit by 8x, #1452
- fix untracked segments made by moved DELETEs, #1442

  Impact: Previously (metadata) segments could become untracked when deleting data,
  these would never be cleaned up.
- extended attributes (xattrs) related fixes:

  - fixed a race condition in xattrs querying that led to the entire file not
    being backed up (while logging the error, exit code = 1), #1469
  - fixed a race condition in xattrs querying that led to a crash, #1462
  - raise OSError including the error message derived from errno, deal with
    path being a integer FD

Other changes:

- print active env var override by default, #1467
- xattr module: refactor code, deduplicate, clean up
- repository: split object size check into too small and too big
- add a transaction_id assertion, so borg init on a broken (inconsistent)
  filesystem does not look like a coding error in borg, but points to the
  real problem.
- explain confusing TypeError caused by compat support for old servers, #1456
- add forgotten usage help file from build_usage
- refactor/unify buffer code into helpers.Buffer class, add tests
- docs:

  - document archive limitation, #1452
  - improve prune examples


Version 1.0.7rc1 (2016-08-05)
-----------------------------

Bug fixes:

- fix repo lock deadlocks (related to lock upgrade), #1220
- catch unpacker exceptions, resync, #1351
- fix borg break-lock ignoring BORG_REPO env var, #1324
- files cache performance fixes (fixes unnecessary re-reading/chunking/
  hashing of unmodified files for some use cases):

  - fix unintended file cache eviction, #1430
  - implement BORG_FILES_CACHE_TTL, update FAQ, raise default TTL from 10
    to 20, #1338
- FUSE:

  - cache partially read data chunks (performance), #965, #966
  - always create a root dir, #1125
- use an OrderedDict for helptext, making the build reproducible, #1346
- RemoteRepository init: always call close on exceptions, #1370 (cosmetic)
- ignore stdout/stderr broken pipe errors (cosmetic), #1116

New features:

- better borg versions management support (useful esp. for borg servers
  wanting to offer multiple borg versions and for clients wanting to choose
  a specific server borg version), #1392:

  - add BORG_VERSION environment variable before executing "borg serve" via ssh
  - add new placeholder {borgversion}
  - substitute placeholders in --remote-path

- borg init --append-only option (makes using the more secure append-only mode
  more convenient. when used remotely, this requires 1.0.7+ also on the borg
  server), #1291.

Other changes:

- Vagrantfile:

  - darwin64: upgrade to FUSE for macOS 3.4.1 (aka osxfuse), #1378
  - xenial64: use user "ubuntu", not "vagrant" (as usual), #1331
- tests:

  - fix FUSE tests on OS X, #1433
- docs:

  - FAQ: add backup using stable filesystem names recommendation
  - FAQ about glibc compatibility added, #491, glibc-check improved
  - FAQ: 'A' unchanged file; remove ambiguous entry age sentence.
  - OS X: install pkg-config to build with FUSE support, fixes #1400
  - add notes about shell/sudo pitfalls with env. vars, #1380
  - added platform feature matrix
- implement borg debug-dump-repo-objs


Version 1.0.6 (2016-07-12)
--------------------------

Bug fixes:

- Linux: handle multiple LD_PRELOAD entries correctly, #1314, #1111
- Fix crash with unclear message if the libc is not found, #1314, #1111

Other changes:

- tests:

  - Fixed O_NOATIME tests for Solaris and GNU Hurd, #1315
  - Fixed sparse file tests for (file) systems not supporting it, #1310
- docs:

  - Fixed syntax highlighting, #1313
  - misc docs: added data processing overview picture


Version 1.0.6rc1 (2016-07-10)
-----------------------------

New features:

- borg check --repair: heal damaged files if missing chunks re-appear (e.g. if
  the previously missing chunk was added again in a later backup archive),
  #148. (*) Also improved logging.

Bug fixes:

- sync_dir: silence fsync() failing with EINVAL, #1287
  Some network filesystems (like smbfs) don't support this and we use this in
  repository code.
- borg mount (FUSE):

  - fix directories being shadowed when contained paths were also specified,
    #1295
  - raise I/O Error (EIO) on damaged files (unless -o allow_damaged_files is
    used), #1302. (*)
- borg extract: warn if a damaged file is extracted, #1299. (*)
- Added some missing return code checks (ChunkIndex._add, hashindex_resize).
- borg check: fix/optimize initial hash table size, avoids resize of the table.

Other changes:

- tests:

  - add more FUSE tests, #1284
  - deduplicate FUSE (u)mount code
  - fix borg binary test issues, #862
- docs:

  - changelog: added release dates to older borg releases
  - fix some sphinx (docs generator) warnings, #881

Notes:

(*) Some features depend on information (chunks_healthy list) added to item
metadata when a file with missing chunks was "repaired" using all-zero
replacement chunks. The chunks_healthy list is generated since borg 1.0.4,
thus borg can't recognize such "repaired" (but content-damaged) files if the
repair was done with an older borg version.


Version 1.0.5 (2016-07-07)
--------------------------

Bug fixes:

- borg mount: fix FUSE crash in xattr code on Linux introduced in 1.0.4, #1282

Other changes:

- backport some FAQ entries from master branch
- add release helper scripts
- Vagrantfile:

  - centos6: no FUSE, don't build binary
  - add xz for redhat-like dists


Version 1.0.4 (2016-07-07)
--------------------------

New features:

- borg serve --append-only, #1168
  This was included because it was a simple change (append-only functionality
  was already present via repository config file) and makes better security now
  practically usable.
- BORG_REMOTE_PATH environment variable, #1258
  This was included because it was a simple change (--remote-path cli option
  was already present) and makes borg much easier to use if you need it.
- Repository: cleanup incomplete transaction on "no space left" condition.
  In many cases, this can avoid a 100% full repo filesystem (which is very
  problematic as borg always needs free space - even to delete archives).

Bug fixes:

- Fix wrong handling and reporting of OSErrors in borg create, #1138.
  This was a serious issue: in the context of "borg create", errors like
  repository I/O errors (e.g. disk I/O errors, ssh repo connection errors)
  were handled badly and did not lead to a crash (which would be good for this
  case, because the repo transaction would be incomplete and trigger a
  transaction rollback to clean up).
  Now, error handling for source files is cleanly separated from every other
  error handling, so only problematic input files are logged and skipped.
- Implement fail-safe error handling for borg extract.
  Note that this isn't nearly as critical as the borg create error handling
  bug, since nothing is written to the repo. So this was "merely" misleading
  error reporting.
- Add missing error handler in directory attr restore loop.
- repo: make sure write data hits disk before the commit tag (#1236) and also
  sync the containing directory.
- FUSE: getxattr fail must use errno.ENOATTR, #1126
  (fixes Mac OS X Finder malfunction: "zero bytes" file length, access denied)
- borg check --repair: do not lose information about the good/original chunks.
  If we do not lose the original chunk IDs list when "repairing" a file
  (replacing missing chunks with all-zero chunks), we have a chance to "heal"
  the file back into its original state later, in case the chunks re-appear
  (e.g. in a fresh backup). Healing is not implemented yet, see #148.
- fixes for --read-special mode:

  - ignore known files cache, #1241
  - fake regular file mode, #1214
  - improve symlinks handling, #1215
- remove passphrase from subprocess environment, #1105
- Ignore empty index file (will trigger index rebuild), #1195
- add missing placeholder support for --prefix, #1027
- improve exception handling for placeholder replacement
- catch and format exceptions in arg parsing
- helpers: fix "undefined name 'e'" in exception handler
- better error handling for missing repo manifest, #1043
- borg delete:

  - make it possible to delete a repo without manifest
  - borg delete --forced allows one to delete corrupted archives, #1139
- borg check:

  - make borg check work for empty repo
  - fix resync and msgpacked item qualifier, #1135
  - rebuild_manifest: fix crash if 'name' or 'time' key were missing.
  - better validation of item metadata dicts, #1130
  - better validation of archive metadata dicts
- close the repo on exit - even if rollback did not work, #1197.
  This is rather cosmetic, it avoids repo closing in the destructor.

- tests:

  - fix sparse file test, #1170
  - flake8: ignore new F405, #1185
  - catch "invalid argument" on cygwin, #257
  - fix sparseness assertion in test prep, #1264

Other changes:

- make borg build/work on OpenSSL 1.0 and 1.1, #1187
- docs / help:

  - fix / clarify prune help, #1143
  - fix "patterns" help formatting
  - add missing docs / help about placeholders
  - resources: rename atticmatic to borgmatic
  - document sshd settings, #545
  - more details about checkpoints, add split trick, #1171
  - support docs: add freenode web chat link, #1175
  - add prune visualization / example, #723
  - add note that Fnmatch is default, #1247
  - make clear that lzma levels > 6 are a waste of cpu cycles
  - add a "do not edit" note to auto-generated files, #1250
  - update cygwin installation docs
- repository interoperability with borg master (1.1dev) branch:

  - borg check: read item metadata keys from manifest, #1147
  - read v2 hints files, #1235
  - fix hints file "unknown version" error handling bug
- tests: add tests for format_line
- llfuse: update version requirement for freebsd
- Vagrantfile:

  - use openbsd 5.9, #716
  - do not install llfuse on netbsd (broken)
  - update OSXfuse to version 3.3.3
  - use Python 3.5.2 to build the binaries
- glibc compatibility checker: scripts/glibc_check.py
- add .eggs to .gitignore


Version 1.0.3 (2016-05-20)
--------------------------

Bug fixes:

- prune: avoid that checkpoints are kept and completed archives are deleted in
  a prune run), #997
- prune: fix commandline argument validation - some valid command lines were
  considered invalid (annoying, but harmless), #942
- fix capabilities extraction on Linux (set xattrs last, after chown()), #1069
- repository: fix commit tags being seen in data
- when probing key files, do binary reads. avoids crash when non-borg binary
  files are located in borg's key files directory.
- handle SIGTERM and make a clean exit - avoids orphan lock files.
- repository cache: don't cache large objects (avoid using lots of temp. disk
  space), #1063

Other changes:

- Vagrantfile: OS X: update osxfuse / install lzma package, #933
- setup.py: add check for platform_darwin.c
- setup.py: on freebsd, use a llfuse release that builds ok
- docs / help:

  - update readthedocs URLs, #991
  - add missing docs for "borg break-lock", #992
  - borg create help: add some words to about the archive name
  - borg create help: document format tags, #894


Version 1.0.2 (2016-04-16)
--------------------------

Bug fixes:

- fix malfunction and potential corruption on (nowadays rather rare) big-endian
  architectures or bi-endian archs in (rare) BE mode. #886, #889

  cache resync / index merge was malfunctioning due to this, potentially
  leading to data loss. borg info had cosmetic issues (displayed wrong values).

  note: all (widespread) little-endian archs (like x86/x64) or bi-endian archs
  in (widespread) LE mode (like ARMEL, MIPSEL, ...) were NOT affected.
- add overflow and range checks for 1st (special) uint32 of the hashindex
  values, switch from int32 to uint32.
- fix so that refcount will never overflow, but just stick to max. value after
  a overflow would have occurred.
- borg delete: fix --cache-only for broken caches, #874

  Makes --cache-only idempotent: it won't fail if the cache is already deleted.
- fixed borg create --one-file-system erroneously traversing into other
  filesystems (if starting fs device number was 0), #873
- workaround a bug in Linux fadvise FADV_DONTNEED, #907

Other changes:

- better test coverage for hashindex, incl. overflow testing, checking correct
  computations so endianness issues would be discovered.
- reproducible doc for ProgressIndicator*,  make the build reproducible.
- use latest llfuse for vagrant machines
- docs:

  - use /path/to/repo in examples, fixes #901
  - fix confusing usage of "repo" as archive name (use "arch")


Version 1.0.1 (2016-04-08)
--------------------------

New features:

Usually there are no new features in a bugfix release, but these were added
due to their high impact on security/safety/speed or because they are fixes
also:

- append-only mode for repositories, #809, #36 (see docs)
- borg create: add --ignore-inode option to make borg detect unmodified files
  even if your filesystem does not have stable inode numbers (like sshfs and
  possibly CIFS).
- add options --warning, --error, --critical for missing log levels, #826.
  it's not recommended to suppress warnings or errors, but the user may decide
  this on his own.
  note: --warning is not given to borg serve so a <= 1.0.0 borg will still
  work as server (it is not needed as it is the default).
  do not use --error or --critical when using a <= 1.0.0 borg server.

Bug fixes:

- fix silently skipping EIO, #748
- add context manager for Repository (avoid orphan repository locks), #285
- do not sleep for >60s while waiting for lock, #773
- unpack file stats before passing to FUSE
- fix build on illumos
- don't try to backup doors or event ports (Solaris and derivatives)
- remove useless/misleading libc version display, #738
- test suite: reset exit code of persistent archiver, #844
- RemoteRepository: clean up pipe if remote open() fails
- Remote: don't print tracebacks for Error exceptions handled downstream, #792
- if BORG_PASSPHRASE is present but wrong, don't prompt for password, but fail
  instead, #791
- ArchiveChecker: move "orphaned objects check skipped" to INFO log level, #826
- fix capitalization, add ellipses, change log level to debug for 2 messages,
  #798

Other changes:

- update llfuse requirement, llfuse 1.0 works
- update OS / dist packages on build machines, #717
- prefer showing --info over -v in usage help, #859
- docs:

  - fix cygwin requirements (gcc-g++)
  - document how to debug / file filesystem issues, #664
  - fix reproducible build of api docs
  - RTD theme: CSS !important overwrite, #727
  - Document logo font. Recreate logo png. Remove GIMP logo file.


Version 1.0.0 (2016-03-05)
--------------------------

The major release number change (0.x -> 1.x) indicates bigger incompatible
changes, please read the compatibility notes, adapt / test your scripts and
check your backup logs.

Compatibility notes:

- drop support for python 3.2 and 3.3, require 3.4 or 3.5, #221 #65 #490
  note: we provide binaries that include python 3.5.1 and everything else
  needed. they are an option in case you are stuck with < 3.4 otherwise.
- change encryption to be on by default (using "repokey" mode)
- moved keyfile keys from ~/.borg/keys to ~/.config/borg/keys,
  you can either move them manually or run "borg upgrade <REPO>"
- remove support for --encryption=passphrase,
  use borg migrate-to-repokey to switch to repokey mode, #97
- remove deprecated --compression <number>,
  use --compression zlib,<number> instead
  in case of 0, you could also use --compression none
- remove deprecated --hourly/daily/weekly/monthly/yearly
  use --keep-hourly/daily/weekly/monthly/yearly instead
- remove deprecated --do-not-cross-mountpoints,
  use --one-file-system instead
- disambiguate -p option, #563:

  - -p now is same as --progress
  - -P now is same as --prefix
- remove deprecated "borg verify",
  use "borg extract --dry-run" instead
- cleanup environment variable semantics, #355
  the environment variables used to be "yes sayers" when set, this was
  conceptually generalized to "automatic answerers" and they just give their
  value as answer (as if you typed in that value when being asked).
  See the "usage" / "Environment Variables" section of the docs for details.
- change the builtin default for --chunker-params, create 2MiB chunks, #343
  --chunker-params new default: 19,23,21,4095 - old default: 10,23,16,4095

  one of the biggest issues with borg < 1.0 (and also attic) was that it had a
  default target chunk size of 64kiB, thus it created a lot of chunks and thus
  also a huge chunk management overhead (high RAM and disk usage).

  please note that the new default won't change the chunks that you already
  have in your repository. the new big chunks do not deduplicate with the old
  small chunks, so expect your repo to grow at least by the size of every
  changed file and in the worst case (e.g. if your files cache was lost / is
  not used) by the size of every file (minus any compression you might use).

  in case you want to immediately see a much lower resource usage (RAM / disk)
  for chunks management, it might be better to start with a new repo than
  continuing in the existing repo (with an existing repo, you'ld have to wait
  until all archives with small chunks got pruned to see a lower resource
  usage).

  if you used the old --chunker-params default value (or if you did not use
  --chunker-params option at all) and you'ld like to continue using small
  chunks (and you accept the huge resource usage that comes with that), just
  explicitly use borg create --chunker-params=10,23,16,4095.
- archive timestamps: the 'time' timestamp now refers to archive creation
  start time (was: end time), the new 'time_end' timestamp refers to archive
  creation end time. This might affect prune if your backups take rather long.
  if you give a timestamp via cli this is stored into 'time', therefore it now
  needs to mean archive creation start time.

New features:

- implement password roundtrip, #695

Bug fixes:

- remote end does not need cache nor keys directories, do not create them, #701
- added retry counter for passwords, #703

Other changes:

- fix compiler warnings, #697
- docs:

  - update README.rst to new changelog location in docs/changes.rst
  - add Teemu to AUTHORS
  - changes.rst: fix old chunker params, #698
  - FAQ: how to limit bandwidth


Version 1.0.0rc2 (2016-02-28)
-----------------------------

New features:

- format options for location: user, pid, fqdn, hostname, now, utcnow, user
- borg list --list-format
- borg prune -v --list enables the keep/prune list output, #658

Bug fixes:

- fix _open_rb noatime handling, #657
- add a simple archivename validator, #680
- borg create --stats: show timestamps in localtime, use same labels/formatting
  as borg info, #651
- llfuse compatibility fixes (now compatible with: 0.40, 0.41, 0.42)

Other changes:

- it is now possible to use "pip install borgbackup[fuse]" to automatically
  install the llfuse dependency using the correct version requirement
  for it. you still need to care about having installed the FUSE / build
  related OS package first, though, so that building llfuse can succeed.
- Vagrant: drop Ubuntu Precise (12.04) - does not have Python >= 3.4
- Vagrant: use pyinstaller v3.1.1 to build binaries
- docs:

  - borg upgrade: add to docs that only LOCAL repos are supported
  - borg upgrade also handles borg 0.xx -> 1.0
  - use pip extras or requirements file to install llfuse
  - fix order in release process
  - updated usage docs and other minor / cosmetic fixes
  - verified borg examples in docs, #644
  - freebsd dependency installation and FUSE configuration, #649
  - add example how to restore a raw device, #671
  - add a hint about the dev headers needed when installing from source
  - add examples for delete (and handle delete after list, before prune), #656
  - update example for borg create -v --stats (use iso datetime format), #663
  - added example to BORG_RSH docs
  - "connection closed by remote": add FAQ entry and point to issue #636


Version 1.0.0rc1 (2016-02-07)
-----------------------------

New features:

- borg migrate-to-repokey ("passphrase" -> "repokey" encryption key mode)
- implement --short for borg list REPO, #611
- implement --list for borg extract (consistency with borg create)
- borg serve: overwrite client's --restrict-to-path with ssh forced command's
  option value (but keep everything else from the client commandline), #544
- use $XDG_CONFIG_HOME/keys for keyfile keys (~/.config/borg/keys), #515
- "borg upgrade" moves the keyfile keys to the new location
- display both archive creation start and end time in "borg info", #627


Bug fixes:

- normalize trailing slashes for the repository path, #606
- Cache: fix exception handling in __init__, release lock, #610

Other changes:

- suppress unneeded exception context (PEP 409), simpler tracebacks
- removed special code needed to deal with imperfections / incompatibilities /
  missing stuff in py 3.2/3.3, simplify code that can be done simpler in 3.4
- removed some version requirements that were kept on old versions because
  newer did not support py 3.2 any more
- use some py 3.4+ stdlib code instead of own/openssl/pypi code:

  - use os.urandom instead of own cython openssl RAND_bytes wrapper, #493
  - use hashlib.pbkdf2_hmac from py stdlib instead of own openssl wrapper
  - use hmac.compare_digest instead of == operator (constant time comparison)
  - use stat.filemode instead of homegrown code
  - use "mock" library from stdlib, #145
  - remove borg.support (with non-broken argparse copy), it is ok in 3.4+, #358
- Vagrant: copy CHANGES.rst as symlink, #592
- cosmetic code cleanups, add flake8 to tox/travis, #4
- docs / help:

  - make "borg -h" output prettier, #591
  - slightly rephrase prune help
  - add missing example for --list option of borg create
  - quote exclude line that includes an asterisk to prevent shell expansion
  - fix dead link to license
  - delete Ubuntu Vivid, it is not supported anymore (EOL)
  - OS X binary does not work for older OS X releases, #629
  - borg serve's special support for forced/original ssh commands, #544
  - misc. updates and fixes
