.. _important_notes:

Important notes 2.x
===================

This section provides information about security and corruption issues.

(nothing to see here yet)

.. _changelog:

Change Log 2.x
==============

Version 2.0.0b6 (not released yet)
----------------------------------

Please note:

This is a beta release, only for testing - do not use for production repos.

Compatibility notes:

- this is a major "breaking" release that is not compatible with existing repos.

  We tried to put all the necessary "breaking" changes into this release, so we
  hopefully do not need another breaking release in the near future. The changes
  were necessary for improved security, improved speed, unblocking future
  improvements, getting rid of legacy crap / design limitations, having less and
  simpler code to maintain.

  You can use "borg transfer" to transfer archives from borg 1.1/1.2 repos to
  a new borg 2.0 repo, but it will need some time and space.

- command line syntax was changed, scripts and wrappers will need changes:

  - you will usually either export BORG_REPO=<MYREPO> into your environment or
    call borg like: "borg -r <MYREPO> <COMMAND>".
    in the docs, we usually omit "-r ..." for brevity.
  - the scp-style REPO syntax was removed, please use ssh://..., #6697
  - ssh:// URLs: removed support for /~otheruser/, #6855.
    If you used this, just replace it by: ssh://user@host:port/home/otheruser/
  - -P / --prefix option was removed, please use the similar -a / --match-archives.
  - the archive name is always given separately from the repository
    (differently than with borg 1.x you must not give repo::archive).
  - the archive name is either given as a positional parameter, like:

    - borg create myarchive2 /some/path
    - borg diff myarchive1 myarchive2
  - or, if the command makes sense for an arbitrary amount of archives, archives
    can be selected using a glob pattern, like:

    - borg delete -a 'sh:myarchive*'
    - borg recreate -a 'sh:myarchive*'
  - some borg 1.x commands that supported working on a repo AND on an archive
    were split into 2 commands, some others were renamed:

    - borg 2 repo commands:

      - borg rcreate  # "repo create", was: borg init
      - borg rlist  # "repo list"
      - borg rinfo  # "repo info"
      - borg rdelete  # "repo delete"
    - borg 2 archive commands:

      - borg create ARCHIVE ...
      - borg list ARCHIVE
      - borg extract ARCHIVE ...
      - borg diff ARCH1 ARCH2
      - borg rename OLDNAME NEWNAME
      - borg info -a ARCH_GLOB
      - borg delete -a ARCH_GLOB
      - borg recreate -a ARCH_GLOB ...
      - borg mount -a ARCH_GLOB mountpoint ...

    For more details, please consult the docs or --help option output.
  - create/recreate/import-tar --timestamp: defaults to local timezone
    now (was: UTC)
- some deprecated options were removed:

  - removed --remote-ratelimit (use --upload-ratelimit)
  - removed --numeric-owner (use --numeric-ids)
  - removed --nobsdflags (use --noflags)
  - removed --noatime (default now, see also --atime)
  - removed --save-space option (does not change behaviour)
- using --list together with --progress is now disallowed (except with --log-json), #7219
- the --glob-archives option was renamed to --match-archives (the short option
  name -a is unchanged) and extended to support different pattern styles:

  - id: for identical string match (this is the new default!)
  - sh: for shell pattern / globbing match (this was used by --glob-archives)
  - re: for regular expression match

  So you might need to edit your scripts like e.g.::

      borg 1.x: --glob-archives 'myserver-*'
      borg 2.0: --match-archives 'sh:myserver-*'

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

New features:

- diff: include changes in ctime and mtime, #7248
- diff: sort JSON output alphabetically
- diff --content-only: option added to ignore metadata changes
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
- docs:

  - add installation instructions for Windows
  - improve --one-file-system help and docs (macOS APFS), #5618 #4876
  - BORG_KEY_FILE: clarify docs, #7444
  - installation: add link to OS dependencies, #7356
  - update FAQ about locale/unicode issues, #6999
  - improve mount options rendering, #7359
  - make timestamps in manual pages reproducible.
  - describe performing pull-backups via ssh remote forwarding
  - suggest to use forced command when using remote-fowarding via ssh
  - fix some -a / --match-archives docs issues
  - incl./excl. options header, clarify --path-from-stdin exclusive control
  - add note about MAX_DATA_SIZE
  - update security support docs
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
