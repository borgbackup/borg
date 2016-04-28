Changelog
=========

Version 1.1.0 (not released yet)
--------------------------------

New features:

- borg recreate: re-create existing archives, #787 #686 #630 #70, also see
  #757, #770.

  - selectively remove files/dirs from old archives
  - re-compress data
  - re-chunkify data, e.g. to have upgraded Attic / Borg 0.xx archives
    deduplicate with Borg 1.x archives or to experiment with chunker-params.
- create: visit files in inode order (better speed, esp. for large directories
  and rotating disks)
- borg diff: show differences between archives
- borg list improved:

  - removed {formatkeys}, see "borg list --help"
  - --list-format is deprecated, use --format instead
  - now supports the usual [PATH [PATHS…]] syntax and excludes
  - new keys: csize, num_chunks, unique_chunks, NUL
  - supports guaranteed_available hashlib hashes
    (to avoid varying functionality depending on environment)
- prune:

  - to better visualize the "thinning out", we now list all archives in
    reverse time order. rephrase and reorder help text.
  - implement --keep-last N via --keep-secondly N, also --keep-minutely.
    assuming that there is not more than 1 backup archive made in 1s,
    --keep-last N and --keep-secondly N are equivalent, #537
- borg comment: add archive comments, #842
- provide "borgfs" wrapper for borg mount, enables usage via fstab, #743
- create: add 'x' status for excluded paths, #814
- --show-version: shows/logs the borg version (use -v), #725
- borg list/prune/delete: also output archive id, #731

Bug fixes:

- init: clean up partial repo if passphrase input is aborted, #850
- info: quote cmdline arguments that have spaces in them
- failing hashindex tests on netbsd, #804
- fix links failing for extracting subtrees, #761

Other changes:

- replace stdlib hmac with OpenSSL, zero-copy decrypt (10-15% increase in
  performance of hash-lists and extract).
- Source:

  - pass meta-data around, #765
  - move some constants to new constants module
  - better readability and less errors with namedtuples, #823
- Docs:

  - better help texts and sphinx reproduction of usage help:

    - Group options
    - Nicer list of options in Sphinx
    - Deduplicate 'Common options' (including --help)
  - chunker: added some insights by "Voltara", #903
  - clarify what "deduplicated size" means
  - fix / update / add package list entries
  - new contributors in AUTHORS!
- Tests:

  - vagrant: add ubuntu/xenial 64bit - this box has still some issues
  - ChunkBuffer: add test for leaving partial chunk in buffer, fixes #945


Version 1.0.2
-------------

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
  a overflow would have occured.
- borg delete: fix --cache-only for broken caches, #874

  Makes --cache-only idempotent: it won't fail if the cache is already deleted.
- fixed borg create --one-file-system erroneously traversing into other
  filesystems (if starting fs device number was 0), #873
- workround a bug in Linux fadvise FADV_DONTNEED, #907

Other changes:

- better test coverage for hashindex, incl. overflow testing, checking correct
  computations so endianness issues would be discovered.
- reproducible doc for ProgressIndicator*,  make the build reproducible.
- use latest llfuse for vagrant machines
- docs:

  - use /path/to/repo in examples, fixes #901
  - fix confusing usage of "repo" as archive name (use "arch")


Version 1.0.1
-------------

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
- don't try to backup doors or event ports (Solaris and derivates)
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


Version 1.0.0
-------------

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


Version 1.0.0rc2
----------------

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
  - freebsd dependency installation and fuse configuration, #649
  - add example how to restore a raw device, #671
  - add a hint about the dev headers needed when installing from source
  - add examples for delete (and handle delete after list, before prune), #656
  - update example for borg create -v --stats (use iso datetime format), #663
  - added example to BORG_RSH docs
  - "connection closed by remote": add FAQ entry and point to issue #636


Version 1.0.0rc1
----------------

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


Version 0.30.0
--------------

Compatibility notes:

- you may need to use -v (or --info) more often to actually see output emitted
  at INFO log level (because it is suppressed at the default WARNING log level).
  See the "general" section in the usage docs.
- for borg create, you need --list (additionally to -v) to see the long file
  list (was needed so you can have e.g. --stats alone without the long list)
- see below about BORG_DELETE_I_KNOW_WHAT_I_AM_DOING (was:
  BORG_CHECK_I_KNOW_WHAT_I_AM_DOING)

Bug fixes:

- fix crash when using borg create --dry-run --keep-tag-files, #570
- make sure teardown with cleanup happens for Cache and RepositoryCache,
  avoiding leftover locks and TEMP dir contents, #285 (partially), #548
- fix locking KeyError, partial fix for #502
- log stats consistently, #526
- add abbreviated weekday to timestamp format, fixes #496
- strip whitespace when loading exclusions from file
- unset LD_LIBRARY_PATH before invoking ssh, fixes strange OpenSSL library
  version warning when using the borg binary, #514
- add some error handling/fallback for C library loading, #494
- added BORG_DELETE_I_KNOW_WHAT_I_AM_DOING for check in "borg delete", #503
- remove unused "repair" rpc method name

New features:

- borg create: implement exclusions using regular expression patterns.
- borg create: implement inclusions using patterns.
- borg extract: support patterns, #361
- support different styles for patterns:

  - fnmatch (`fm:` prefix, default when omitted), like borg <= 0.29.
  - shell (`sh:` prefix) with `*` not matching directory separators and
    `**/` matching 0..n directories
  - path prefix (`pp:` prefix, for unifying borg create pp1 pp2 into the
    patterns system), semantics like in borg <= 0.29
  - regular expression (`re:`), new!
- --progress option for borg upgrade (#291) and borg delete <archive>
- update progress indication more often (e.g. for borg create within big
  files or for borg check repo), #500
- finer chunker granularity for items metadata stream, #547, #487
- borg create --list now used (additionally to -v) to enable the verbose
  file list output
- display borg version below tracebacks, #532

Other changes:

- hashtable size (and thus: RAM and disk consumption) follows a growth policy:
  grows fast while small, grows slower when getting bigger, #527
- Vagrantfile: use pyinstaller 3.1 to build binaries, freebsd sqlite3 fix,
  fixes #569
- no separate binaries for centos6 any more because the generic linux binaries
  also work on centos6 (or in general: on systems with a slightly older glibc
  than debian7
- dev environment: require virtualenv<14.0 so we get a py32 compatible pip
- docs:

  - add space-saving chunks.archive.d trick to FAQ
  - important: clarify -v and log levels in usage -> general, please read!
  - sphinx configuration: create a simple man page from usage docs
  - add a repo server setup example
  - disable unneeded SSH features in authorized_keys examples for security.
  - borg prune only knows "--keep-within" and not "--within"
  - add gource video to resources docs, #507
  - add netbsd install instructions
  - authors: make it more clear what refers to borg and what to attic
  - document standalone binary requirements, #499
  - rephrase the mailing list section
  - development docs: run build_api and build_usage before tagging release
  - internals docs: hash table max. load factor is 0.75 now
  - markup, typo, grammar, phrasing, clarifications and other fixes.
  - add gcc gcc-c++ to redhat/fedora/corora install docs, fixes #583


Version 0.29.0
--------------

Compatibility notes:

- when upgrading to 0.29.0 you need to upgrade client as well as server
  installations due to the locking and commandline interface changes otherwise
  you'll get an error msg about a RPC protocol mismatch or a wrong commandline
  option.
  if you run a server that needs to support both old and new clients, it is
  suggested that you have a "borg-0.28.2" and a "borg-0.29.0" command.
  clients then can choose via e.g. "borg --remote-path=borg-0.29.0 ...".
- the default waiting time for a lock changed from infinity to 1 second for a
  better interactive user experience. if the repo you want to access is
  currently locked, borg will now terminate after 1s with an error message.
  if you have scripts that shall wait for the lock for a longer time, use
  --lock-wait N (with N being the maximum wait time in seconds).

Bug fixes:

- hash table tuning (better chosen hashtable load factor 0.75 and prime initial
  size of 1031 gave ~1000x speedup in some scenarios)
- avoid creation of an orphan lock for one case, #285
- --keep-tag-files: fix file mode and multiple tag files in one directory, #432
- fixes for "borg upgrade" (attic repo converter), #466
- remove --progress isatty magic (and also --no-progress option) again, #476
- borg init: display proper repo URL
- fix format of umask in help pages, #463

New features:

- implement --lock-wait, support timeout for UpgradableLock, #210
- implement borg break-lock command, #157
- include system info below traceback, #324
- sane remote logging, remote stderr, #461:

  - remote log output: intercept it and log it via local logging system,
    with "Remote: " prefixed to message. log remote tracebacks.
  - remote stderr: output it to local stderr with "Remote: " prefixed.
- add --debug and --info (same as --verbose) to set the log level of the
  builtin logging configuration (which otherwise defaults to warning), #426
  note: there are few messages emitted at DEBUG level currently.
- optionally configure logging via env var BORG_LOGGING_CONF
- add --filter option for status characters: e.g. to show only the added
  or modified files (and also errors), use "borg create -v --filter=AME ...".
- more progress indicators, #394
- use ISO-8601 date and time format, #375
- "borg check --prefix" to restrict archive checking to that name prefix, #206

Other changes:

- hashindex_add C implementation (speed up cache re-sync for new archives)
- increase FUSE read_size to 1024 (speed up metadata operations)
- check/delete/prune --save-space: free unused segments quickly, #239
- increase rpc protocol version to 2 (see also Compatibility notes), #458
- silence borg by default (via default log level WARNING)
- get rid of C compiler warnings, #391
- upgrade OS X FUSE to 3.0.9 on the OS X binary build system
- use python 3.5.1 to build binaries
- docs:

  - new mailing list borgbackup@python.org, #468
  - readthedocs: color and logo improvements
  - load coverage icons over SSL (avoids mixed content)
  - more precise binary installation steps
  - update release procedure docs about OS X FUSE
  - FAQ entry about unexpected 'A' status for unchanged file(s), #403
  - add docs about 'E' file status
  - add "borg upgrade" docs, #464
  - add developer docs about output and logging
  - clarify encryption, add note about client-side encryption
  - add resources section, with videos, talks, presentations, #149
  - Borg moved to Arch Linux [community]
  - fix wrong installation instructions for archlinux


Version 0.28.2
--------------

New features:

- borg create --exclude-if-present TAGFILE - exclude directories that have the
  given file from the backup. You can additionally give --keep-tag-files to
  preserve just the directory roots and the tag-files (but not backup other
  directory contents), #395, attic #128, attic #142

Other changes:

- do not create docs sources at build time (just have them in the repo),
  completely remove have_cython() hack, do not use the "mock" library at build
  time, #384
- avoid hidden import, make it easier for PyInstaller, easier fix for #218
- docs:

  - add description of item flags / status output, fixes #402
  - explain how to regenerate usage and API files (build_api or
    build_usage) and when to commit usage files directly into git, #384
  - minor install docs improvements


Version 0.28.1
--------------

Bug fixes:

- do not try to build api / usage docs for production install,
  fixes unexpected "mock" build dependency, #384

Other changes:

- avoid using msgpack.packb at import time
- fix formatting issue in changes.rst
- fix build on readthedocs


Version 0.28.0
--------------

Compatibility notes:

- changed return codes (exit codes), see docs. in short:
  old: 0 = ok, 1 = error. now: 0 = ok, 1 = warning, 2 = error

New features:

- refactor return codes (exit codes), fixes #61
- add --show-rc option enable "terminating with X status, rc N" output, fixes 58, #351
- borg create backups atime and ctime additionally to mtime, fixes #317
  - extract: support atime additionally to mtime
  - FUSE: support ctime and atime additionally to mtime
- support borg --version
- emit a warning if we have a slow msgpack installed
- borg list --prefix=thishostname- REPO, fixes #205
- Debug commands (do not use except if you know what you do: debug-get-obj,
  debug-put-obj, debug-delete-obj, debug-dump-archive-items.

Bug fixes:

- setup.py: fix bug related to BORG_LZ4_PREFIX processing
- fix "check" for repos that have incomplete chunks, fixes #364
- borg mount: fix unlocking of repository at umount time, fixes #331
- fix reading files without touching their atime, #334
- non-ascii ACL fixes for Linux, FreeBSD and OS X, #277
- fix acl_use_local_uid_gid() and add a test for it, attic #359
- borg upgrade: do not upgrade repositories in place by default, #299
- fix cascading failure with the index conversion code, #269
- borg check: implement 'cmdline' archive metadata value decoding, #311
- fix RobustUnpacker, it missed some metadata keys (new atime and ctime keys
  were missing, but also bsdflags). add check for unknown metadata keys.
- create from stdin: also save atime, ctime (cosmetic)
- use default_notty=False for confirmations, fixes #345
- vagrant: fix msgpack installation on centos, fixes #342
- deal with unicode errors for symlinks in same way as for regular files and
  have a helpful warning message about how to fix wrong locale setup, fixes #382
- add ACL keys the RobustUnpacker must know about

Other changes:

- improve file size displays, more flexible size formatters
- explicitly commit to the units standard, #289
- archiver: add E status (means that an error occurred when processing this
  (single) item
- do binary releases via "github releases", closes #214
- create: use -x and --one-file-system (was: --do-not-cross-mountpoints), #296
- a lot of changes related to using "logging" module and screen output, #233
- show progress display if on a tty, output more progress information, #303
- factor out status output so it is consistent, fix surrogates removal,
  maybe fixes #309
- move away from RawConfigParser to ConfigParser
- archive checker: better error logging, give chunk_id and sequence numbers
  (can be used together with borg debug-dump-archive-items).
- do not mention the deprecated passphrase mode
- emit a deprecation warning for --compression N (giving a just a number)
- misc .coverragerc fixes (and coverage measurement improvements), fixes #319
- refactor confirmation code, reduce code duplication, add tests
- prettier error messages, fixes #307, #57
- tests:

  - add a test to find disk-full issues, #327
  - travis: also run tests on Python 3.5
  - travis: use tox -r so it rebuilds the tox environments
  - test the generated pyinstaller-based binary by archiver unit tests, #215
  - vagrant: tests: announce whether fakeroot is used or not
  - vagrant: add vagrant user to fuse group for debianoid systems also
  - vagrant: llfuse install on darwin needs pkgconfig installed
  - vagrant: use pyinstaller from develop branch, fixes #336
  - benchmarks: test create, extract, list, delete, info, check, help, fixes #146
  - benchmarks: test with both the binary and the python code
  - archiver tests: test with both the binary and the python code, fixes #215
  - make basic test more robust
- docs:

  - moved docs to borgbackup.readthedocs.org, #155
  - a lot of fixes and improvements, use mobile-friendly RTD standard theme
  - use zlib,6 compression in some examples, fixes #275
  - add missing rename usage to docs, closes #279
  - include the help offered by borg help <topic> in the usage docs, fixes #293
  - include a list of major changes compared to attic into README, fixes #224
  - add OS X install instructions, #197
  - more details about the release process, #260
  - fix linux glibc requirement (binaries built on debian7 now)
  - build: move usage and API generation to setup.py
  - update docs about return codes, #61
  - remove api docs (too much breakage on rtd)
  - borgbackup install + basics presentation (asciinema)
  - describe the current style guide in documentation
  - add section about debug commands
  - warn about not running out of space
  - add example for rename
  - improve chunker params docs, fixes #362
  - minor development docs update


Version 0.27.0
--------------

New features:

- "borg upgrade" command - attic -> borg one time converter / migration, #21
- temporary hack to avoid using lots of disk space for chunks.archive.d, #235:
  To use it: rm -rf chunks.archive.d ; touch chunks.archive.d
- respect XDG_CACHE_HOME, attic #181
- add support for arbitrary SSH commands, attic #99
- borg delete --cache-only REPO (only delete cache, not REPO), attic #123


Bug fixes:

- use Debian 7 (wheezy) to build pyinstaller borgbackup binaries, fixes slow
  down observed when running the Centos6-built binary on Ubuntu, #222
- do not crash on empty lock.roster, fixes #232
- fix multiple issues with the cache config version check, #234
- fix segment entry header size check, attic #352
  plus other error handling improvements / code deduplication there.
- always give segment and offset in repo IntegrityErrors


Other changes:

- stop producing binary wheels, remove docs about it, #147
- docs:
  - add warning about prune
  - generate usage include files only as needed
  - development docs: add Vagrant section
  - update / improve / reformat FAQ
  - hint to single-file pyinstaller binaries from README


Version 0.26.1
--------------

This is a minor update, just docs and new pyinstaller binaries.

- docs update about python and binary requirements
- better docs for --read-special, fix #220
- re-built the binaries, fix #218 and #213 (glibc version issue)
- update web site about single-file pyinstaller binaries

Note: if you did a python-based installation, there is no need to upgrade.


Version 0.26.0
--------------

New features:

- Faster cache sync (do all in one pass, remove tar/compression stuff), #163
- BORG_REPO env var to specify the default repo, #168
- read special files as if they were regular files, #79
- implement borg create --dry-run, attic issue #267
- Normalize paths before pattern matching on OS X, #143
- support OpenBSD and NetBSD (except xattrs/ACLs)
- support / run tests on Python 3.5

Bug fixes:

- borg mount repo: use absolute path, attic #200, attic #137
- chunker: use off_t to get 64bit on 32bit platform, #178
- initialize chunker fd to -1, so it's not equal to STDIN_FILENO (0)
- fix reaction to "no" answer at delete repo prompt, #182
- setup.py: detect lz4.h header file location
- to support python < 3.2.4, add less buggy argparse lib from 3.2.6 (#194)
- fix for obtaining ``char *`` from temporary Python value (old code causes
  a compile error on Mint 17.2)
- llfuse 0.41 install troubles on some platforms, require < 0.41
  (UnicodeDecodeError exception due to non-ascii llfuse setup.py)
- cython code: add some int types to get rid of unspecific python add /
  subtract operations (avoid ``undefined symbol FPE_``... error on some platforms)
- fix verbose mode display of stdin backup
- extract: warn if a include pattern never matched, fixes #209,
  implement counters for Include/ExcludePatterns
- archive names with slashes are invalid, attic issue #180
- chunker: add a check whether the POSIX_FADV_DONTNEED constant is defined -
  fixes building on OpenBSD.

Other changes:

- detect inconsistency / corruption / hash collision, #170
- replace versioneer with setuptools_scm, #106
- docs:

  - pkg-config is needed for llfuse installation
  - be more clear about pruning, attic issue #132
- unit tests:

  - xattr: ignore security.selinux attribute showing up
  - ext3 seems to need a bit more space for a sparse file
  - do not test lzma level 9 compression (avoid MemoryError)
  - work around strange mtime granularity issue on netbsd, fixes #204
  - ignore st_rdev if file is not a block/char device, fixes #203
  - stay away from the setgid and sticky mode bits
- use Vagrant to do easy cross-platform testing (#196), currently:

  - Debian 7 "wheezy" 32bit, Debian 8 "jessie" 64bit
  - Ubuntu 12.04 32bit, Ubuntu 14.04 64bit
  - Centos 7 64bit
  - FreeBSD 10.2 64bit
  - OpenBSD 5.7 64bit
  - NetBSD 6.1.5 64bit
  - Darwin (OS X Yosemite)


Version 0.25.0
--------------

Compatibility notes:

- lz4 compression library (liblz4) is a new requirement (#156)
- the new compression code is very compatible: as long as you stay with zlib
  compression, older borg releases will still be able to read data from a
  repo/archive made with the new code (note: this is not the case for the
  default "none" compression, use "zlib,0" if you want a "no compression" mode
  that can be read by older borg). Also the new code is able to read repos and
  archives made with older borg versions (for all zlib levels  0..9).

Deprecations:

- --compression N (with N being a number, as in 0.24) is deprecated.
  We keep the --compression 0..9 for now to not break scripts, but it is
  deprecated and will be removed later, so better fix your scripts now:
  --compression 0 (as in 0.24) is the same as --compression zlib,0 (now).
  BUT: if you do not want compression, you rather want --compression none
  (which is the default).
  --compression 1 (in 0.24) is the same as --compression zlib,1 (now)
  --compression 9 (in 0.24) is the same as --compression zlib,9 (now)

New features:

- create --compression none (default, means: do not compress, just pass through
  data "as is". this is more efficient than zlib level 0 as used in borg 0.24)
- create --compression lz4 (super-fast, but not very high compression)
- create --compression zlib,N (slower, higher compression, default for N is 6)
- create --compression lzma,N (slowest, highest compression, default N is 6)
- honor the nodump flag (UF_NODUMP) and do not backup such items
- list --short just outputs a simple list of the files/directories in an archive

Bug fixes:

- fixed --chunker-params parameter order confusion / malfunction, fixes #154
- close fds of segments we delete (during compaction)
- close files which fell out the lrucache
- fadvise DONTNEED now is only called for the byte range actually read, not for
  the whole file, fixes #158.
- fix issue with negative "all archives" size, fixes #165
- restore_xattrs: ignore if setxattr fails with EACCES, fixes #162

Other changes:

- remove fakeroot requirement for tests, tests run faster without fakeroot
  (test setup does not fail any more without fakeroot, so you can run with or
  without fakeroot), fixes #151 and #91.
- more tests for archiver
- recover_segment(): don't assume we have an fd for segment
- lrucache refactoring / cleanup, add dispose function, py.test tests
- generalize hashindex code for any key length (less hardcoding)
- lock roster: catch file not found in remove() method and ignore it
- travis CI: use requirements file
- improved docs:

  - replace hack for llfuse with proper solution (install libfuse-dev)
  - update docs about compression
  - update development docs about fakeroot
  - internals: add some words about lock files / locking system
  - support: mention BountySource and for what it can be used
  - theme: use a lighter green
  - add pypi, wheel, dist package based install docs
  - split install docs into system-specific preparations and generic instructions


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
---------------

Here you can see the full list of changes between each Attic release until Borg
forked from Attic:

Version 0.17
~~~~~~~~~~~~

(bugfix release, released on X)

- Fix hashindex ARM memory alignment issue (#309)
- Improve hashindex error messages (#298)

Version 0.16
~~~~~~~~~~~~

(bugfix release, released on May 16, 2015)

- Fix typo preventing the security confirmation prompt from working (#303)
- Improve handling of systems with improperly configured file system encoding (#289)
- Fix "All archives" output for attic info. (#183)
- More user friendly error message when repository key file is not found (#236)
- Fix parsing of iso 8601 timestamps with zero microseconds (#282)

Version 0.15
~~~~~~~~~~~~

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
~~~~~~~~~~~~

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
~~~~~~~~~~~~

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
~~~~~~~~~~~~

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
~~~~~~~~~~~~

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
~~~~~~~~~~~~

(bugfix release, released on Jan 30, 2014)

- Fix deadlock when extracting 0 sized files from remote repositories
- "--exclude" wildcard patterns are now properly applied to the full path
  not just the file name part (#5).
- Make source code endianness agnostic (#1)

Version 0.9
~~~~~~~~~~~

(feature release, released on Jan 23, 2014)

- Remote repository speed and reliability improvements.
- Fix sorting of segment names to ignore NFS left over files. (#17)
- Fix incorrect display of time (#13)
- Improved error handling / reporting. (#12)
- Use fcntl() instead of flock() when locking repository/cache. (#15)
- Let ssh figure out port/user if not specified so we don't override .ssh/config (#9)
- Improved libcrypto path detection (#23).

Version 0.8.1
~~~~~~~~~~~~~

(bugfix release, released on Oct 4, 2013)

- Fix segmentation fault issue.

Version 0.8
~~~~~~~~~~~

(feature release, released on Oct 3, 2013)

- Fix xattr issue when backing up sshfs filesystems (#4)
- Fix issue with excessive index file size (#6)
- Support access of read only repositories.
- New syntax to enable repository encryption:
    attic init --encryption="none|passphrase|keyfile".
- Detect and abort if repository is older than the cache.


Version 0.7
~~~~~~~~~~~

(feature release, released on Aug 5, 2013)

- Ported to FreeBSD
- Improved documentation
- Experimental: Archives mountable as fuse filesystems.
- The "user." prefix is no longer stripped from xattrs on Linux


Version 0.6.1
~~~~~~~~~~~~~

(bugfix release, released on July 19, 2013)

- Fixed an issue where mtime was not always correctly restored.


Version 0.6
~~~~~~~~~~~

First public release on July 9, 2013
