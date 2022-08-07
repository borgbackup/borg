.. _important_notes:

Important notes 2.x
===================

This section provides information about security and corruption issues.

(nothing to see here yet)

.. _changelog:

Change Log 2.x
==============

Version 2.0.0b1 (2022-08-08)
----------------------------

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
  - -P / --prefix option was removed, please use the similar -a / --glob-archives.
  - differently than with borg 1.x you ONLY give the repo there, never a ::archive.
  - the archive name is either given as a positional parameter, like:

    - borg create myarchive2 /some/path
    - borg diff myarchive1 myarchive2
  - or, if the command makes sense for an arbitrary amount of archives, archives
    can be selected using a glob pattern, like:

    - borg delete -a 'myarchive*'
    - borg recreate -a 'myarchive*'
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
- some deprecated options were removed:

  - removed --remote-ratelimit (use --upload-ratelimit)
  - removed --numeric-owner (use --numeric-ids)
  - removed --nobsdflags (use --noflags)
  - removed --noatime (default now, see also --atime)

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
    - all hardlinks have chunks, maybe chunks_healty, hlid
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
