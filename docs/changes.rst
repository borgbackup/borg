.. _important_notes:

Important notes 2.x
===================

This section provides information about security and corruption issues.

(nothing to see here yet)

.. _changelog:

Change Log 2.x
==============

Version 2.0.0a2 (2022-06-26)
----------------------------

Please note:

This is an alpha release, only for testing - do not use for production repos.

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
- borg init --other-repo=OTHER_REPO: reuse key material from OTHER_REPO, #6554.
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
