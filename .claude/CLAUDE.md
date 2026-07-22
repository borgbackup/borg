# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Machine-specific settings (e.g. the local virtualenv path) live in the gitignored `CLAUDE.local.md`:

@CLAUDE.local.md

## Branch context

This checkout is based on `1.4-maint`, a stable maintenance branch (main development happens on
`master`). The current branch is either `1.4-maint` itself or a branch forked from it (e.g. to work on
a bug fix).

Only backport data-loss/corruption/security/forward-compat/doc fixes here — most PRs should target
`master` instead.

On the 1.4 line, `src/borg/archiver.py` is one large monolithic file (all `do_*` command
implementations); on `master` it is split into separate modules in `src/borg/archiver/` package.
Don't be surprised by the difference if you're comparing against upstream docs or memory of the codebase.

## Build

Borg has Cython/C extensions and must be built before it can run.

```bash
source <project-virtualenv>/bin/activate  # see @CLAUDE.local.md for the local path
pip install -r requirements.d/development.txt
pip install -e .  # builds Cython/C extensions in place
```

Requires Python >=3.10, Cython >=3.0.3, pkgconfig, and dev headers for OpenSSL, lz4, zstd, xxhash.

Env vars to point the build at non-standard lib locations: `BORG_OPENSSL_PREFIX`, `BORG_LIBLZ4_PREFIX`,
`BORG_LIBZSTD_PREFIX`, `BORG_LIBXXHASH_PREFIX`.

After editing any `.pyx`/`.c` file, rebuild the extensions:

```bash
python scripts/make.py clean && pip install -e .
```

If you are requested to build a BINARY (the usual borg build does not build a binary as it is Python),
a pyinstaller-made binary is meant. On this `1.4-maint` branch:

- POSIX: `pyinstaller --clean --distpath=dist/binary/ scripts/borg.exe.spec`

## Writing tests

Always write pytest-style tests unless unittest-style is explicitly required.

## Writing docstrings, comments, documentation

The docs shall always be in sync with the current code, algorithms and data structures.

The docs must:
- describe how it works, what it does, in its CURRENT state.
- use "TODO:" comments to refer to future tasks

The docs must not:
- describe what the code did in the past
- describe something that the code is NOT doing in its current state.

## Running code or tests

Always activate the project virtualenv first (see `@CLAUDE.local.md` for its local path).

## Tests

```bash
# Run everything (never omit --benchmark-skip unless you specifically want the slow benchmarks).
# Running all the tests without parallelizing them is very slow, the parallel variant should be preferred.
pytest --benchmark-skip -v -rs -n auto  # parallel variant
pytest --benchmark-skip -v -rs          # sequential (slow)

# Single file / single test
pytest src/borg/testsuite/archiver.py
pytest src/borg/testsuite/archiver.py::TestClass::test_method

# Via tox (matches CI; needs fakeroot for full coverage, most tests still work without it)
fakeroot -u tox                                     # all tests
fakeroot -u tox --recreate                          # after changing tox.ini
fakeroot -u tox -e py310                            # one Python version only
fakeroot -u tox borg.testsuite.locking              # one test module
fakeroot -u tox borg.testsuite.locking -- -k 'not Timer'   # -- requires the module path too
```

Test env vars: `BORG_TESTS_IGNORE_MODES` (disable mode/permission tests), `BORG_FUSE_IMPL=llfuse|pyfuse3`
(select FUSE implementation for mount tests).

Tests live in `src/borg/testsuite/`, see `python_files` in `pyproject.toml`.

macOS users without a Linux box can run the Linux test matrix via Podman: `./scripts/linux-run tox -e py311-pyfuse3`.

## Lint

```bash
tox -e ruff        # or: ruff check .
pre-commit install # one-time, so pre-commit hooks run automatically on commit
```

Style: PEP 8 at 120 columns (not 79). Comments/docstrings that are full sentences end with a period.
Per-file ruff ignores (mostly `E501`/`F401`/legacy `E722`/`E741`) are listed in `pyproject.toml`
under `[tool.ruff.per-file-ignores]` — check there before "fixing" a lint warning in an old file;
it may be intentionally exempted.

Python code files must never have trailing blanks at the end of lines.
Python code files must always end with exactly one linefeed character at the end of the file.

## Committing

The working tree has a lot of stray untracked scratch files at the repo root — these are the user's
own working notes, not build artifacts.
Never do `git add -A` / `git add .`; stage only the files you intentionally changed.

## Architecture

Borg is a client encrypting/deduplicating/compressing data *before* it ever reaches the repository,
so the repository storage layer never sees plaintext or has any notion of files/archives.

**Layering, bottom to top:**

- **`repository.py`** — a transactional, append-only key→value store (`Repository`). Keys are 32-byte
  IDs; the repo doesn't know what an "archive" or "file" is. Segments in `data/` are the journal; a
  segment ordering + `COMMIT` entries define transaction boundaries and crash consistency. The
  `HashIndex` (`_hashindex.c`/`hashindex.pyx`) maps object IDs to segment+offset. See
  `docs/internals/data-structures.rst` for the full on-disk format spec — read it before touching
  repository/segment/index code.
- **`remote.py`** — `RemoteRepository` (client) / `RepositoryServer` (server side of `borg serve`)
  implement the same key-value API over a RPC protocol on stdin/stdout (used for
  `ssh://` repos). Every method callable remotely must be allowlisted in `RepositoryServer.rpc_methods`.
- **`crypto/key.py`, `crypto/low_level.pyx`** — encryption/authentication (AES + HMAC-SHA256, or
  ChaCha20-Poly1305/BLAKE2) and key file handling (keyfile vs repokey storage). `id_hash` used for
  deduplication depends on the encryption mode.
- **`compress.pyx`**, **`chunkers/`** (buzhash, buzhash64, fastcdc in Cython/C) — per-chunk compression
  and content-defined chunking; chunking is what makes dedup insensitive to shifted/inserted bytes.
- **`cache.py`, `cache_sync/`** — the local chunks/files cache (which chunk IDs already exist in the
  repo, refcounts) used to decide what needs uploading; synced against the repository's authoritative
  state via `cache_sync` (C-accelerated msgpack stream unpacking).
- **`archive.py`** — `Archive`/`Manifest`: the next layer up, turning the flat KV store into archives
  made of `Item`s (files/dirs/links, see `item.pyx`) referencing chunk lists. The manifest
  (`helpers/manifest.py`) is itself an object in the repo listing all archives.
- **`archiver.py`** — the CLI: argument parsing (`build_parser`, one `subparsers.add_parser(...)` block
  per subcommand) and one `do_<command>` method per subcommand, e.g. `do_create`, `do_check`. This is
  the file to search first when changing or adding a CLI command/flag.
- **`platform/`** — per-OS backends (Linux/Darwin/FreeBSD/NetBSD/Windows) for xattrs, ACLs, syncing,
  process info; `platform/__init__.py` picks the right implementation at import time.
- **`helpers/`** — grab-bag of utilities used across layers (arg/format parsing, msgpack helpers,
  progress reporting, filesystem helpers); check here before writing a new utility, it may exist.

**Client/server split:** most `do_*` archiver commands operate against a `Repository` or
`RemoteRepository` transparently — the choice of local vs. `ssh://` is resolved by `Location` parsing
in `helpers/` and doesn't otherwise change command logic. `borg serve` on the remote end runs
`RepositoryServer`, which allowlists and dispatches RPCs to a local `Repository`.

**Docs as source of truth for on-disk formats:** `docs/internals/data-structures.rst` documents the
repository/segment/index/manifest/archive/item/cache formats in detail and is more authoritative than
guessing from code — read the relevant section before changing serialization or the transaction log.
CLI usage docs (`docs/usage/`) and man pages are generated from the argparse definitions in
`archiver.py` (`python scripts/make.py build_usage`/`build_man`); don't hand-edit generated usage docs,
and don't feel obligated to regenerate them for every CLI change — that's normally done at release time.

## Logging conventions

Use the correct log level (debug only for debugging; info/warning/error/critical as appropriate).

When directly prompting the user (e.g. Y/N confirmations), write straight to stderr, not through the
logger and not to stdout (stdout may be piped). Info-level volume is controlled via flags like
`--stats`/`--list` feeding topic loggers — see `_setup_implied_logging()` in `archiver.py`.


