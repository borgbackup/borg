# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Machine-specific settings (e.g. the local virtualenv path) live in the gitignored `CLAUDE.local.md`:

@CLAUDE.local.md

## Branch context

This checkout is on `master`, the main development branch — currently borg 2.x (a beta, see
`borg --version`). New development happens here; the stable maintenance branch for the previous
major is `1.4-maint`.

borg 2 is not just newer code, it is a different on-disk world from borg 1.x:

- The repository is a **borgstore** object store (`repository.py` wraps `borgstore.store.Store`),
  not the borg 1.x segment/journal format. There are no `data/` segments, no `COMMIT` transaction
  log, and no repository-side segment index.
- The CLI changed (e.g. `borg repo-create`, `borg repo-list`, archive series, archive IDs) and the
  crypto/key modes changed (AEAD: AES-256-OCB / ChaCha20-Poly1305, with HMAC-SHA256 or BLAKE3 ids).
- `src/borg/archiver/` is a package, one `*_cmd.py` module per command group — not the single
  monolithic `archiver.py` file that borg 1.x (and the `1.4-maint` branch) uses.

Don't be surprised by these differences if you're comparing against borg 1.x docs or memory. Legacy
borg 1.x repositories are only supported read-only via `src/borg/legacy/` (e.g. for `borg transfer`).

## Build

Borg has Cython/C extensions and must be built before it can run.

```bash
source <project-virtualenv>/bin/activate  # see @CLAUDE.local.md for the local path
pip install -r requirements.d/development.txt
pip install -e .  # builds Cython/C extensions in place
```

Requires Python >=3.11, Cython >=3.0.3, pkgconfig, and dev headers for OpenSSL, lz4, zstd, xxhash.
The `borgstore` package (repository backend) is pulled in as a normal dependency.

Env vars to point the build at non-standard lib locations: `BORG_OPENSSL_PREFIX`, `BORG_LIBLZ4_PREFIX`,
`BORG_LIBZSTD_PREFIX`, `BORG_LIBXXHASH_PREFIX`.

After editing any `.pyx`/`.c` file, rebuild the extensions:

```bash
python scripts/make.py clean && pip install -e .
```

If you are requested to build a BINARY (the usual borg build does not build a binary as it is Python),
a pyinstaller-made binary is meant:

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

# Single file / single test (test files are named *_test.py; see python_files in pyproject.toml)
pytest src/borg/testsuite/compress_test.py
pytest src/borg/testsuite/compress_test.py::TestClass::test_method
# archiver command tests live in the src/borg/testsuite/archiver/ package
pytest src/borg/testsuite/archiver/create_test.py

# Via tox (matches CI; needs fakeroot for full coverage, most tests still work without it)
fakeroot -u tox                                 # all tests
fakeroot -u tox --recreate                      # after changing tox.ini
fakeroot -u tox -e py311                         # one Python version only
fakeroot -u tox -e py311 -- -k 'locking'        # select tests by keyword (posargs after --)
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

- **`repository.py`** — `Repository`, a key→value object store built on top of **borgstore**
  (`borgstore.store.Store`). Keys are 32-byte object IDs; the repo doesn't know what an "archive" or
  "file" is. borgstore provides the actual storage backends and transport: local filesystem,
  `ssh://` (borgstore ssh backend, optionally reusing `BORGSTORE_RSH`), and `rest://` (borgstore REST
  server, served by `borg serve --rest`). This replaces the borg 1.x segment/journal format — read
  `docs/internals/data-structures.rst` before touching repository/object/format code.
- **`archiver/serve_cmd.py`** — `borg serve` provides the server side for remote repositories: the
  default mode serves a repository over stdio to a connecting borgstore ssh backend, and
  `borg serve --rest` runs the borgstore REST server. (There is no separate `remote.py` / custom RPC
  layer anymore — borgstore owns the client/server transport.)
- **`crypto/key.py`, `crypto/low_level.pyx`** — encryption/authentication (AEAD: AES-256-OCB or
  ChaCha20-Poly1305; ids via HMAC-SHA256 or BLAKE3) and key file handling (keyfile vs repokey
  storage). The `id_hash` used for deduplication depends on the key/encryption mode.
- **`chunkers/`** (buzhash, buzhash64, fastcdc, reader — Cython/C) — content-defined chunking:
  splitting the input into variable-length chunks at content-defined boundaries is what makes dedup
  insensitive to shifted/inserted bytes.
- **`compress.pyx`** — per-chunk compression (lz4/zstd/zlib/lzma/…), applied to each chunk before
  it is encrypted and stored.
- **`cache.py`** — the local chunks/files cache used to decide what needs uploading. borg2 does **not**
  refcount chunks. The chunks index (`ChunkIndex` from `hashindex.pyx`/`_hashindex.c`) maps chunk ID →
  `(flags, size, pack_id, obj_offset, obj_size)`. Because borg2 batches many objects into a single
  **pack** and stores that pack as one borgstore object, the index also records where each chunk lives
  inside its pack: the containing `pack_id` plus the object's offset and size within the pack. The
  files cache short-circuits re-chunking unchanged files. See `docs/internals/packs.rst` for the pack
  format.
- **`archive.py`** (`Archive`) and **`manifest.py`** (`Manifest`, `Archives`) — the layer above the
  flat KV store, turning it into archives made of `Item`s (files/dirs/links, see `item.pyx`)
  referencing chunk lists. The `manifest` is largely a relic from borg 1.x; in borg2 the list of
  archives is a **separate** structure (the `Archives` class in `manifest.py`), no longer embedded in
  the manifest object.
- **`archiver/`** — the CLI, one `do_<command>` method per subcommand spread across `*_cmd.py`
  modules (e.g. `create_cmd.py`, `check_cmd.py`, `repo_create_cmd.py`). `build_parser` and the
  argument-parsing entry points live in `archiver/__init__.py`. This is the package to search first
  when changing or adding a CLI command/flag.
- **`platform/`** — per-OS backends (Linux/Darwin/FreeBSD/NetBSD/Windows) for xattrs, ACLs, syncing,
  process info; `platform/__init__.py` picks the right implementation at import time.
- **`helpers/`** — grab-bag of utilities used across layers (arg/format parsing, msgpack helpers,
  progress reporting, filesystem helpers); check here before writing a new utility, it may exist.

**Client/server split:** most `do_*` archiver commands operate against a local or remote `Repository`
transparently — the choice of local vs. `ssh://`/`rest://` is resolved by `Location` parsing in
`helpers/` and borgstore backend selection, and doesn't otherwise change command logic. `borg serve`
on the remote end provides the server side.

**Docs as source of truth for on-disk formats:** `docs/internals/data-structures.rst` (plus
`docs/internals/packs.rst` for the pack format) document the repository/object/pack/archive/item/cache
formats in detail and are more authoritative than guessing from code — read the relevant section
before changing serialization or the on-disk layout.
CLI usage docs (`docs/usage/`) and man pages are generated from the argparse definitions in
`archiver/` (`python scripts/make.py build_usage`/`build_man`); don't hand-edit generated usage docs,
and don't feel obligated to regenerate them for every CLI change — that's normally done at release time.

## Logging conventions

Use the correct log level (debug only for debugging; info/warning/error/critical as appropriate).

When directly prompting the user (e.g. Y/N confirmations), write straight to stderr, not through the
logger and not to stdout (stdout may be piped). Info-level volume is controlled via flags like
`--stats`/`--list` feeding topic loggers — see `_setup_implied_logging()` in `archiver/__init__.py`.
