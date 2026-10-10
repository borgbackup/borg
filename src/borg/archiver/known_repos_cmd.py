import errno
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

from ..constants import *  # NOQA
from ..crypto.key import LEGACY_KEY_TYPES, AVAILABLE_KEY_TYPES
from ..helpers import format_file_size, json_print, get_security_dir, get_cache_dir
from ..helpers import safe_timestamp, OutputTimestamp
from ..helpers import os_open, os_stat, flags_dir, flags_dir_follow, flags_normal
from ..helpers.argparsing import ArgumentParser
from ..legacy.fs import get_config_dir as get_config_dir_legacy
from ..legacy.fs import get_cache_dir as get_cache_dir_legacy

from ..logger import create_logger

logger = create_logger()

# A borg2 repository id is a 32 byte random id, hex-encoded (bin_to_hex), see Repository.create().
# \Z (not $) anchors strictly at the end of the string: $ also matches just before a trailing
# newline, which would let a directory name like "<64 hex chars>\n" slip through re.match().
REPO_ID_RE = re.compile(r"^[0-9a-f]{64}\Z")


def _printable(s):
    """Escape control characters for safe terminal output (JSON output is unaffected)."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in s)


def _build_key_type_labels():
    """Map each key-type byte (as SecurityManager.save() writes it) to a readable label.

    Derived from LEGACY_KEY_TYPES + AVAILABLE_KEY_TYPES (the classes identify_key() searches),
    matching how "borg repo-info" builds its "Encrypted:" line, rather than a hand-maintained table.
    """
    labels = {}
    for key_cls in LEGACY_KEY_TYPES + AVAILABLE_KEY_TYPES:
        is_legacy = key_cls in LEGACY_KEY_TYPES
        label = key_cls.ENC_NAME
        if not key_cls.IDHASH_IN_ENC_NAME:
            label += f", {key_cls.IDHASH_NAME}"
        if is_legacy:
            label += " (legacy)"
        for type_byte in key_cls.TYPES_ACCEPTABLE:
            labels[str(type_byte)] = label
    return labels


# built once at import time: the key classes list is static.
KEY_TYPE_LABELS = _build_key_type_labels()


class _Inspector:
    """Filesystem probes that count a failed probe as "incomplete" (see print_warning below).

    Built on borg's os_open()/os_stat() helpers (helpers/fs.py), the same ones create_cmd.py
    uses. Where those return a real fd (not Windows), a validated directory is read from via
    that fd rather than its pathname - closing the TOCTOU window where the pathname is replaced
    between a check and a later read. On Windows, os_open() returns None for directories and a
    pathname fallback is used instead - still correct, just not race-free.
    """

    def __init__(self):
        self.incomplete = 0

    def _warn(self, msg, *args):
        self.incomplete += 1
        # escape control chars in str/OSError args before logging (logger.py has no sanitizer)
        logger.warning(msg, *(_printable(str(a)) if isinstance(a, (str, OSError)) else a for a in args))

    def close_dir(self, d):
        """Close a directory handle from open_root/open_subdir - a no-op for the Windows

        pathname fallback (a Path, not a real fd).
        """
        if not isinstance(d, Path):
            os.close(d)

    def _open_dir(self, parent, name, display, follow_symlinks):
        """Open name (an absolute Path if parent is None, else relative to the fd/Path parent)

        as a directory, via borg's os_open(). None if missing, not a directory, or (if not
        follow_symlinks) a symlink. parent is None only for a scan root. The caller must
        close_dir() a non-None result.
        """
        flags = flags_dir_follow if follow_symlinks else flags_dir
        try:
            if parent is None:
                fd = os_open(path=name, flags=flags)
            elif isinstance(parent, Path):
                fd = os_open(path=parent / name, flags=flags)  # Windows pathname fallback
            else:
                fd = os_open(parent_fd=parent, name=name, flags=flags)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            if not follow_symlinks and getattr(exc, "errno", None) == errno.ELOOP:
                return None  # O_NOFOLLOW rejected a symlink leaf - not a failure, just "not a dir"
            self._warn("known-repos: could not open %s: %s", display, exc)
            return None
        if fd is None:
            # Windows: os_open() can't open a directory; fall back to the pathname itself.
            path = name if parent is None else (parent / name if isinstance(parent, Path) else None)
            if path is None:
                self._warn("known-repos: could not open %s: no descriptor and no pathname fallback", display)
                return None
            try:
                st = path.stat() if follow_symlinks else path.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                self._warn("known-repos: could not check %s: %s", display, exc)
                return None
            return path if stat.S_ISDIR(st.st_mode) else None
        # release fd on every path out except the final success, including KeyboardInterrupt etc.
        try:
            is_real_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        except OSError as exc:
            os.close(fd)
            self._warn("known-repos: could not check %s: %s", display, exc)
            return None
        except BaseException:
            os.close(fd)
            raise
        if not is_real_dir:
            os.close(fd)
            return None
        return fd

    def open_root(self, path, display):
        """Open a scan root (security/cache root) by absolute path, following symlinks - these

        are Borg's own config/cache directories, not attacker-influenced repo-id entries, so
        there is nothing to protect by rejecting a symlink here. None if not a real directory.
        """
        return self._open_dir(None, path, display, follow_symlinks=True)

    def open_subdir(self, parent, name, display):
        """Open and validate name below parent as a real (non-symlink) directory. None if

        missing/not-a-real-directory. The caller must close_dir() a non-None result.
        """
        return self._open_dir(parent, name, display, follow_symlinks=False)

    def read_subfile(self, parent, name, display, max_size=4096):
        """Read name below parent as a real (non-symlink) regular file, bounded.

        None if missing, not a regular file, too large, or not UTF-8. Missing and
        "not a regular file" (including a symlink/FIFO in place of the expected file,
        since Borg itself never creates one there) are not inspection failures; too
        large and not-UTF-8 are, and so is a read/stat error on an entry that does
        exist.
        """
        if isinstance(parent, Path):
            path = parent / name
            try:
                st = path.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                self._warn("known-repos: could not check %s: %s", display, exc)
                return None
            if not stat.S_ISREG(st.st_mode):
                return None
            try:
                with path.open("rb") as f:
                    data = f.read(max_size + 1)
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                self._warn("known-repos: could not read %s: %s", display, exc)
                return None
        else:
            # flags_normal includes O_NONBLOCK|O_NOFOLLOW (see helpers/fs.py) - the same flags
            # borg's own create_cmd.py uses to read a regular file without blocking on a FIFO
            # that has no writer, and without following a symlink leaf.
            try:
                fd = os_open(parent_fd=parent, name=name, flags=flags_normal)
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                if getattr(exc, "errno", None) == errno.ELOOP:
                    return None
                self._warn("known-repos: could not read %s: %s", display, exc)
                return None
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return None
                # loop until EOF or max_size + 1 bytes: a single os.read can return a short read
                chunks = []
                remaining = max_size + 1
                while remaining > 0:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            except OSError as exc:
                self._warn("known-repos: could not read %s: %s", display, exc)
                return None
            finally:
                os.close(fd)
        if len(data) > max_size:
            self._warn("known-repos: %s is larger than %d bytes, ignoring its content", display, max_size)
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._warn("known-repos: %s is not valid UTF-8, ignoring its content: %s", display, exc)
            return None

    def stat_subfile(self, parent, name, display):
        """stat (not following symlinks) name below parent; the result only if it is a regular file."""
        if isinstance(parent, Path):
            path = parent / name
            try:
                st = path.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                self._warn("known-repos: could not check %s: %s", display, exc)
                return None
        else:
            try:
                st = os_stat(parent_fd=parent, name=name, follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                return None
            except OSError as exc:
                self._warn("known-repos: could not check %s: %s", display, exc)
                return None
        return st if stat.S_ISREG(st.st_mode) else None

    def list_names(self, d, display):
        """List entry names in an open directory (fd or Path), or [] with a warning on OSError."""
        try:
            if isinstance(d, Path):
                return [e.name for e in d.iterdir()]
            with os.scandir(d) as it:
                return [e.name for e in it]
        except (FileNotFoundError, NotADirectoryError):
            return []
        except OSError as exc:
            self._warn("known-repos: could not list %s, results may be incomplete: %s", display, exc)
            return []

    def dir_size(self, root, root_display):
        """Sum regular-file sizes below an already-open/validated directory (fd or Path), not

        following symlinks. Consumes (closes) root. Best-effort: an unreadable entry is
        skipped (warned, counted incomplete), so the total can be a partial count. Uses an
        explicit stack, not Python recursion, to bound open descriptors by tree depth, not
        breadth, and to avoid Python's recursion limit on a very deep tree.
        """
        total = 0
        # each entry is (dir_handle, display, remaining_names_iterator); closed once exhausted.
        # root is pushed before the try so a BaseException from list_names() (list_names() itself
        # catches OSError) still leaves root on the stack for the finally below to close.
        stack = [[root, root_display, None]]
        try:
            stack[0][2] = iter(self.list_names(root, root_display))
            while stack:
                current, display, names = stack[-1]
                name = next(names, None)
                if name is None:
                    self.close_dir(current)
                    stack.pop()
                    continue
                entry_display = f"{display}/{name}"
                if isinstance(current, Path):
                    try:
                        st = (current / name).lstat()
                    except (FileNotFoundError, NotADirectoryError):
                        continue
                    except OSError as exc:
                        self._warn(
                            "known-repos: could not check %s, reported cache size may be incomplete: %s",
                            entry_display,
                            exc,
                        )
                        continue
                else:
                    try:
                        st = os_stat(parent_fd=current, name=name, follow_symlinks=False)
                    except (FileNotFoundError, NotADirectoryError):
                        continue
                    except OSError as exc:
                        self._warn(
                            "known-repos: could not check %s, reported cache size may be incomplete: %s",
                            entry_display,
                            exc,
                        )
                        continue
                if stat.S_ISDIR(st.st_mode):
                    sub = self.open_subdir(current, name, entry_display)
                    if sub is not None:
                        frame = [sub, entry_display, None]
                        stack.append(frame)
                        frame[2] = iter(self.list_names(sub, entry_display))
                elif stat.S_ISREG(st.st_mode):
                    total += st.st_size
        finally:
            # closes anything left on the stack on an exception path (ordinary completion
            # already pops/closes each level).
            for entry in stack:
                self.close_dir(entry[0])
        return total

    def cache_config_mtime(self, cache_dir, display):
        """mtime of config below an already-open cache_dir, as an OutputTimestamp, or None.

        Best-effort proxy for "a cache-using borg command last ran" - not every command touches
        the cache, so this can lag behind actual repository access.
        """
        st = self.stat_subfile(cache_dir, "config", f"{display}/config")
        if st is None:
            return None
        try:
            return OutputTimestamp(safe_timestamp(st.st_mtime_ns))
        except (OverflowError, OSError, ValueError) as exc:
            self._warn("known-repos: could not convert the mtime of %s/config: %s", display, exc)
            return None

    def open_cache_entry(self, cache_root, repo_id, display):
        """Open and classify the cache entry for repo_id below an already-open cache_root.

        Returns (kind, entry): 'present' (entry is the open, caller-owned handle for
        dir_size/cache_config_mtime), 'absent' (confirmed not a cache, entry is None), or
        'unreadable' (state never established - not a confirmed cache, and the caller must not
        fall back to another root either; entry is None).
        """
        before = self.incomplete
        entry = self.open_subdir(cache_root, repo_id, display)
        if entry is None:
            return ("unreadable" if self.incomplete > before else "absent"), None
        # release entry on every path out except the "present" return, which transfers ownership
        try:
            before = self.incomplete
            if self.stat_subfile(entry, "config", f"{display}/config") is not None:
                return "present", entry
            kind = "unreadable" if self.incomplete > before else "absent"
        except BaseException:
            self.close_dir(entry)
            raise
        self.close_dir(entry)
        return kind, None

    def scan_security_root(self, root, root_display):
        """Return (repo_ids, info, unreadable_ids, listing_ok) for ids directly below an
        already-open security root.

        repo_ids is the set of 64-hex-digit directories with at least one of the two known files
        confirmed present (checked via stat_subfile, independent of read success). info is
        {repo_id: (location, key_type_raw)}, read while the entry is open; a value is None if
        its file is absent or could not be read/decoded.

        unreadable_ids is disjoint from repo_ids: directory names list_names() returned whose
        presence/absence could not be established (the entry itself could not be opened, e.g.
        EACCES, or neither file was confirmed present and at least one of the two
        presence checks failed). A name list_names() returned must end up in repo_ids,
        unreadable_ids, or genuinely neither - never silently dropped.

        listing_ok is False when list_names() on root itself failed (e.g. EIO after the root was
        already opened): repo_ids/unreadable_ids are then necessarily incomplete, so the caller
        must not treat this root as fully searched for an id discovered elsewhere.
        """
        repo_ids = set()
        info = {}
        unreadable_ids = set()
        before_list = self.incomplete
        names = self.list_names(root, root_display)
        listing_ok = self.incomplete == before_list
        for name in names:
            if not REPO_ID_RE.match(name):
                continue
            entry_display = f"{root_display}/{name}"
            before = self.incomplete
            entry = self.open_subdir(root, name, entry_display)
            if entry is None:
                if self.incomplete > before:
                    unreadable_ids.add(name)
                continue
            try:
                before = self.incomplete
                has_location = self.stat_subfile(entry, "location", f"{entry_display}/location") is not None
                has_key_type = self.stat_subfile(entry, "key-type", f"{entry_display}/key-type") is not None
                if has_location or has_key_type:
                    location = self.read_subfile(entry, "location", f"{entry_display}/location")
                    # SecurityManager.save() writes location verbatim (no trailing newline); only
                    # turn a present-but-empty read into None, do not alter legitimate whitespace.
                    location = location or None
                    key_type_raw = self.read_subfile(entry, "key-type", f"{entry_display}/key-type")
                    key_type_raw = key_type_raw.strip() or None if key_type_raw else None
                    repo_ids.add(name)
                    info[name] = (location, key_type_raw)
                elif self.incomplete > before:
                    # stat_subfile only counts incomplete on a real OSError, not on
                    # FileNotFoundError/NotADirectoryError, so this path means a genuine
                    # EACCES-class failure, not plain absence.
                    unreadable_ids.add(name)
                # else: neither file exists - not a security entry, not an inspection failure.
            finally:
                self.close_dir(entry)
        return repo_ids, info, unreadable_ids, listing_ok

    def scan_cache_root(self, root, root_display, repo_ids_out, unreadable_ids_out):
        """Add repo ids directly below an already-open cache root into repo_ids_out: a

        64-hex-digit directory with a config *file* (excludes the storecache directory and
        the CACHEDIR.TAG file get_cache_dir() writes). A name list_names() returned that could
        not be classified as having a cache or not (the entry could not be opened, or its
        config file's presence could not be established) goes into unreadable_ids_out instead
        of being dropped - see scan_security_root() for why that distinction matters.

        Returns listing_ok (see scan_security_root() for its meaning).
        """
        before_list = self.incomplete
        names = self.list_names(root, root_display)
        listing_ok = self.incomplete == before_list
        for name in names:
            if not REPO_ID_RE.match(name):
                continue
            entry_display = f"{root_display}/{name}"
            before = self.incomplete
            entry = self.open_subdir(root, name, entry_display)
            if entry is None:
                if self.incomplete > before:
                    unreadable_ids_out.add(name)
                continue
            try:
                before = self.incomplete
                is_cache = self.stat_subfile(entry, "config", f"{entry_display}/config") is not None
            finally:
                self.close_dir(entry)
            if is_cache:
                repo_ids_out.add(name)
            elif self.incomplete > before:
                unreadable_ids_out.add(name)
        return listing_ok


def _legacy_security_dir():
    """Where borg 1.x stores local security information, without creating anything.

    Mirrors legacy.fs.get_security_dir(create=False), but that still calls get_config_dir()
    with create=True internally; re-implemented here to stay fully read-only.
    """
    security_dir = os.environ.get("BORG_SECURITY_DIR")
    if security_dir is None:
        security_dir = str(Path(get_config_dir_legacy(create=False)) / "security")
    return security_dir


class KnownReposMixIn:
    def do_known_repos(self, args):
        """List repositories Borg has local state for (security info and/or cache)."""
        inspector = _Inspector()
        security_root = Path(get_security_dir(create=False))
        # v1 repos keep security info at a different default location than borg2 (and on some
        # platforms, e.g. macOS, a different cache root too) unless BORG_SECURITY_DIR/BORG_CACHE_DIR
        # override both to the same place.
        legacy_security_root = Path(_legacy_security_dir())
        cache_root = Path(get_cache_dir(create=False))
        legacy_cache_root = Path(get_cache_dir_legacy(create=False))

        with ExitStack() as stack:
            # every root is opened once up front and held open for the whole scan.
            def _open(path):
                before = inspector.incomplete
                d = inspector.open_root(path, str(path))
                if d is not None:
                    stack.callback(inspector.close_dir, d)
                    return d, "present"
                return None, ("unreadable" if inspector.incomplete > before else "absent")

            security_root_d, security_root_kind = _open(security_root)
            if legacy_security_root != security_root:
                legacy_security_root_d, legacy_security_root_kind = _open(legacy_security_root)
            else:
                legacy_security_root_d, legacy_security_root_kind = None, "absent"
            cache_root_d, cache_root_kind = _open(cache_root)
            if legacy_cache_root != cache_root:
                legacy_cache_root_d, legacy_cache_root_kind = _open(legacy_cache_root)
            else:
                legacy_cache_root_d, legacy_cache_root_kind = None, "absent"

            if security_root_d is not None:
                borg2_ids, borg2_info, borg2_unreadable_ids, borg2_security_listing_ok = inspector.scan_security_root(
                    security_root_d, str(security_root)
                )
            else:
                borg2_ids, borg2_info, borg2_unreadable_ids, borg2_security_listing_ok = set(), {}, set(), True
            if legacy_security_root_d is not None:
                legacy_ids, legacy_info, legacy_unreadable_ids, legacy_security_listing_ok = (
                    inspector.scan_security_root(legacy_security_root_d, str(legacy_security_root))
                )
                legacy_ids -= borg2_ids  # prefer the borg2 entry if an id somehow exists in both trees
                legacy_unreadable_ids -= borg2_ids
            else:
                legacy_ids, legacy_info, legacy_unreadable_ids, legacy_security_listing_ok = set(), {}, set(), True
            security_unreadable_ids = (borg2_unreadable_ids | legacy_unreadable_ids) - borg2_ids - legacy_ids
            repo_ids = borg2_ids | legacy_ids | security_unreadable_ids
            # "no security entry" can only be a confirmed False for a cache-only id when BOTH
            # security roots were fully searched (root opened and its own listing succeeded,
            # not just free of per-id EACCES - scan_security_root() tracks that separately).
            security_fully_searched = (
                security_root_kind != "unreadable"
                and legacy_security_root_kind != "unreadable"
                and borg2_security_listing_ok
                and legacy_security_listing_ok
            )
            borg2_cache_ids = set()
            borg2_cache_unreadable_ids = set()
            if cache_root_d is not None:
                inspector.scan_cache_root(cache_root_d, str(cache_root), borg2_cache_ids, borg2_cache_unreadable_ids)
            legacy_cache_ids = set()
            legacy_cache_unreadable_ids = set()
            if legacy_cache_root_d is not None:
                inspector.scan_cache_root(
                    legacy_cache_root_d, str(legacy_cache_root), legacy_cache_ids, legacy_cache_unreadable_ids
                )
            cache_unreadable_ids = (borg2_cache_unreadable_ids | legacy_cache_unreadable_ids) - (
                borg2_cache_ids | legacy_cache_ids
            )
            repo_ids |= borg2_cache_ids | legacy_cache_ids | cache_unreadable_ids

            repos = []
            for repo_id in sorted(repo_ids):
                if repo_id in borg2_ids:
                    location, key_type_raw = borg2_info[repo_id]
                    layout = "borg2"
                    has_security_info = True
                elif repo_id in legacy_ids:
                    location, key_type_raw = legacy_info[repo_id]
                    layout = "legacy"
                    has_security_info = True
                elif repo_id in borg2_cache_ids:
                    location, key_type_raw = None, None
                    layout = "borg2"
                    # discovered only via the cache; security info is confirmed absent only if
                    # this id was not flagged unreadable AND both security roots were fully
                    # searched (see security_fully_searched above).
                    if repo_id in security_unreadable_ids or not security_fully_searched:
                        has_security_info = None
                    else:
                        has_security_info = False
                elif repo_id in legacy_cache_ids:
                    location, key_type_raw = None, None
                    layout = "legacy"
                    if repo_id in security_unreadable_ids or not security_fully_searched:
                        has_security_info = None
                    else:
                        has_security_info = False
                else:
                    location, key_type_raw = None, None
                    layout = None
                    if repo_id in security_unreadable_ids or not security_fully_searched:
                        has_security_info = None
                    else:
                        has_security_info = False

                # fall back to the legacy cache root only when borg2 is confirmed absent -
                # "unreadable" must not be treated as "try the other root" nor as "present".
                used_root_path = cache_root
                if cache_root_d is not None:
                    kind, entry = inspector.open_cache_entry(cache_root_d, repo_id, str(cache_root / repo_id))
                else:
                    kind, entry = cache_root_kind, None
                if kind == "absent" and legacy_cache_root_d is not None:
                    used_root_path = legacy_cache_root
                    kind, entry = inspector.open_cache_entry(
                        legacy_cache_root_d, repo_id, str(legacy_cache_root / repo_id)
                    )
                elif kind == "absent" and legacy_cache_root_kind == "unreadable":
                    # current-root confirmed absent, but the legacy root could not be opened
                    # either - the legacy side was never searched, so this is unknown, not absent.
                    kind = "unreadable"

                # tri-state: True (confirmed present), False (confirmed absent in every root
                # that could be searched), or None (at least one root's state could not be
                # established). This re-examines repo_id's cache state fresh rather than
                # reusing scan_cache_root()'s earlier discovery pass.
                has_cache = {"present": True, "unreadable": None, "absent": False}[kind]
                cache_size = None
                cache_mtime = None
                if has_cache is True:
                    # dir_size closes entry unconditionally; guard only the window before it
                    # starts, where cache_config_mtime could raise first.
                    entry_display = str(used_root_path / repo_id)
                    try:
                        cache_mtime = inspector.cache_config_mtime(entry, entry_display)
                    except BaseException:
                        inspector.close_dir(entry)
                        raise
                    cache_size = inspector.dir_size(entry, entry_display)  # consumes/closes entry; always an int
                elif entry is not None:
                    inspector.close_dir(entry)

                repos.append(
                    {
                        "id": repo_id,
                        "layout": layout,
                        "location": location,
                        "key_type_raw": key_type_raw,
                        "key_type": (KEY_TYPE_LABELS.get(key_type_raw) or key_type_raw) if key_type_raw else None,
                        "has_security_info": has_security_info,
                        "has_cache": has_cache,
                        "cache_size": cache_size if has_cache is True else None,
                        "cache_config_mtime": cache_mtime.isoformat() if has_cache is True and cache_mtime else None,
                    }
                )

        if inspector.incomplete:
            # counts failed inspection operations, not distinct paths (the same path can be
            # probed more than once), so this number can exceed the paths actually affected.
            self.print_warning(
                "known-repos: %d filesystem inspection(s) could not be fully completed; "
                "results may be incomplete - see the warnings above.",
                inspector.incomplete,
            )

        if args.json:
            json_print({"repositories": repos})
            return

        if not repos:
            print("No locally known repositories.")
            return

        for repo in repos:
            print(f"Repository ID: {repo['id']}")
            layout = repo["layout"]
            if layout is None:
                print("  Layout: unknown (could not be determined)")
            else:
                print(f"  Layout: {layout}")
            print(f"  Location: {_printable(repo['location']) if repo['location'] else '(unknown)'}")
            if repo["has_cache"] is True:
                print(f"  Local cache: yes, {format_file_size(repo['cache_size'])}")
                print(f"  Cache last written: {repo['cache_config_mtime'] or '(unknown)'}")
            elif repo["has_cache"] is None:
                print("  Local cache: unknown (could not be determined)")
            else:
                print("  Local cache: no")
            if repo["has_security_info"] is True:
                key_type = repo["key_type"]
                if key_type:
                    print(f"  Security info: yes ({_printable(key_type)})")
                else:
                    print("  Security info: yes (key type unknown)")
            elif repo["has_security_info"] is None:
                print("  Security info: unknown (could not be determined)")
            else:
                print("  Security info: no")
            if repo["has_cache"] is True and repo["has_security_info"] is False:
                print("  Note: a local cache exists, but no security info was found for this repository.")
            print()

    def build_parser_known_repos(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        known_repos_epilog = process_epilog("""
        This command lists the repositories that this local Borg installation currently
        has state for: security information (key type, last known location) and/or a
        local repository cache.

        It inspects only local state - the security directory and the cache directory,
        each checked both at its current (borg2) default location and, separately, at
        the legacy (borg 1.x) default location those same kinds of state used before the
        borg2 base-dir rewrite (see ``$BORG_SECURITY_DIR``/``$BORG_CACHE_DIR`` in
        ``borg help environment`` for the exact resolution rules, including the platforms
        where the two locations differ by default, e.g. macOS). It does not access any
        repository, locally or remotely, so a repository that is currently unreachable
        (e.g. a disconnected external disk or an unresponsive remote host) will still be
        listed just fine. This also means -r/--repo has no effect on this command: it
        always lists every locally known repository.

        "Layout" reflects which state directory tree the repository was discovered in -
        ``borg2`` or ``legacy`` - not the repository's actual on-disk format version (see
        ``borg repo-info``'s "Repository version" for that; this command never opens the
        repository, so it cannot report that field at all). The borg2 security entry is
        checked first, then the legacy (borg 1.x) security entry, then - only when
        neither security entry could be confirmed - whichever cache root matched (borg2
        cache checked before the legacy cache). "unknown" means neither a security entry
        nor a cache entry could be confirmed for this id - it was listed as a directory
        name, but this command could not establish which layout (if either) it belongs
        to. If ``$BORG_SECURITY_DIR``/``$BORG_CACHE_DIR`` make the borg2 and legacy
        locations resolve to the same path, only the borg2 scan runs and a legacy (v1)
        repository there is reported with layout ``borg2``.

        This is useful for auditing which repositories this installation has local state for
        (and, for repository-encrypted modes, which crypto suite each one uses), finding
        repositories with a local cache that may be taking up unwanted disk space, and general
        housekeeping of stale local Borg state.

        The reported cache size is the size of all regular files below the repository's
        cache directory (symlinks are not followed and not counted) - for a current (borg2)
        repository that is the files cache plus a small amount of metadata (``config``,
        ``README``), not an index of the repository's chunks; a legacy (borg 1.x) cache
        directory can be considerably larger, since it also holds a local chunks index.
        A repository-id directory that is a symlink (Borg itself always creates a plain
        directory) is skipped, and a ``location`` or ``key-type`` file that is a symlink
        is treated the same as missing; neither is followed.

        "Cache last written" is the modification time of the cache's own config file, as
        a best-effort proxy for when a cache-using Borg command last ran against this
        repository. It is not a precise "last backup" or "last access" time: not every
        Borg command updates the cache, and a repository without a local cache at all
        will not show one.

        This command does not list or export any key material: the keys dir
        (``$BORG_KEYS_DIR``) is not scanned.

        "Security info" and "Local cache" are each one of three states, not a plain
        yes/no: "yes" (confirmed present - for security info, a ``location`` and/or
        ``key-type`` file was confirmed to exist there, independent of whether its
        *content* could be read; for cache, a real, non-symlinked cache directory with a
        ``config`` file was confirmed to exist), "no" (confirmed absent - this command
        actually searched the relevant location(s) and found nothing there - for the
        cache specifically, the legacy root is only checked once the borg2 cache root is
        confirmed absent for this id, so an unreadable borg2 cache entry reports
        "unknown" rather than falling back to check whether a legacy cache exists), or
        "unknown"
        (this command could not determine which of the above is true - most commonly a
        permission error on the repository-id directory itself, or on one of the files
        inside it). A file that is simply missing (e.g. a repository with only a
        "location" file and no "key-type") does not affect the other field's state (that
        repository still has "Security info: yes"); a security file that exists but
        could not be fully read (a permission error, a file too large, or not valid
        UTF-8) does not change "Security info" away from "yes" either - existence, not
        readability, is what that field reports. A repository-id directory that was found
        during the directory listing but that then could not be opened or classified for
        some other reason - rather than being dropped from the results, as the directory
        listing already proves it exists - is still listed, with "unknown" for whichever
        of "Security info"/"Local cache"/"Layout" could not be established, so a script
        auditing this output never mistakes "could not check" for "confirmed not there".
        For the cache specifically, once a cache directory's own existence is confirmed
        (a real, non-symlinked directory containing a ``config`` file), a later failure
        to fully list its *contents* does not change "Local cache" away from "yes" -
        only the reported size becomes a partial count rather than the exact size. Any
        of these inspection failures is both logged as its own warning and counted
        towards a final summary warning, which (unlike a plain log message) makes this
        command exit with a non-zero return code (usually 1) - including when the
        failure happened while listing a security or cache root itself (e.g. EIO), which
        can keep a repository that exists only there out of the output entirely, with no
        per-repository record to point to. A script checking the exit code therefore
        learns only that the scan was incomplete, not that every affected repository is
        still represented somewhere in the output.
        """)
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_known_repos.__doc__, epilog=known_repos_epilog
        )
        subparsers.add_subcommand("known-repos", subparser, help="list locally known repositories")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
