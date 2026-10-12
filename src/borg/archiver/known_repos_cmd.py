import os
import re
import stat
from configparser import ConfigParser, Error as ConfigParserError
from pathlib import Path

from ..crypto.key import LEGACY_KEY_TYPES, AVAILABLE_KEY_TYPES, KEYFILE_ID
from ..helpers import format_file_size, json_print, get_security_dir, get_cache_dir, get_keys_dir
from ..helpers import safe_timestamp, OutputTimestamp
from ..helpers.argparsing import ArgumentParser
from ..legacy.fs import get_cache_dir as get_cache_dir_legacy
from ..legacy.fs import get_security_dir as get_security_dir_legacy
from ..legacy.fs import get_keys_dir as get_keys_dir_legacy

from ..logger import create_logger

logger = create_logger()

REPO_ID_RE = re.compile(r"^[0-9a-f]{64}\Z")


def _printable(s):
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in s)


def _build_key_type_labels():
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


KEY_TYPE_LABELS = _build_key_type_labels()


class _Scanner:
    def __init__(self):
        self.incomplete = False

    def warn(self, msg, *args):
        self.incomplete = True
        logger.warning(msg, *(_printable(str(a)) if isinstance(a, (str, OSError)) else a for a in args))

    def _list_dir(self, root):
        """List root's direct children, or [] if it does not exist - an OSError beyond that
        (e.g. a configured root that is not actually a directory, EACCES, EIO) is warned on
        and also counted via warn().
        """
        try:
            return list(root.iterdir())
        except FileNotFoundError:
            return []
        except OSError as exc:
            self.warn("known-repos: could not list %s, results may be incomplete: %s", root, exc)
            return []

    def repo_id_dirs(self, root):
        for entry in self._list_dir(root):
            if REPO_ID_RE.match(entry.name) and self._is_dir(entry):
                yield entry.name, entry

    def _stat(self, path):
        """Symlink-following stat(), or None if the path does not exist - an OSError beyond
        that (e.g. EACCES, EIO) is warned on and also counted via warn().
        """
        try:
            return path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            self.warn("known-repos: could not check %s: %s", path, exc)
            return None

    def _is_dir(self, path):
        st = self._stat(path)
        return st is not None and stat.S_ISDIR(st.st_mode)

    def is_real_file(self, path):
        st = self._stat(path)
        return st is not None and stat.S_ISREG(st.st_mode)

    def marker_exists(self, path):
        """True if the marker is confirmed present, False otherwise - including on a
        filesystem error, which is already warned on and counted via self._stat().
        """
        return self._stat(path) is not None

    def read_text(self, path):
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            self.warn("known-repos: could not read %s: %s", path, exc)
            return None
        except UnicodeDecodeError as exc:
            self.warn("known-repos: %s is not valid UTF-8, ignoring its content: %s", path, exc)
            return None

    def read_first_line(self, path, max_size=128):
        """Read only the first max_size bytes of a (possibly large) file and return the line
        up to the first newline within them - used for key files, so most of a key file's
        content (the encrypted key material after the header) is never read. The header
        itself ("BORG_KEY <repoid>", 73 bytes) always fits within max_size, so this never
        needs to read past it in practice.
        """
        try:
            with open(path, "rb") as fd:
                chunk = fd.read(max_size)
        except FileNotFoundError:
            return None
        except OSError as exc:
            self.warn("known-repos: could not read %s: %s", path, exc)
            return None
        line = chunk.split(b"\n", 1)[0]
        try:
            return line.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def plain_files(self, root):
        """Yield (name, path) for every regular file directly under root."""
        for entry in self._list_dir(root):
            if self.is_real_file(entry):
                yield entry.name, entry

    def mtime(self, path):
        st = self._stat(path)
        return OutputTimestamp(safe_timestamp(st.st_mtime_ns)) if st is not None else None

    def dir_size(self, path):
        total = 0
        for dirpath, dirnames, filenames in os.walk(path, onerror=self._walk_error):
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    total += os.path.getsize(fpath)
                except OSError as exc:
                    self.warn("known-repos: could not check %s, reported cache size may be incomplete: %s", fpath, exc)
        return total

    def _walk_error(self, exc):
        self.warn("known-repos: could not list %s, reported cache size may be incomplete: %s", exc.filename, exc)


def _scan_security_root(scanner, root):
    info = {}
    for repo_id, entry in scanner.repo_id_dirs(root):
        location_path = entry / "location"
        key_type_path = entry / "key-type"
        has_location = scanner.is_real_file(location_path)
        has_key_type = scanner.is_real_file(key_type_path)
        if not (has_location or has_key_type):
            continue
        location = scanner.read_text(location_path) if has_location else None
        key_type_raw = scanner.read_text(key_type_path) if has_key_type else None
        info[repo_id] = (location or None, (key_type_raw.strip() or None) if key_type_raw else None)
    return info


def _scan_cache_root(scanner, root):
    return {repo_id: entry for repo_id, entry in scanner.repo_id_dirs(root) if scanner.is_real_file(entry / "config")}


def _scan_keys_dir(scanner, root):
    """Map repo_id -> set of key file paths, by reading only the first 128 bytes of each file
    (enough to cover the "BORG_KEY <repoid>" header, never the bulk of the encrypted key
    material that follows it). A key file's name is a hash of its own content, not the repo
    id, so this has to open every file in the directory - unlike the security/cache dirs,
    which name their subdirectories after the repo id.
    """
    info = {}
    for _name, path in scanner.plain_files(root):
        header = scanner.read_first_line(path)
        if not header or not header.startswith(f"{KEYFILE_ID} "):
            continue
        repo_id = header[len(KEYFILE_ID) + 1 :].strip()
        if not REPO_ID_RE.match(repo_id):
            continue
        info.setdefault(repo_id, set()).add(path)
    return info


def _cache_layout(scanner, cache_entry):
    """ "legacy" if the cache entry has a borg 1.x marker ("chunks.archive.d" or a "chunks"
    file), else "borg2". A marker that could not be confirmed due to a filesystem error is
    treated the same as absent (the error is already warned on by marker_exists()).
    """
    if scanner.marker_exists(cache_entry / "chunks.archive.d"):
        return "legacy"
    return "legacy" if scanner.marker_exists(cache_entry / "chunks") else "borg2"


def _cache_previous_location(scanner, cache_entry):
    config_text = scanner.read_text(cache_entry / "config")
    if not config_text:
        return None
    parser = ConfigParser(interpolation=None)
    try:
        parser.read_string(config_text)
        return parser.get("cache", "previous_location", fallback=None) or None
    except ConfigParserError as exc:
        scanner.warn("known-repos: could not parse %s: %s", cache_entry / "config", exc)
        return None


class KnownReposMixIn:
    def do_known_repos(self, args):
        """List repositories Borg has local state for (security info and/or cache)."""
        scanner = _Scanner()

        security_root = Path(get_security_dir(create=False))
        legacy_security_root = Path(get_security_dir_legacy(create=False))
        cache_root = Path(get_cache_dir(create=False))
        legacy_cache_root = Path(get_cache_dir_legacy(create=False))
        keys_root = Path(get_keys_dir(create=False))
        legacy_keys_root = Path(get_keys_dir_legacy(create=False))

        security_roots_coincide = legacy_security_root == security_root
        cache_roots_coincide = legacy_cache_root == cache_root
        keys_roots_coincide = legacy_keys_root == keys_root

        borg2_security = _scan_security_root(scanner, security_root)
        legacy_security = {} if security_roots_coincide else _scan_security_root(scanner, legacy_security_root)

        borg2_cache = _scan_cache_root(scanner, cache_root)
        legacy_cache = {} if cache_roots_coincide else _scan_cache_root(scanner, legacy_cache_root)
        legacy_cache = {k: v for k, v in legacy_cache.items() if k not in borg2_cache}

        keys = _scan_keys_dir(scanner, keys_root)
        if not keys_roots_coincide:
            for repo_id, paths in _scan_keys_dir(scanner, legacy_keys_root).items():
                keys.setdefault(repo_id, set()).update(paths)

        repo_ids = set(borg2_security) | set(legacy_security) | set(borg2_cache) | set(legacy_cache) | set(keys)

        repos = []
        for repo_id in sorted(repo_ids):
            if repo_id in borg2_security:
                location, key_type_raw = borg2_security[repo_id]
                has_security_info = True
                # location/key-type filenames are the same for borg1 and borg2, so a shared
                # root cannot tell them apart - defer to the cache-based check below.
                layout = None if security_roots_coincide else "borg2"
            elif repo_id in legacy_security:
                location, key_type_raw = legacy_security[repo_id]
                layout = "legacy"
                has_security_info = True
            else:
                location, key_type_raw = None, None
                layout = None
                has_security_info = False

            cache_entry = borg2_cache.get(repo_id) or legacy_cache.get(repo_id)
            has_cache = cache_entry is not None
            cache_size = None
            cache_mtime = None
            location_mismatch = False
            if has_cache:
                cache_size = scanner.dir_size(cache_entry)
                cache_mtime = scanner.mtime(cache_entry / "config")
                if layout is None:
                    if cache_roots_coincide:
                        layout = _cache_layout(scanner, cache_entry)
                    else:
                        layout = "legacy" if repo_id in legacy_cache else "borg2"
                if layout == "legacy":
                    cache_location = _cache_previous_location(scanner, cache_entry)
                    if location is None:
                        location = cache_location
                    else:
                        location_mismatch = cache_location is not None and cache_location != location

            repos.append(
                {
                    "id": repo_id,
                    "layout": layout,
                    "location": location,
                    "key_type": (
                        (KEY_TYPE_LABELS.get(key_type_raw) or f"unknown key type {key_type_raw}")
                        if key_type_raw
                        else None
                    ),
                    "has_security_info": has_security_info,
                    "has_cache": has_cache,
                    "cache_size": cache_size,
                    "cache_config_mtime": cache_mtime.isoformat() if cache_mtime else None,
                    "key_file_count": len(keys.get(repo_id, ())),
                    "location_mismatch": location_mismatch,
                }
            )

        if scanner.incomplete:
            self.print_warning(
                "known-repos: some filesystem inspections could not be completed; "
                "results may be incomplete - see the warnings above."
            )

        if args.json:
            json_print({"repositories": repos})
            return

        if not repos:
            print("No locally known repositories.")
            return

        headers = ("Repository ID", "Layout", "Cache", "Security", "Key files", "Last written")
        rows = []
        for repo in repos:
            security = "no"
            if repo["has_security_info"]:
                security = _printable(repo["key_type"]) if repo["key_type"] else "yes (key type unknown)"
            location = _printable(repo["location"]) if repo["location"] else "(unknown)"
            if repo["location_mismatch"]:
                location += " (!= cache's last location)"
            rows.append(
                (
                    repo["id"][:15] + "..",
                    repo["layout"] or "unknown",
                    format_file_size(repo["cache_size"]) if repo["has_cache"] else "-",
                    security,
                    str(repo["key_file_count"]) if repo["key_file_count"] else "-",
                    repo["cache_config_mtime"][:19] if repo["cache_config_mtime"] else "-",
                    location,
                )
            )

        widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
        print("".join(f"{h:<{w}} " for h, w in zip(headers, widths)) + "Location")
        for row in rows:
            print("".join(f"{col:<{w}} " for col, w in zip(row[:-1], widths)) + row[-1])

    def build_parser_known_repos(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        known_repos_epilog = process_epilog("""
        Lists the repositories this local Borg installation currently has state for -
        security info (key type, last known location), a local repository cache, and/or key
        files - without accessing any repository itself (-r/--repo has no effect). "Layout"
        is which state was found in (not the on-disk repository format, see "borg repo-info"
        for that); "Last written" is the cache config's mtime, a best-effort last-used proxy,
        not an exact timestamp and not a staleness check on its own; a mismatch between a
        legacy repo's known location and its cache's last location is flagged; a key file's
        presence does not by itself mean the repository is still openable. Use --json for a
        machine-readable version, including the full repository id.
        """)
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_known_repos.__doc__, epilog=known_repos_epilog
        )
        subparsers.add_subcommand("known-repos", subparser, help="list locally known repositories")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
