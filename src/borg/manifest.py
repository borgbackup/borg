import re
from collections import defaultdict, namedtuple
from datetime import datetime
from operator import attrgetter
from collections.abc import Iterator, Sequence
from typing import Protocol, runtime_checkable

from borgstore.store import ObjectNotFound, ItemInfo

from .logger import create_logger

logger = create_logger()

from .constants import *  # NOQA
from .helpers.parseformat import bin_to_hex, hex_to_bin
from .helpers.time import (
    parse_timestamp,
    calculate_relative_offset,
    archive_ts_now,
    compile_date_pattern,
    DatePatternError,
)
from .helpers.errors import Error, CommandError
from .crypto.low_level import IntegrityError as IntegrityErrorBase
from .item import ArchiveItem
from .patterns import get_regex_from_pattern
from .repoobj import RepoObj


# Not raised anymore: the repository feature flags mechanism was removed. The class is kept so that its
# return code stays reserved and never gets a different meaning.
class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of Borg is required to access this repository."""

    exit_mcode = 25


# Not raised anymore: borg 2 repositories have no manifest object (their config is the config/config store
# object). The class is kept so that its return code stays reserved and never gets a different meaning.
class NoManifestError(Error):
    """Repository has no manifest."""

    exit_mcode = 26


ArchiveInfo = namedtuple("ArchiveInfo", "name id ts tags host user", defaults=[(), None, None])

# timestamp is a replacement for ts, archive is an alias for name (see SortBySpec)
AI_HUMAN_SORT_KEYS = ["timestamp", "archive"] + list(ArchiveInfo._fields)
AI_HUMAN_SORT_KEYS.remove("ts")

# archive attributes describing what an archive contains and where it came from, usable to group
# archives that belong together, e.g. for applying retention rules separately (see GroupBySpec).
AI_GROUP_BY_KEYS = ["name", "host", "user", "tags"]


def archive_group_key(archive_info: ArchiveInfo, group_by: Sequence[str]) -> tuple[str, ...]:
    """Compute the grouping key of *archive_info* for the given *group_by* archive attributes."""
    key = []
    for group_by_key in group_by:
        if group_by_key == "tags":
            # internal tags (e.g. @PROT) say nothing about what an archive contains or where it
            # came from, so they must not put an archive into a group of its own.
            value = ",".join(tag for tag in archive_info.tags if not tag.startswith("@"))
        else:
            # host and user are empty for archives that do not have this metadata, e.g. archives
            # transferred from a borg 1.x repo. they form their own group then.
            value = getattr(archive_info, group_by_key) or ""
        key.append(value)
    return tuple(key)


def group_archives(archives: list[ArchiveInfo], group_by: Sequence[str]) -> dict[tuple[str, ...], list[ArchiveInfo]]:
    """
    Group *archives* by the given *group_by* archive attributes, keeping their relative order.

    An empty *group_by* puts all archives into one group.
    """
    groups: dict[tuple[str, ...], list[ArchiveInfo]] = defaultdict(list)
    for archive_info in archives:
        groups[archive_group_key(archive_info, group_by)].append(archive_info)
    return groups


def format_group_key(key: tuple[str, ...], group_by: Sequence[str]) -> str:
    """Format a grouping key for human consumption, e.g. \"name='home', host='myhost'\"."""
    return ", ".join(f"{group_by_key}={value!r}" for group_by_key, value in zip(group_by, key))


def filter_archives_by_date(archives, older=None, newer=None, oldest=None, newest=None):
    def get_first_and_last_archive_ts(archives_list):
        timestamps = [x.ts for x in archives_list]
        return min(timestamps), max(timestamps)

    if not archives:
        return archives

    now = archive_ts_now()
    earliest_ts, latest_ts = get_first_and_last_archive_ts(archives)

    until_ts = calculate_relative_offset(older, now, earlier=True) if older is not None else latest_ts
    from_ts = calculate_relative_offset(newer, now, earlier=True) if newer is not None else earliest_ts
    archives = [x for x in archives if from_ts <= x.ts <= until_ts]

    if not archives:
        return archives

    earliest_ts, latest_ts = get_first_and_last_archive_ts(archives)
    if oldest:
        until_ts = calculate_relative_offset(oldest, earliest_ts, earlier=False)
        archives = [x for x in archives if x.ts <= until_ts]
    if newest:
        from_ts = calculate_relative_offset(newest, latest_ts, earlier=True)
        archives = [x for x in archives if x.ts >= from_ts]

    return archives


@runtime_checkable
class ArchivesInterface(Protocol):  # pragma: no cover
    """
    Structural interface that both Archives and LegacyArchives must satisfy.

    Manifest.__init__ assigns one of these two classes to self.archives depending
    on whether the repository is a LegacyRepository (Borg 1.x) or a modern one.
    All callers go through this interface without knowing which class they got.

    When Borg 1.x support is dropped, delete LegacyArchives and this Protocol
    can either be removed or kept as documentation of the Archives public API.
    """

    def prepare(self, manifest, m) -> None: ...
    def ids(self, *, deleted: bool = False) -> Iterator: ...
    def count(self) -> int: ...
    def names(self) -> Iterator: ...
    def exists(self, name: str) -> bool: ...
    def exists_id(self, id: bytes, *, deleted: bool = False) -> bool: ...
    def exists_name_and_id(self, name: str, id: bytes) -> bool: ...
    def exists_name_and_ts(self, name: str, ts) -> bool: ...
    def get(self, name: str, raw: bool = False): ...
    def get_by_id(self, id: bytes, raw: bool = False, *, deleted: bool = False): ...
    def create(self, name: str, id: bytes, ts, *, overwrite: bool = False) -> None: ...
    def delete_by_id(self, id: bytes) -> None: ...
    def undelete_by_id(self, id: bytes) -> None: ...
    def nuke_by_id(self, id: bytes) -> None: ...
    def list(
        self,
        *,
        match=None,
        match_end=r"\Z",
        sort_by=(),
        reverse=False,
        first=None,
        last=None,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
        deleted=False,
    ): ...
    def list_considering(self, args, *, reverse=False): ...
    def get_one(self, match, *, match_end=r"\Z", deleted=False): ...


class Archives:
    """
    Manage the list of archives for a Borg 2.x repository.

    Each archive has a separate entry in borgstore at archives/<hex-id>.
    """

    def __init__(self, repository, manifest):
        self.repository = repository
        self.manifest = manifest

    def prepare(self, manifest, m):
        pass  # only the legacy borg 1.x manifest has an archives list to load, see LegacyArchives

    def ids(self, *, deleted=False):
        # yield the binary IDs of all archives
        try:
            infos = list(self.repository.store_list("archives", deleted=deleted))
        except ObjectNotFound:
            infos = []
        for info in infos:
            info = ItemInfo(*info)  # RPC does not give us a NamedTuple
            yield hex_to_bin(info.name)

    def _get_archive_meta(self, id: bytes, *, tolerate_read_errors: bool = False) -> dict:
        # get all metadata directly from the ArchiveItem in the repo.
        from .repository import Repository

        try:
            cdata = self.repository.get(id)
        except Repository.StoreReadError:
            # the archive metadata could not be read at all (I/O error, refs #3509). only borg check
            # opts into a placeholder here, so it can go on and check the other archives. everybody
            # else must not act on a repository it can not fully read: the placeholder's 1970
            # timestamp would e.g. make prune treat the archive as the oldest one.
            if not tolerate_read_errors:
                raise
            metadata = dict(
                id=id,
                name="archive-metadata-could-not-be-read",
                time="1970-01-01T00:00:00.000000",
                exists=False,  # we have the pointer, but we could not read the archive item
                username="",
                hostname="",
                tags=(),
            )
        except Repository.ObjectNotFound:
            metadata = dict(
                id=id,
                name="archive-does-not-exist",
                time="1970-01-01T00:00:00.000000",
                exists=False,  # we have the pointer, but the repo does not have an archive item
                username="",
                hostname="",
                tags=(),
            )
        else:
            try:
                _, data = self.manifest.repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)
            except IntegrityErrorBase:
                metadata = dict(
                    id=id,
                    name="archive-metadata-has-integrity-error",
                    time="1970-01-01T00:00:00.000000",
                    exists=False,  # we have the pointer, but the repo does not have an archive item
                    username="",
                    hostname="",
                    tags=(),
                )
            else:
                archive_dict = self.manifest.key.unpack_archive(data)
                archive_item = ArchiveItem(internal_dict=archive_dict)
                if archive_item.version not in (1, 2):  # legacy: still need to read v1 archives
                    raise Exception("Unknown archive metadata version")
                # callers expect a dict with dict["key"] access, not ArchiveItem.key access.
                # also, we need to put the id in there.
                metadata = dict(
                    id=id,
                    name=archive_item.name,
                    time=archive_item.time,
                    exists=True,  # repo has a valid archive item
                    username=archive_item.username,
                    hostname=archive_item.hostname,
                    size=archive_item.get("size", 0),
                    nfiles=archive_item.get("nfiles", 0),
                    comment=archive_item.get("comment", ""),
                    tags=tuple(sorted(getattr(archive_item, "tags", []))),  # must be hashable
                )
        return metadata

    def _infos(self, *, deleted=False, tolerate_read_errors=False):
        # yield the infos of all archives
        for id in self.ids(deleted=deleted):
            yield self._get_archive_meta(id, tolerate_read_errors=tolerate_read_errors)

    def _info_tuples(self, *, deleted=False, tolerate_read_errors=False):
        for info in self._infos(deleted=deleted, tolerate_read_errors=tolerate_read_errors):
            yield ArchiveInfo(
                name=info["name"],
                id=info["id"],
                ts=parse_timestamp(info["time"]),
                tags=info["tags"],
                user=info["username"],
                host=info["hostname"],
            )

    def _matching_info_tuples(self, match_patterns, match_end, *, deleted=False, tolerate_read_errors=False):
        archive_infos = list(self._info_tuples(deleted=deleted, tolerate_read_errors=tolerate_read_errors))
        if match_patterns:
            assert isinstance(match_patterns, list), f"match_pattern is a {type(match_patterns)}"
            for match in match_patterns:
                if match.startswith("aid:"):  # do a match on the archive ID (prefix)
                    wanted_id = match.removeprefix("aid:")
                    archive_infos = [x for x in archive_infos if bin_to_hex(x.id).startswith(wanted_id)]
                    if len(archive_infos) != 1:
                        raise CommandError("archive ID based match needs to match precisely one archive ID")
                elif match.startswith("tags:"):
                    wanted_tags = match.removeprefix("tags:")
                    wanted_tags = [tag for tag in wanted_tags.split(",") if tag]  # remove empty tags
                    archive_infos = [x for x in archive_infos if set(x.tags) >= set(wanted_tags)]
                elif match.startswith("user:"):
                    wanted_user = match.removeprefix("user:")
                    archive_infos = [x for x in archive_infos if x.user == wanted_user]
                elif match.startswith("host:"):
                    wanted_host = match.removeprefix("host:")
                    archive_infos = [x for x in archive_infos if x.host == wanted_host]
                elif match.startswith("date:"):
                    wanted_date = match.removeprefix("date:")
                    try:
                        date_matches = compile_date_pattern(wanted_date)
                    except DatePatternError as exc:
                        raise CommandError(f"Invalid date pattern: {match} ({exc})")
                    archive_infos = [x for x in archive_infos if date_matches(x.ts)]
                else:  #  do a match on the name
                    match = match.removeprefix("name:")  # accept optional name: prefix
                    regex = get_regex_from_pattern(match)
                    regex = re.compile(regex + match_end)
                    archive_infos = [x for x in archive_infos if regex.match(x.name) is not None]
        return archive_infos

    def count(self):
        # return the count of archives in the repo
        return len(list(self.ids()))

    def names(self):
        # yield the names of all archives
        for archive_info in self._infos():
            yield archive_info["name"]

    def exists(self, name):
        # check if an archive with this name exists
        assert isinstance(name, str)
        return name in self.names()

    def exists_id(self, id, *, deleted=False):
        # check if an archive with this id exists
        assert isinstance(id, bytes)
        return id in self.ids(deleted=deleted)

    def exists_name_and_id(self, name, id):
        # check if an archive with this name AND id exists
        assert isinstance(name, str)
        assert isinstance(id, bytes)
        for archive_info in self._infos():
            if archive_info["name"] == name and archive_info["id"] == id:
                return True
        else:
            return False

    def exists_name_and_ts(self, name, ts):
        # check if an archive with this name AND timestamp exists
        assert isinstance(name, str)
        assert isinstance(ts, datetime)
        for archive_info in self._info_tuples():
            if archive_info.name == name and archive_info.ts == ts:
                return True
        else:
            return False

    def _lookup_name(self, name, raw=False):
        assert isinstance(name, str)
        for archive_info in self._infos():
            if archive_info["exists"] and archive_info["name"] == name:
                if not raw:
                    ts = parse_timestamp(archive_info["time"])
                    return ArchiveInfo(
                        name=archive_info["name"],
                        id=archive_info["id"],
                        ts=ts,
                        tags=archive_info["tags"],
                        user=archive_info["username"],
                        host=archive_info["hostname"],
                    )
                else:
                    return archive_info
        else:
            raise KeyError(name)

    def get(self, name, raw=False):
        assert isinstance(name, str)
        try:
            return self._lookup_name(name, raw=raw)
        except KeyError:
            return None

    def get_by_id(self, id, raw=False, *, deleted=False):
        assert isinstance(id, bytes)
        if id in self.ids(deleted=deleted):  # check directory
            # looks like this archive id is in the archives directory, thus it is NOT deleted.
            # OR we have explicitly requested a soft-deleted archive via deleted=True.
            archive_info = self._get_archive_meta(id)
            if archive_info["exists"]:  # True means we have found Archive metadata in the repo.
                if not raw:
                    ts = parse_timestamp(archive_info["time"])
                    archive_info = ArchiveInfo(
                        name=archive_info["name"],
                        id=archive_info["id"],
                        ts=ts,
                        tags=archive_info["tags"],
                        user=archive_info["username"],
                        host=archive_info["hostname"],
                    )
                return archive_info
        return None  # id not in store, or archive metadata blob missing from repo

    def create(self, name, id, ts, *, overwrite=False):
        assert isinstance(name, str)
        assert isinstance(id, bytes)
        if isinstance(ts, datetime):
            ts = ts.isoformat(timespec="microseconds")
        assert isinstance(ts, str)
        # flush buffered packs first: the pointer must not reference objects still sitting in the pack writer.
        self.repository.flush()
        # we only create a directory entry, its name points to the archive item:
        self.repository.store_store(f"archives/{bin_to_hex(id)}", b"")

    def delete_by_id(self, id):
        # soft-delete an archive
        assert isinstance(id, bytes)
        self.repository.store_move(f"archives/{bin_to_hex(id)}", delete=True)  # soft-delete

    def undelete_by_id(self, id):
        # undelete an archive
        assert isinstance(id, bytes)
        self.repository.store_move(f"archives/{bin_to_hex(id)}", undelete=True)

    def nuke_by_id(self, id):
        # really delete an already soft-deleted archive
        assert isinstance(id, bytes)
        self.repository.store_delete(f"archives/{bin_to_hex(id)}", deleted=True)

    def list(
        self,
        *,
        match=None,
        match_end=r"\Z",
        sort_by=(),
        reverse=False,
        first=None,
        last=None,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
        deleted=False,
        tolerate_read_errors=False,
    ):
        """
        Return list of ArchiveInfo instances according to the parameters.

        First match *match* (considering *match_end*), then filter by timestamp considering *older* and *newer*.
        Second, follow with a filter considering *oldest* and *newest*, then sort by the given *sort_by* argument.

        Apply *first* and *last* filters, and then possibly *reverse* the list.

        *sort_by* is a list of sort keys applied in reverse order.
        *newer* and *older* are relative time markers that indicate offset from now.
        *newest* and *oldest* are relative time markers that indicate offset from newest/oldest archive's timestamp.


        Note: for better robustness, all filtering / limiting parameters must default to
              "not limit / not filter", so a FULL archive list is produced by a simple .list().
              some callers EXPECT to iterate over all archives in a repo for correct operation.
        """
        if isinstance(sort_by, (str, bytes)):
            raise TypeError("sort_by must be a sequence of str")

        archive_infos = self._matching_info_tuples(
            match, match_end, deleted=deleted, tolerate_read_errors=tolerate_read_errors
        )

        if any([oldest, newest, older, newer]):
            archive_infos = filter_archives_by_date(
                archive_infos, oldest=oldest, newest=newest, newer=newer, older=older
            )
        for sortkey in reversed(sort_by):
            archive_infos.sort(key=attrgetter(sortkey))
        if first:
            archive_infos = archive_infos[:first]
        elif last:
            archive_infos = archive_infos[max(len(archive_infos) - last, 0) :]
        if reverse:
            archive_infos.reverse()
        return archive_infos

    def list_considering(self, args, *, reverse=False):
        """
        get a list of archives, considering --first/last/prefix/match-archives/sort cmdline args
        """
        name = getattr(args, "name", None)
        if name is not None:
            raise Error(
                "Giving a specific name is incompatible with options --first, --last " "and -a / --match-archives."
            )
        return self.list(
            sort_by=args.sort_by.split(","),
            reverse=reverse,
            match=args.match_archives,
            first=getattr(args, "first", None),
            last=getattr(args, "last", None),
            older=getattr(args, "older", None),
            newer=getattr(args, "newer", None),
            oldest=getattr(args, "oldest", None),
            newest=getattr(args, "newest", None),
            deleted=getattr(args, "deleted", False),
        )

    def get_one(self, match, *, match_end=r"\Z", deleted=False):
        """get exactly one archive matching <match>"""
        assert match is not None
        archive_infos = self._matching_info_tuples(match, match_end, deleted=deleted)
        if len(archive_infos) != 1:
            raise CommandError(f"{match} needed to match precisely one archive, but matched {len(archive_infos)}.")
        return archive_infos[0]


class Manifest:
    """
    The repository's key, RepoObj and archives directory, bundled for the code that works with archives.

    Historically (borg 1.x), the manifest was a repository object holding the archives list and other
    metadata. borg 2 repositories have no manifest object: the archives are in the archives/ namespace
    and the repository config is the config/config store object (see Repository.save_config). This class
    only lives on as the container the archive-level code takes its key, repo_objs, repository and
    archives from. For borg 1.x repositories (read-only, e.g. "borg transfer --from-borg1"), load()
    still reads the manifest object, as it holds their archives list.
    """

    MANIFEST_ID = b"\0" * 32  # legacy: the id of a borg 1.x repository's manifest object

    def __init__(self, key, repository, ro_cls=RepoObj):
        from .legacy.repository import LegacyRepository
        from .legacy.remote import LegacyRemoteRepository
        from .legacy.archives import LegacyArchives

        if isinstance(repository, (LegacyRepository, LegacyRemoteRepository)):
            self.archives: ArchivesInterface = LegacyArchives(repository, self)
        else:
            self.archives: ArchivesInterface = Archives(repository, self)
            repository.set_key(key)  # the key protects the repository's index/ and cache/ store objects
        self.key = key
        self.repo_objs = ro_cls(key)
        self.repository = repository

    @classmethod
    def load(cls, repository, key=None, *, other=False, ro_cls=RepoObj):
        """Return the Manifest of repository, loading its key (see key_factory) if key is not given."""
        from .crypto.key import key_factory  # crypto.key imports this module, hence the local import
        from .legacy.repository import LegacyRepository
        from .legacy.remote import LegacyRemoteRepository

        if isinstance(repository, (LegacyRepository, LegacyRemoteRepository)):
            return cls._load_legacy(repository, key, other=other, ro_cls=ro_cls)
        if not key:
            key = key_factory(repository, other=other)
        return cls(key, repository, ro_cls=ro_cls)

    @classmethod
    def _load_legacy(cls, repository, key, *, other, ro_cls):
        # a borg 1.x repository: its manifest object identifies the key type and holds the archives list.
        from .item import ManifestItem
        from .crypto.key import legacy_key_factory

        cdata = repository.get_manifest()
        if not key:
            key = legacy_key_factory(repository, cdata, other=other)
        manifest = cls(key, repository, ro_cls=ro_cls)
        # borg 1.x objects carry no type in their (non-existent) metadata; RepoObj1.parse ignores ro_type.
        _, data = manifest.repo_objs.parse(cls.MANIFEST_ID, cdata, ro_type=ROBJ_DONTCARE)
        m = ManifestItem(internal_dict=key.unpack_manifest(data))
        if m.get("version") not in (1, 2):
            raise ValueError("Invalid manifest version")
        manifest.archives.prepare(manifest, m)
        return manifest
