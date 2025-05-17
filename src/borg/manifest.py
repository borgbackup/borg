import enum
import re
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from operator import attrgetter
from collections.abc import Sequence

from borgstore.store import ObjectNotFound, ItemInfo

from .logger import create_logger

logger = create_logger()

from .constants import *  # NOQA
from .helpers.datastruct import StableDict
from .helpers.parseformat import bin_to_hex, hex_to_bin
from .helpers.time import parse_timestamp, calculate_relative_offset, archive_ts_now
from .helpers.errors import Error, CommandError
from .item import ArchiveItem
from .patterns import get_regex_from_pattern
from .repoobj import RepoObj


class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of borg is required to access this repository."""

    exit_mcode = 25


class NoManifestError(Error):
    """Repository has no manifest."""

    exit_mcode = 26


ArchiveInfo = namedtuple("ArchiveInfo", "name id ts tags host user", defaults=[(), None, None])

# timestamp is a replacement for ts, archive is an alias for name (see SortBySpec)
AI_HUMAN_SORT_KEYS = ["timestamp", "archive"] + list(ArchiveInfo._fields)
AI_HUMAN_SORT_KEYS.remove("ts")


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


class Archives:
    """
    Manage the list of archives.

    We still need to support the borg 1.x manifest-with-list-of-archives,
    so borg transfer can work.
    borg2 has separate items archives/* in the borgstore.
    """

    def __init__(self, repository, manifest):
        from .repository import Repository
        from .remote import RemoteRepository

        self.repository = repository
        self.legacy = not isinstance(repository, (Repository, RemoteRepository))
        # key: str archive name, value: dict('id': bytes_id, 'time': str_iso_ts)
        self._archives = {}
        self.manifest = manifest

    def prepare(self, manifest, m):
        if not self.legacy:
            pass
        else:
            self._set_raw_dict(m.archives)

    def finish(self, manifest):
        if not self.legacy:
            manifest_archives = {}
        else:
            manifest_archives = StableDict(self._get_raw_dict())
        return manifest_archives

    def ids(self, *, deleted=False):
        # yield the binary IDs of all archives
        if not self.legacy:
            try:
                infos = list(self.repository.store_list("archives", deleted=deleted))
            except ObjectNotFound:
                infos = []
            for info in infos:
                info = ItemInfo(*info)  # RPC does not give us a NamedTuple
                yield hex_to_bin(info.name)
        else:
            for archive_info in self._archives.values():
                yield archive_info["id"]

    def _get_archive_meta(self, id: bytes) -> dict:
        # get all metadata directly from the ArchiveItem in the repo.
        from .legacyrepository import LegacyRepository
        from .repository import Repository

        try:
            cdata = self.repository.get(id)
        except (Repository.ObjectNotFound, LegacyRepository.ObjectNotFound):
            metadata = dict(
                id=id,
                name="archive-does-not-exist",
                time="1970-01-01T00:00:00.000000",
                # new:
                exists=False,  # we have the pointer, but the repo does not have an archive item
                username="",
                hostname="",
                tags=(),
            )
        else:
            _, data = self.manifest.repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)
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
                # new:
                exists=True,  # repo has a valid archive item
                username=archive_item.username,
                hostname=archive_item.hostname,
                size=archive_item.get("size", 0),
                nfiles=archive_item.get("nfiles", 0),
                comment=archive_item.comment,  # not always present?
                tags=tuple(sorted(getattr(archive_item, "tags", []))),  # must be hashable
            )
        return metadata

    def _infos(self, *, deleted=False):
        # yield the infos of all archives
        for id in self.ids(deleted=deleted):
            yield self._get_archive_meta(id)

    def _info_tuples(self, *, deleted=False):
        for info in self._infos(deleted=deleted):
            yield ArchiveInfo(
                name=info["name"],
                id=info["id"],
                ts=parse_timestamp(info["time"]),
                tags=info["tags"],
                user=info["username"],
                host=info["hostname"],
            )

    def _matching_info_tuples(self, match_patterns, match_end, *, deleted=False):
        archive_infos = list(self._info_tuples(deleted=deleted))
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
        if not self.legacy:
            return name in self.names()
        else:
            return name in self._archives

    def exists_id(self, id, *, deleted=False):
        # check if an archive with this id exists
        assert isinstance(id, bytes)
        if not self.legacy:
            return id in self.ids(deleted=deleted)
        else:
            raise NotImplementedError

    def exists_name_and_id(self, name, id):
        # check if an archive with this name AND id exists
        assert isinstance(name, str)
        assert isinstance(id, bytes)
        if not self.legacy:
            for archive_info in self._infos():
                if archive_info["name"] == name and archive_info["id"] == id:
                    return True
            else:
                return False
        else:
            raise NotImplementedError

    def exists_name_and_ts(self, name, ts):
        # check if an archive with this name AND timestamp exists
        assert isinstance(name, str)
        assert isinstance(ts, datetime)
        if not self.legacy:
            for archive_info in self._info_tuples():
                if archive_info.name == name and archive_info.ts == ts:
                    return True
            else:
                return False
        else:
            raise NotImplementedError

    def _lookup_name(self, name, raw=False):
        assert isinstance(name, str)
        assert not self.legacy
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
        if not self.legacy:
            try:
                return self._lookup_name(name, raw=raw)
            except KeyError:
                return None
        else:
            values = self._archives.get(name)
            if values is None:
                return None
            if not raw:
                ts = parse_timestamp(values["time"])
                return ArchiveInfo(name=name, id=values["id"], ts=ts)
            else:
                return dict(name=name, id=values["id"], time=values["time"])

    def get_by_id(self, id, raw=False, *, deleted=False):
        assert isinstance(id, bytes)
        if not self.legacy:
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
        else:
            for name, values in self._archives.items():
                if id == values["id"]:
                    break
            else:
                return None
            if not raw:
                ts = parse_timestamp(values["time"])
                return ArchiveInfo(name=name, id=values["id"], ts=ts)
            else:
                return dict(name=name, id=values["id"], time=values["time"])

    def create(self, name, id, ts, *, overwrite=False):
        assert isinstance(name, str)
        assert isinstance(id, bytes)
        if isinstance(ts, datetime):
            ts = ts.isoformat(timespec="microseconds")
        assert isinstance(ts, str)
        if not self.legacy:
            # we only create a directory entry, its name points to the archive item:
            self.repository.store_store(f"archives/{bin_to_hex(id)}", b"")
        else:
            if self.exists(name) and not overwrite:
                raise KeyError("archive already exists")
            self._archives[name] = {"id": id, "time": ts}

    def delete_by_id(self, id):
        # soft-delete an archive
        assert isinstance(id, bytes)
        assert not self.legacy
        self.repository.store_move(f"archives/{bin_to_hex(id)}", delete=True)  # soft-delete

    def undelete_by_id(self, id):
        # undelete an archive
        assert isinstance(id, bytes)
        assert not self.legacy
        self.repository.store_move(f"archives/{bin_to_hex(id)}", undelete=True)

    def nuke_by_id(self, id):
        # really delete an already soft-deleted archive
        assert isinstance(id, bytes)
        assert not self.legacy
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

        archive_infos = self._matching_info_tuples(match, match_end, deleted=deleted)

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

    def list_considering(self, args):
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

    def _set_raw_dict(self, d):
        """set the dict we get from the msgpack unpacker"""
        for k, v in d.items():
            assert isinstance(k, str)
            assert isinstance(v, dict) and "id" in v and "time" in v
            self._archives[k] = v

    def _get_raw_dict(self):
        """get the dict we can give to the msgpack packer"""
        return self._archives


class Manifest:
    @enum.unique
    class Operation(enum.Enum):
        # The comments here only roughly describe the scope of each feature. In the end, additions need to be
        # based on potential problems older clients could produce when accessing newer repositories and the
        # trade-offs of locking version out or still allowing access. As all older versions and their exact
        # behaviours are known when introducing new features sometimes this might not match the general descriptions
        # below.

        # The READ operation describes which features are needed to list and extract the archives safely in the
        # repository.
        READ = "read"
        # The CHECK operation is for all operations that need either to understand every detail
        # of the repository (for consistency checks and repairs) or are seldom used functions that just
        # should use the most restrictive feature set because more fine grained compatibility tracking is
        # not needed.
        CHECK = "check"
        # The WRITE operation is for adding archives. Features here ensure that older clients don't add archives
        # in an old format, or is used to lock out clients that for other reasons can no longer safely add new
        # archives.
        WRITE = "write"
        # The DELETE operation is for all operations (like archive deletion) that need a 100% correct reference
        # count and the need to be able to find all (directly and indirectly) referenced chunks of a given archive.
        DELETE = "delete"

    NO_OPERATION_CHECK: Sequence[Operation] = tuple()

    SUPPORTED_REPO_FEATURES: frozenset[str] = frozenset([])

    MANIFEST_ID = b"\0" * 32

    def __init__(self, key, repository, item_keys=None, ro_cls=RepoObj):
        self.archives = Archives(repository, self)
        self.config = {}
        self.key = key
        self.repo_objs = ro_cls(key)
        self.repository = repository
        self.item_keys = frozenset(item_keys) if item_keys is not None else ITEM_KEYS
        self.timestamp = None

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    @property
    def last_timestamp(self):
        return parse_timestamp(self.timestamp)

    @classmethod
    def load(cls, repository, operations, key=None, *, other=False, ro_cls=RepoObj):
        from .item import ManifestItem
        from .crypto.key import key_factory

        cdata = repository.get_manifest()
        if not key:
            key = key_factory(repository, cdata, other=other, ro_cls=ro_cls)
        manifest = cls(key, repository, ro_cls=ro_cls)
        _, data = manifest.repo_objs.parse(cls.MANIFEST_ID, cdata, ro_type=ROBJ_MANIFEST)
        manifest_dict = key.unpack_manifest(data)
        m = ManifestItem(internal_dict=manifest_dict)
        manifest.id = manifest.repo_objs.id_hash(data)
        if m.get("version") not in (1, 2):
            raise ValueError("Invalid manifest version")
        manifest.archives.prepare(manifest, m)
        manifest.timestamp = m.get("timestamp")
        manifest.config = m.config
        # valid item keys are whatever is known in the repo or every key we know
        manifest.item_keys = ITEM_KEYS
        manifest.item_keys |= frozenset(m.config.get("item_keys", []))  # new location of item_keys since borg2
        manifest.item_keys |= frozenset(m.get("item_keys", []))  # legacy: borg 1.x: item_keys not in config yet
        manifest.check_repository_compatibility(operations)
        return manifest

    def check_repository_compatibility(self, operations):
        for operation in operations:
            assert isinstance(operation, self.Operation)
            feature_flags = self.config.get("feature_flags", None)
            if feature_flags is None:
                return
            if operation.value not in feature_flags:
                continue
            requirements = feature_flags[operation.value]
            if "mandatory" in requirements:
                unsupported = set(requirements["mandatory"]) - self.SUPPORTED_REPO_FEATURES
                if unsupported:
                    raise MandatoryFeatureUnsupported(list(unsupported))

    def get_all_mandatory_features(self):
        result = {}
        feature_flags = self.config.get("feature_flags", None)
        if feature_flags is None:
            return result

        for operation, requirements in feature_flags.items():
            if "mandatory" in requirements:
                result[operation] = set(requirements["mandatory"])
        return result

    def write(self):
        from .item import ManifestItem

        # self.timestamp needs to be strictly monotonically increasing. Clocks often are not set correctly
        if self.timestamp is None:
            self.timestamp = datetime.now(tz=timezone.utc).isoformat(timespec="microseconds")
        else:
            incremented_ts = self.last_timestamp + timedelta(microseconds=1)
            now_ts = datetime.now(tz=timezone.utc)
            max_ts = max(incremented_ts, now_ts)
            self.timestamp = max_ts.isoformat(timespec="microseconds")
        # include checks for limits as enforced by limited unpacker (used by load())
        assert self.archives.count() <= MAX_ARCHIVES
        assert len(self.item_keys) <= 100
        self.config["item_keys"] = tuple(sorted(self.item_keys))
        manifest_archives = self.archives.finish(self)
        manifest = ManifestItem(
            version=2, archives=manifest_archives, timestamp=self.timestamp, config=StableDict(self.config)
        )
        data = self.key.pack_metadata(manifest.as_dict())
        self.id = self.repo_objs.id_hash(data)
        robj = self.repo_objs.format(self.MANIFEST_ID, {}, data, ro_type=ROBJ_MANIFEST)
        self.repository.put_manifest(robj)
