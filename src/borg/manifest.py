import enum
import re
from collections import abc, namedtuple
from datetime import datetime, timedelta, timezone
from operator import attrgetter
from collections.abc import Sequence

from .logger import create_logger

logger = create_logger()

from .constants import *  # NOQA
from .helpers.datastruct import StableDict
from .helpers.parseformat import bin_to_hex
from .helpers.time import parse_timestamp, calculate_relative_offset, archive_ts_now
from .helpers.errors import Error
from .patterns import get_regex_from_pattern
from .repoobj import RepoObj


class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of borg is required to access this repository."""

    exit_mcode = 25


class NoManifestError(Error):
    """Repository has no manifest."""

    exit_mcode = 26


ArchiveInfo = namedtuple("ArchiveInfo", "name id ts")

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


class Archives(abc.MutableMapping):
    """
    Nice wrapper around the archives dict, making sure only valid types/values get in
    and we can deal with str keys (and it internally encodes to byte keys) and either
    str timestamps or datetime timestamps.
    """

    def __init__(self):
        # key: str archive name, value: dict('id': bytes_id, 'time': str_iso_ts)
        self._archives = {}

    def __len__(self):
        return len(self._archives)

    def __iter__(self):
        return iter(self._archives)

    def __getitem__(self, name):
        assert isinstance(name, str)
        values = self._archives.get(name)
        if values is None:
            raise KeyError
        ts = parse_timestamp(values["time"])
        return ArchiveInfo(name=name, id=values["id"], ts=ts)

    def __setitem__(self, name, info):
        assert isinstance(name, str)
        assert isinstance(info, tuple)
        id, ts = info
        assert isinstance(id, bytes)
        if isinstance(ts, datetime):
            ts = ts.isoformat(timespec="microseconds")
        assert isinstance(ts, str)
        self._archives[name] = {"id": id, "time": ts}

    def __delitem__(self, name):
        assert isinstance(name, str)
        del self._archives[name]

    def list(
        self,
        *,
        consider_checkpoints=True,
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

        archives = self.values()
        regex = get_regex_from_pattern(match or "re:.*")
        regex = re.compile(regex + match_end)
        archives = [x for x in archives if regex.match(x.name) is not None]

        if any([oldest, newest, older, newer]):
            archives = filter_archives_by_date(archives, oldest=oldest, newest=newest, newer=newer, older=older)
        if not consider_checkpoints:
            archives = [x for x in archives if ".checkpoint" not in x.name]
        for sortkey in reversed(sort_by):
            archives.sort(key=attrgetter(sortkey))
        if first:
            archives = archives[:first]
        elif last:
            archives = archives[max(len(archives) - last, 0) :]
        if reverse:
            archives.reverse()
        return archives

    def list_considering(self, args):
        """
        get a list of archives, considering --first/last/prefix/match-archives/sort/consider-checkpoints cmdline args
        """
        name = getattr(args, "name", None)
        consider_checkpoints = getattr(args, "consider_checkpoints", None)
        if name is not None:
            raise Error(
                "Giving a specific name is incompatible with options --first, --last, "
                "-a / --match-archives, and --consider-checkpoints."
            )
        return self.list(
            sort_by=args.sort_by.split(","),
            consider_checkpoints=consider_checkpoints,
            match=args.match_archives,
            first=getattr(args, "first", None),
            last=getattr(args, "last", None),
            older=getattr(args, "older", None),
            newer=getattr(args, "newer", None),
            oldest=getattr(args, "oldest", None),
            newest=getattr(args, "newest", None),
        )

    def set_raw_dict(self, d):
        """set the dict we get from the msgpack unpacker"""
        for k, v in d.items():
            assert isinstance(k, str)
            assert isinstance(v, dict) and "id" in v and "time" in v
            self._archives[k] = v

    def get_raw_dict(self):
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
        self.archives = Archives()
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
    def load(cls, repository, operations, key=None, *, ro_cls=RepoObj):
        from .item import ManifestItem
        from .crypto.key import key_factory
        from .repository import Repository

        try:
            cdata = repository.get(cls.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError
        if not key:
            key = key_factory(repository, cdata, ro_cls=ro_cls)
        manifest = cls(key, repository, ro_cls=ro_cls)
        _, data = manifest.repo_objs.parse(cls.MANIFEST_ID, cdata, ro_type=ROBJ_MANIFEST)
        manifest_dict = key.unpack_manifest(data)
        m = ManifestItem(internal_dict=manifest_dict)
        manifest.id = manifest.repo_objs.id_hash(data)
        if m.get("version") not in (1, 2):
            raise ValueError("Invalid manifest version")
        manifest.archives.set_raw_dict(m.archives)
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
        assert len(self.archives) <= MAX_ARCHIVES
        assert all(len(name) <= 255 for name in self.archives)
        assert len(self.item_keys) <= 100
        self.config["item_keys"] = tuple(sorted(self.item_keys))
        manifest = ManifestItem(
            version=2,
            archives=StableDict(self.archives.get_raw_dict()),
            timestamp=self.timestamp,
            config=StableDict(self.config),
        )
        data = self.key.pack_metadata(manifest.as_dict())
        self.id = self.repo_objs.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.repo_objs.format(self.MANIFEST_ID, {}, data, ro_type=ROBJ_MANIFEST))
