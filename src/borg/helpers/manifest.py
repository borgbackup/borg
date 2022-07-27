import enum
import os
import os.path
import re
from collections import abc, namedtuple
from datetime import datetime, timedelta
from operator import attrgetter
from typing import Sequence, FrozenSet

from .errors import Error

from ..logger import create_logger

logger = create_logger()

from .datastruct import StableDict
from .parseformat import bin_to_hex
from .time import parse_timestamp
from .. import shellpattern
from ..constants import *  # NOQA


class NoManifestError(Error):
    """Repository has no manifest."""


class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of borg is required to access this repository."""


ArchiveInfo = namedtuple("ArchiveInfo", "name id ts")

AI_HUMAN_SORT_KEYS = ["timestamp"] + list(ArchiveInfo._fields)
AI_HUMAN_SORT_KEYS.remove("ts")


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
            ts = ts.replace(tzinfo=None).strftime(ISO_FORMAT)
        assert isinstance(ts, str)
        self._archives[name] = {"id": id, "time": ts}

    def __delitem__(self, name):
        assert isinstance(name, str)
        del self._archives[name]

    def list(
        self, *, glob=None, match_end=r"\Z", sort_by=(), consider_checkpoints=True, first=None, last=None, reverse=False
    ):
        """
        Return list of ArchiveInfo instances according to the parameters.

        First match *glob* (considering *match_end*), then *sort_by*.
        Apply *first* and *last* filters, and then possibly *reverse* the list.

        *sort_by* is a list of sort keys applied in reverse order.

        Note: for better robustness, all filtering / limiting parameters must default to
              "not limit / not filter", so a FULL archive list is produced by a simple .list().
              some callers EXPECT to iterate over all archives in a repo for correct operation.
        """
        if isinstance(sort_by, (str, bytes)):
            raise TypeError("sort_by must be a sequence of str")
        regex = re.compile(shellpattern.translate(glob or "*", match_end=match_end))
        archives = [x for x in self.values() if regex.match(x.name) is not None]
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
        get a list of archives, considering --first/last/prefix/glob-archives/sort/consider-checkpoints cmdline args
        """
        name = getattr(args, "name", None)
        consider_checkpoints = getattr(args, "consider_checkpoints", None)
        if name is not None:
            raise Error(
                "Giving a specific name is incompatible with options --first, --last, -a / --glob-archives, and --consider-checkpoints."
            )
        return self.list(
            sort_by=args.sort_by.split(","),
            consider_checkpoints=consider_checkpoints,
            glob=args.glob_archives,
            first=args.first,
            last=args.last,
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
        # tradeofs of locking version out or still allowing access. As all older versions and their exact
        # behaviours are known when introducing new features sometimes this might not match the general descriptions
        # below.

        # The READ operation describes which features are needed to safely list and extract the archives in the
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

    SUPPORTED_REPO_FEATURES: FrozenSet[str] = frozenset([])

    MANIFEST_ID = b"\0" * 32

    def __init__(self, key, repository, item_keys=None):
        self.archives = Archives()
        self.config = {}
        self.key = key
        self.repository = repository
        self.item_keys = frozenset(item_keys) if item_keys is not None else ITEM_KEYS
        self.tam_verified = False
        self.timestamp = None

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    @property
    def last_timestamp(self):
        return parse_timestamp(self.timestamp, tzinfo=None)

    @classmethod
    def load(cls, repository, operations, key=None, force_tam_not_required=False):
        from ..item import ManifestItem
        from ..crypto.key import key_factory, tam_required_file, tam_required
        from ..repository import Repository

        try:
            cdata = repository.get(cls.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError
        if not key:
            key = key_factory(repository, cdata)
        manifest = cls(key, repository)
        data = key.decrypt(cls.MANIFEST_ID, cdata)
        manifest_dict, manifest.tam_verified = key.unpack_and_verify_manifest(
            data, force_tam_not_required=force_tam_not_required
        )
        m = ManifestItem(internal_dict=manifest_dict)
        manifest.id = key.id_hash(data)
        if m.get("version") not in (1, 2):
            raise ValueError("Invalid manifest version")
        manifest.archives.set_raw_dict(m.archives)
        manifest.timestamp = m.get("timestamp")
        manifest.config = m.config
        # valid item keys are whatever is known in the repo or every key we know
        manifest.item_keys = ITEM_KEYS | frozenset(m.get("item_keys", []))

        if manifest.tam_verified:
            manifest_required = manifest.config.get("tam_required", False)
            security_required = tam_required(repository)
            if manifest_required and not security_required:
                logger.debug("Manifest is TAM verified and says TAM is required, updating security database...")
                file = tam_required_file(repository)
                open(file, "w").close()
            if not manifest_required and security_required:
                logger.debug("Manifest is TAM verified and says TAM is *not* required, updating security database...")
                os.unlink(tam_required_file(repository))
        manifest.check_repository_compatibility(operations)
        return manifest, key

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
        from ..item import ManifestItem

        if self.key.tam_required:
            self.config["tam_required"] = True
        # self.timestamp needs to be strictly monotonically increasing. Clocks often are not set correctly
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().strftime(ISO_FORMAT)
        else:
            prev_ts = self.last_timestamp
            incremented = (prev_ts + timedelta(microseconds=1)).strftime(ISO_FORMAT)
            self.timestamp = max(incremented, datetime.utcnow().strftime(ISO_FORMAT))
        # include checks for limits as enforced by limited unpacker (used by load())
        assert len(self.archives) <= MAX_ARCHIVES
        assert all(len(name) <= 255 for name in self.archives)
        assert len(self.item_keys) <= 100
        manifest = ManifestItem(
            version=1,
            archives=StableDict(self.archives.get_raw_dict()),
            timestamp=self.timestamp,
            config=StableDict(self.config),
            item_keys=tuple(sorted(self.item_keys)),
        )
        self.tam_verified = True
        data = self.key.pack_and_authenticate_metadata(manifest.as_dict())
        self.id = self.key.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(self.MANIFEST_ID, data))
