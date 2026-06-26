"""Legacy archive list management for Borg 1.x repositories.

In Borg 1.x the list of archives is embedded directly in the manifest blob
as a dict {name: {"id": bytes, "time": str}}.  This class manages that dict.
Used by ``borg transfer --from-borg1``.

This module can be removed entirely when Borg 1.x support is dropped.
"""

import re
from datetime import datetime
from operator import attrgetter

from ..constants import *  # NOQA
from ..helpers.datastruct import StableDict
from ..helpers.errors import CommandError, Error
from ..helpers.parseformat import bin_to_hex
from ..helpers.time import parse_timestamp
from ..item import ArchiveItem
from ..patterns import get_regex_from_pattern

# ArchiveInfo and filter_archives_by_date are imported from ..manifest below.
# These module-level imports are safe because legacy/archives.py is only ever
# imported from inside Manifest.__init__ — by that point manifest.py is fully
# loaded and present in sys.modules.
from ..manifest import ArchiveInfo, filter_archives_by_date


class LegacyArchives:
    """
    Manage the list of archives for a Borg 1.x repository.

    The archive registry lives inside the manifest blob itself:
        {name: {"id": <bytes>, "time": <iso-timestamp-str>}}

    Manifest.__init__ chooses this class over Archives when the repository is a
    LegacyRepository.  It can be deleted entirely when Borg 1.x support is dropped.
    """

    def __init__(self, repository, manifest):
        self.repository = repository
        self.manifest = manifest
        # key: str archive name, value: dict("id": bytes_id, "time": str_iso_ts)
        self._archives = {}

    def prepare(self, manifest, m):
        self._set_raw_dict(m.archives)

    def finish(self, manifest):
        return StableDict(self._get_raw_dict())

    def ids(self, *, deleted=False):
        for archive_info in self._archives.values():
            yield archive_info["id"]

    def _get_archive_meta(self, id: bytes) -> dict:
        # get all metadata directly from the ArchiveItem in the repo.
        from .repository import LegacyRepository

        try:
            cdata = self.repository.get(id)
        except LegacyRepository.ObjectNotFound:
            return dict(
                id=id,
                name="archive-does-not-exist",
                time="1970-01-01T00:00:00.000000",
                exists=False,
                username="",
                hostname="",
                tags=(),
            )
        else:
            _, data = self.manifest.repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)
            archive_dict = self.manifest.key.unpack_archive(data)
            archive_item = ArchiveItem(internal_dict=archive_dict)
            if archive_item.version not in (1, 2):
                raise Exception("Unknown archive metadata version")
            return dict(
                id=id,
                name=archive_item.name,
                time=archive_item.time,
                exists=True,
                username=archive_item.username,
                hostname=archive_item.hostname,
                size=archive_item.get("size", 0),
                nfiles=archive_item.get("nfiles", 0),
                comment=archive_item.get("comment", ""),
                tags=tuple(sorted(getattr(archive_item, "tags", []))),
            )

    def _infos(self, *, deleted=False):
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
                if match.startswith("aid:"):
                    wanted_id = match.removeprefix("aid:")
                    archive_infos = [x for x in archive_infos if bin_to_hex(x.id).startswith(wanted_id)]
                    if len(archive_infos) != 1:
                        raise CommandError("archive ID based match needs to match precisely one archive ID")
                elif match.startswith("tags:"):
                    wanted_tags = match.removeprefix("tags:")
                    wanted_tags = [tag for tag in wanted_tags.split(",") if tag]
                    archive_infos = [x for x in archive_infos if set(x.tags) >= set(wanted_tags)]
                elif match.startswith("user:"):
                    wanted_user = match.removeprefix("user:")
                    archive_infos = [x for x in archive_infos if x.user == wanted_user]
                elif match.startswith("host:"):
                    wanted_host = match.removeprefix("host:")
                    archive_infos = [x for x in archive_infos if x.host == wanted_host]
                else:
                    match = match.removeprefix("name:")
                    regex = get_regex_from_pattern(match)
                    regex = re.compile(regex + match_end)
                    archive_infos = [x for x in archive_infos if regex.match(x.name) is not None]
        return archive_infos

    def count(self):
        return len(self._archives)

    def names(self):
        yield from self._archives.keys()

    def exists(self, name):
        assert isinstance(name, str)
        return name in self._archives

    def exists_id(self, id, *, deleted=False):
        assert isinstance(id, bytes)
        raise NotImplementedError

    def exists_name_and_id(self, name, id):
        assert isinstance(name, str)
        assert isinstance(id, bytes)
        raise NotImplementedError

    def exists_name_and_ts(self, name, ts):
        assert isinstance(name, str)
        assert isinstance(ts, datetime)
        raise NotImplementedError

    def get(self, name, raw=False):
        assert isinstance(name, str)
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
        if self.exists(name) and not overwrite:
            raise KeyError("archive already exists")
        self._archives[name] = {"id": id, "time": ts}

    def delete_by_id(self, id):
        assert isinstance(id, bytes)
        raise NotImplementedError("Borg 1.x repositories do not support soft-delete")

    def undelete_by_id(self, id):
        assert isinstance(id, bytes)
        raise NotImplementedError("Borg 1.x repositories do not support undelete")

    def nuke_by_id(self, id):
        assert isinstance(id, bytes)
        raise NotImplementedError("Borg 1.x repositories do not support nuke")

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
        See Archives.list() for full parameter documentation.
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
        """Get a list of archives, considering --first/last/prefix/match-archives/sort cmdline args."""
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
        """Get exactly one archive matching <match>."""
        assert match is not None
        archive_infos = self._matching_info_tuples(match, match_end, deleted=deleted)
        if len(archive_infos) != 1:
            raise CommandError(f"{match} needed to match precisely one archive, but matched {len(archive_infos)}.")
        return archive_infos[0]

    def _set_raw_dict(self, d):
        for k, v in d.items():
            assert isinstance(k, str)
            assert isinstance(v, dict) and "id" in v and "time" in v
            self._archives[k] = v

    def _get_raw_dict(self):
        return self._archives
