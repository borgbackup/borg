import functools
import os
import textwrap

import borg
from ..archive import Archive
from ..constants import *  # NOQA
from ..cache import Cache, assert_secure
from ..helpers import Error
from ..helpers import SortBySpec, positive_int_validator, location_validator, Location, relative_time_marker_validator
from ..helpers import Highlander
from ..helpers.nanorst import rst_to_terminal
from ..manifest import Manifest, AI_HUMAN_SORT_KEYS
from ..patterns import PatternMatcher
from ..legacyremote import LegacyRemoteRepository
from ..remote import RemoteRepository
from ..legacyrepository import LegacyRepository
from ..repository import Repository
from ..repoobj import RepoObj, RepoObj1
from ..patterns import (
    ArgparsePatternAction,
    ArgparseExcludeFileAction,
    ArgparsePatternFileAction,
    parse_exclude_pattern,
)


from ..logger import create_logger

logger = create_logger(__name__)


def get_repository(location, *, create, exclusive, lock_wait, lock, args, v1_or_v2):
    if location.proto in ("ssh", "socket"):
        RemoteRepoCls = LegacyRemoteRepository if v1_or_v2 else RemoteRepository
        repository = RemoteRepoCls(
            location, create=create, exclusive=exclusive, lock_wait=lock_wait, lock=lock, args=args
        )

    elif location.proto in ("sftp", "file", "rclone") and not v1_or_v2:  # stuff directly supported by borgstore
        repository = Repository(location, create=create, exclusive=exclusive, lock_wait=lock_wait, lock=lock)

    else:
        RepoCls = LegacyRepository if v1_or_v2 else Repository
        repository = RepoCls(location.path, create=create, exclusive=exclusive, lock_wait=lock_wait, lock=lock)
    return repository


def compat_check(*, create, manifest, key, cache, compatibility, decorator_name):
    if not create and (manifest or key or cache):
        if compatibility is None:
            raise AssertionError(f"{decorator_name} decorator used without compatibility argument")
        if type(compatibility) is not tuple:
            raise AssertionError(f"{decorator_name} decorator compatibility argument must be of type tuple")
    else:
        if compatibility is not None:
            raise AssertionError(
                f"{decorator_name} called with compatibility argument, " f"but would not check {compatibility!r}"
            )
        if create:
            compatibility = Manifest.NO_OPERATION_CHECK
    return compatibility


def with_repository(
    create=False, lock=True, exclusive=False, manifest=True, cache=False, secure=True, compatibility=None
):
    """
    Method decorator for subcommand-handling methods: do_XYZ(self, args, repository, …)

    If a parameter (where allowed) is a str the attribute named of args is used instead.
    :param create: create repository
    :param lock: lock repository
    :param exclusive: (bool) lock repository exclusively (for writing)
    :param manifest: load manifest and repo_objs (key), pass them as keyword arguments
    :param cache: open cache, pass it as keyword argument (implies manifest)
    :param secure: do assert_secure after loading manifest
    :param compatibility: mandatory if not create and (manifest or cache), specifies mandatory
           feature categories to check
    """
    # Note: with_repository decorator does not have a "key" argument (yet?)
    compatibility = compat_check(
        create=create,
        manifest=manifest,
        key=manifest,
        cache=cache,
        compatibility=compatibility,
        decorator_name="with_repository",
    )

    # We may need to modify `lock` inside `wrapper`. Therefore we cannot use the
    # `nonlocal` statement to access `lock` as modifications would also
    # affect the scope outside of `wrapper`. Subsequent calls would
    # only see the overwritten value of `lock`, not the original one.
    # The solution is to define a place holder variable `_lock` to
    # propagate the value into `wrapper`.
    _lock = lock

    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, args, **kwargs):
            location = getattr(args, "location")
            if not location.valid:  # location always must be given
                raise Error("missing repository, please use --repo or BORG_REPO env var!")
            assert isinstance(exclusive, bool)
            lock = getattr(args, "lock", _lock)

            repository = get_repository(
                location,
                create=create,
                exclusive=exclusive,
                lock_wait=self.lock_wait,
                lock=lock,
                args=args,
                v1_or_v2=False,
            )

            with repository:
                if repository.version not in (3,):
                    raise Error(
                        f"This borg version only accepts version 3 repos for -r/--repo, "
                        f"but not version {repository.version}. "
                        f"You can use 'borg transfer' to copy archives from old to new repos."
                    )
                if manifest or cache:
                    manifest_ = Manifest.load(repository, compatibility, other=False)
                    kwargs["manifest"] = manifest_
                    if "compression" in args:
                        manifest_.repo_objs.compressor = args.compression.compressor
                    if secure:
                        assert_secure(repository, manifest_)
                if cache:
                    with Cache(
                        repository,
                        manifest_,
                        progress=getattr(args, "progress", False),
                        cache_mode=getattr(args, "files_cache_mode", FILES_CACHE_MODE_DISABLED),
                        start_backup=getattr(self, "start_backup", None),
                        iec=getattr(args, "iec", False),
                    ) as cache_:
                        return method(self, args, repository=repository, cache=cache_, **kwargs)
                else:
                    return method(self, args, repository=repository, **kwargs)

        return wrapper

    return decorator


def with_other_repository(manifest=False, cache=False, compatibility=None):
    """
    this is a simplified version of "with_repository", just for the "other location".

    the repository at the "other location" is intended to get used as a **source** (== read operations).
    """

    compatibility = compat_check(
        create=False,
        manifest=manifest,
        key=manifest,
        cache=cache,
        compatibility=compatibility,
        decorator_name="with_other_repository",
    )

    def decorator(method):
        @functools.wraps(method)
        def wrapper(self, args, **kwargs):
            location = getattr(args, "other_location")
            if not location.valid:  # nothing to do
                return method(self, args, **kwargs)

            v1_or_v2 = getattr(args, "v1_or_v2", False)

            repository = get_repository(
                location,
                create=False,
                exclusive=True,
                lock_wait=self.lock_wait,
                lock=True,
                args=args,
                v1_or_v2=v1_or_v2,
            )

            with repository:
                acceptable_versions = (1, 2) if v1_or_v2 else (3,)
                if repository.version not in acceptable_versions:
                    raise Error(
                        f"This borg version only accepts version {' or '.join(acceptable_versions)} "
                        f"repos for --other-repo."
                    )
                kwargs["other_repository"] = repository
                if manifest or cache:
                    manifest_ = Manifest.load(
                        repository, compatibility, other=True, ro_cls=RepoObj if repository.version > 1 else RepoObj1
                    )
                    assert_secure(repository, manifest_)
                    if manifest:
                        kwargs["other_manifest"] = manifest_
                if cache:
                    with Cache(
                        repository,
                        manifest_,
                        progress=False,
                        cache_mode=getattr(args, "files_cache_mode", FILES_CACHE_MODE_DISABLED),
                        iec=getattr(args, "iec", False),
                    ) as cache_:
                        kwargs["other_cache"] = cache_
                        return method(self, args, **kwargs)
                else:
                    return method(self, args, **kwargs)

        return wrapper

    return decorator


def with_archive(method):
    @functools.wraps(method)
    def wrapper(self, args, repository, manifest, **kwargs):
        archive_name = getattr(args, "name", None)
        assert archive_name is not None
        archive_info = manifest.archives.get_one([archive_name])
        archive = Archive(
            manifest,
            archive_info.id,
            numeric_ids=getattr(args, "numeric_ids", False),
            noflags=getattr(args, "noflags", False),
            noacls=getattr(args, "noacls", False),
            noxattrs=getattr(args, "noxattrs", False),
            cache=kwargs.get("cache"),
            log_json=args.log_json,
            iec=args.iec,
        )
        return method(self, args, repository=repository, manifest=manifest, archive=archive, **kwargs)

    return wrapper


# You can use :ref:`xyz` in the following usage pages. However, for plain-text view,
# e.g. through "borg ... --help", define a substitution for the reference here.
# It will replace the entire :ref:`foo` verbatim.
rst_plain_text_references = {
    "a_status_oddity": '"I am seeing ‘A’ (added) status for a unchanged file!?"',
    "separate_compaction": '"Separate compaction"',
    "list_item_flags": '"Item flags"',
    "borg_patterns": '"borg help patterns"',
    "borg_placeholders": '"borg help placeholders"',
    "key_files": "Internals -> Data structures and file formats -> Key files",
    "borg_key_export": "borg key export --help",
}


def process_epilog(epilog):
    epilog = textwrap.dedent(epilog).splitlines()
    try:
        mode = borg.doc_mode
    except AttributeError:
        mode = "command-line"
    if mode in ("command-line", "build_usage"):
        epilog = [line for line in epilog if not line.startswith(".. man")]
    epilog = "\n".join(epilog)
    if mode == "command-line":
        epilog = rst_to_terminal(epilog, rst_plain_text_references)
    return epilog


def define_exclude_and_patterns(add_option, *, tag_files=False, strip_components=False):
    add_option(
        "-e",
        "--exclude",
        metavar="PATTERN",
        dest="patterns",
        type=parse_exclude_pattern,
        action="append",
        help="exclude paths matching PATTERN",
    )
    add_option(
        "--exclude-from",
        metavar="EXCLUDEFILE",
        action=ArgparseExcludeFileAction,
        help="read exclude patterns from EXCLUDEFILE, one per line",
    )
    add_option(
        "--pattern", metavar="PATTERN", action=ArgparsePatternAction, help="include/exclude paths matching PATTERN"
    )
    add_option(
        "--patterns-from",
        metavar="PATTERNFILE",
        action=ArgparsePatternFileAction,
        help="read include/exclude patterns from PATTERNFILE, one per line",
    )

    if tag_files:
        add_option(
            "--exclude-caches",
            dest="exclude_caches",
            action="store_true",
            help="exclude directories that contain a CACHEDIR.TAG file " "(http://www.bford.info/cachedir/spec.html)",
        )
        add_option(
            "--exclude-if-present",
            metavar="NAME",
            dest="exclude_if_present",
            action="append",
            type=str,
            help="exclude directories that are tagged by containing a filesystem object with " "the given NAME",
        )
        add_option(
            "--keep-exclude-tags",
            dest="keep_exclude_tags",
            action="store_true",
            help="if tag objects are specified with ``--exclude-if-present``, "
            "don't omit the tag objects themselves from the backup archive",
        )

    if strip_components:
        add_option(
            "--strip-components",
            metavar="NUMBER",
            dest="strip_components",
            type=int,
            default=0,
            action=Highlander,
            help="Remove the specified number of leading path elements. "
            "Paths with fewer elements will be silently skipped.",
        )


def define_exclusion_group(subparser, **kwargs):
    exclude_group = subparser.add_argument_group("Include/Exclude options")
    define_exclude_and_patterns(exclude_group.add_argument, **kwargs)
    return exclude_group


def define_archive_filters_group(
    subparser, *, sort_by=True, first_last=True, oldest_newest=True, older_newer=True, deleted=False
):
    filters_group = subparser.add_argument_group(
        "Archive filters", "Archive filters can be applied to repository targets."
    )
    group = filters_group.add_mutually_exclusive_group()
    group.add_argument(
        "-a",
        "--match-archives",
        metavar="PATTERN",
        dest="match_archives",
        action="append",
        help='only consider archives matching all patterns. see "borg help match-archives".',
    )

    if sort_by:
        sort_by_default = "timestamp"
        filters_group.add_argument(
            "--sort-by",
            metavar="KEYS",
            dest="sort_by",
            type=SortBySpec,
            default=sort_by_default,
            action=Highlander,
            help="Comma-separated list of sorting keys; valid keys are: {}; default is: {}".format(
                ", ".join(AI_HUMAN_SORT_KEYS), sort_by_default
            ),
        )

    if first_last:
        group = filters_group.add_mutually_exclusive_group()
        group.add_argument(
            "--first",
            metavar="N",
            dest="first",
            type=positive_int_validator,
            default=0,
            action=Highlander,
            help="consider first N archives after other filters were applied",
        )
        group.add_argument(
            "--last",
            metavar="N",
            dest="last",
            type=positive_int_validator,
            default=0,
            action=Highlander,
            help="consider last N archives after other filters were applied",
        )

    if oldest_newest:
        group = filters_group.add_mutually_exclusive_group()
        group.add_argument(
            "--oldest",
            metavar="TIMESPAN",
            dest="oldest",
            type=relative_time_marker_validator,
            action=Highlander,
            help="consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.",
        )
        group.add_argument(
            "--newest",
            metavar="TIMESPAN",
            dest="newest",
            type=relative_time_marker_validator,
            action=Highlander,
            help="consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.",
        )

    if older_newer:
        group = filters_group.add_mutually_exclusive_group()
        group.add_argument(
            "--older",
            metavar="TIMESPAN",
            dest="older",
            type=relative_time_marker_validator,
            action=Highlander,
            help="consider archives older than (now - TIMESPAN), e.g. 7d or 12m.",
        )
        group.add_argument(
            "--newer",
            metavar="TIMESPAN",
            dest="newer",
            type=relative_time_marker_validator,
            action=Highlander,
            help="consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.",
        )

    if deleted:
        filters_group.add_argument(
            "--deleted", dest="deleted", action="store_true", help="consider only soft-deleted archives."
        )

    return filters_group


def define_common_options(add_common_option):
    add_common_option("-h", "--help", action="help", help="show this help message and exit")
    add_common_option(
        "--critical",
        dest="log_level",
        action="store_const",
        const="critical",
        default="warning",
        help="work on log level CRITICAL",
    )
    add_common_option(
        "--error",
        dest="log_level",
        action="store_const",
        const="error",
        default="warning",
        help="work on log level ERROR",
    )
    add_common_option(
        "--warning",
        dest="log_level",
        action="store_const",
        const="warning",
        default="warning",
        help="work on log level WARNING (default)",
    )
    add_common_option(
        "--info",
        "-v",
        "--verbose",
        dest="log_level",
        action="store_const",
        const="info",
        default="warning",
        help="work on log level INFO",
    )
    add_common_option(
        "--debug",
        dest="log_level",
        action="store_const",
        const="debug",
        default="warning",
        help="enable debug output, work on log level DEBUG",
    )
    add_common_option(
        "--debug-topic",
        metavar="TOPIC",
        dest="debug_topics",
        action="append",
        default=[],
        help="enable TOPIC debugging (can be specified multiple times). "
        "The logger path is borg.debug.<TOPIC> if TOPIC is not fully qualified.",
    )
    add_common_option("-p", "--progress", dest="progress", action="store_true", help="show progress information")
    add_common_option("--iec", dest="iec", action="store_true", help="format using IEC units (1KiB = 1024B)")
    add_common_option(
        "--log-json",
        dest="log_json",
        action="store_true",
        help="Output one JSON object per log line instead of formatted text.",
    )
    add_common_option(
        "--lock-wait",
        metavar="SECONDS",
        dest="lock_wait",
        type=int,
        default=int(os.environ.get("BORG_LOCK_WAIT", 10)),
        action=Highlander,
        help="wait at most SECONDS for acquiring a repository/cache lock (default: %(default)d).",
    )
    add_common_option("--show-version", dest="show_version", action="store_true", help="show/log the borg version")
    add_common_option("--show-rc", dest="show_rc", action="store_true", help="show/log the return code (rc)")
    add_common_option(
        "--umask",
        metavar="M",
        dest="umask",
        type=lambda s: int(s, 8),
        default=UMASK_DEFAULT,
        action=Highlander,
        help="set umask to M (local only, default: %(default)04o)",
    )
    add_common_option(
        "--remote-path",
        metavar="PATH",
        dest="remote_path",
        action=Highlander,
        help='use PATH as borg executable on the remote (default: "borg")',
    )
    add_common_option(
        "--upload-ratelimit",
        metavar="RATE",
        dest="upload_ratelimit",
        type=int,
        action=Highlander,
        help="set network upload rate limit in kiByte/s (default: 0=unlimited)",
    )
    add_common_option(
        "--upload-buffer",
        metavar="UPLOAD_BUFFER",
        dest="upload_buffer",
        type=int,
        action=Highlander,
        help="set network upload buffer size in MiB. (default: 0=no buffer)",
    )
    add_common_option(
        "--debug-profile",
        metavar="FILE",
        dest="debug_profile",
        default=None,
        action=Highlander,
        help="Write execution profile in Borg format into FILE. For local use a Python-"
        'compatible file can be generated by suffixing FILE with ".pyprof".',
    )
    add_common_option(
        "--rsh",
        metavar="RSH",
        dest="rsh",
        action=Highlander,
        help="Use this command to connect to the 'borg serve' process (default: 'ssh')",
    )
    add_common_option(
        "--socket",
        metavar="PATH",
        dest="use_socket",
        default=False,
        const=True,
        nargs="?",
        action=Highlander,
        help="Use UNIX DOMAIN (IPC) socket at PATH for client/server communication with socket: protocol.",
    )
    add_common_option(
        "-r",
        "--repo",
        metavar="REPO",
        dest="location",
        type=location_validator(other=False),
        default=Location(other=False),
        action=Highlander,
        help="repository to use",
    )


def build_matcher(inclexcl_patterns, include_paths):
    matcher = PatternMatcher()
    matcher.add_inclexcl(inclexcl_patterns)
    matcher.add_includepaths(include_paths)
    return matcher


def build_filter(matcher, strip_components):
    if strip_components:

        def item_filter(item):
            matched = matcher.match(item.path) and len(item.path.split(os.sep)) > strip_components
            return matched

    else:

        def item_filter(item):
            matched = matcher.match(item.path)
            return matched

    return item_filter
