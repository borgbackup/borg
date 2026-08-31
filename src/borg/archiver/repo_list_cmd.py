import os
import textwrap
import sys

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import BaseFormatter, ArchiveFormatter, json_print, basic_json_data
from ..helpers import GroupBySpec
from ..helpers.argparsing import ArgumentParser
from ..manifest import AI_GROUP_BY_KEYS, Manifest, format_group_key, group_archives

from ..logger import create_logger

logger = create_logger()

# the default for "borg repo-list --format", also used to document the default in --format's help text.
FORMAT_DEFAULT = "{id:.8}  {time}  {archive:<15}  {tags:<10}  {username:<10}  {hostname:<10}  {comment:.40}{NL}"


class RepoListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,), allow_v1=True)
    def do_repo_list(self, args, repository, manifest):
        """List the archives contained in a repository."""
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{id}{NL}"
        else:
            format = os.environ.get("BORG_REPO_LIST_FORMAT", FORMAT_DEFAULT)
        formatter = ArchiveFormatter(format, repository, manifest, manifest.key, deleted=args.deleted)

        output_data = []

        archive_infos = manifest.archives.list_considering(args)
        group_by = tuple(args.group_by.split(",")) if args.group_by else ()
        # without grouping, all archives are listed as one group, exactly as before.
        groups = group_archives(archive_infos, group_by) if group_by else {(): archive_infos}

        for group_number, (key, group) in enumerate(groups.items()):
            if group_by and not args.json:
                separator = "" if group_number == 0 else "\n"
                sys.stdout.write(f"{separator}Group ({format_group_key(key, group_by)}):\n")
            for archive_info in group:
                if args.json:
                    item_data = formatter.get_item_data(archive_info, args.json)
                    if group_by:
                        item_data["group"] = dict(zip(group_by, key))
                    output_data.append(item_data)
                else:
                    sys.stdout.write(formatter.format_item(archive_info, args.json))

        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))

    def build_parser_repo_list(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        repo_list_epilog = process_epilog(
            textwrap.dedent(
                """
        This command lists the archives contained in a repository.

        Grouping archives
        +++++++++++++++++

        ``--group-by`` lists the archives grouped by the given comma-separated archive
        attributes, each group preceded by a header line naming it::

            $ borg repo-list --group-by name,host --format '{archive} {time}{NL}'
            Group (name='home', host='host1'):
            home Thu, 2026-06-04 18:00:00 +0200
            home Wed, 2026-06-03 18:00:00 +0200

            Group (name='home', host='host2'):
            home Thu, 2026-06-04 19:00:00 +0200

        Valid keys are ``name``, ``host``, ``user`` and ``tags``; borg's internal tags (starting
        with ``@``) do not affect grouping. Archives without ``host`` / ``user`` metadata (e.g.
        archives transferred from a borg 1.x repository) form their own group.

        These are the same keys and the same grouping that ``borg prune --group-by`` uses, so
        this is a way to see which archives a prune run will consider together before running
        it. Without ``--group-by``, archives are listed as before, ungrouped.

        With ``--json``, no header lines are emitted; each archive gets a ``group`` object
        instead.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses Python's `format string syntax
        <https://docs.python.org/3.11/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg repo-list --format '{archive}{NL}'
            ArchiveFoo
            ArchiveBar
            ...

            # {VAR:NUMBER} - pad to NUMBER columns.
            # Strings are left-aligned, numbers are right-aligned.
            # Note: the time keys (time, start, end) can not be padded - for them, the
            # format spec is a strftime format string, e.g. {time:%Y-%m-%d}.
            $ borg repo-list --format '{archive:36} {time} [{id}]{NL}'
            ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9...3b274]
            ...

        The following keys are always available:

        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when listing archives in a repository:

        """
            )
            + ArchiveFormatter.keys_help()
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_repo_list.__doc__, epilog=repo_list_epilog
        )
        subparsers.add_subcommand("repo-list", subparser, help="list repository contents")
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print the archive IDs, nothing else"
        )
        subparser.add_argument("--from-borg1", dest="v1_legacy", action="store_true", help="repository is Borg 1.x")
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help=f'specify format for archive listing (default: "{FORMAT_DEFAULT}")',
        )
        subparser.add_argument(
            "--group-by",
            metavar="KEYS",
            dest="group_by",
            type=GroupBySpec,
            default="",
            action=Highlander,
            help="comma-separated list of archive attributes to group the listed archives by; "
            "valid keys are: {}; default is to not group".format(", ".join(AI_GROUP_BY_KEYS)),
        )
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Format output as JSON. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text.",
        )
        define_archive_filters_group(subparser, deleted=True)
