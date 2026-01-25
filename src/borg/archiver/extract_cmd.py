import sys
import argparse
import logging
import stat

from ._common import with_repository, with_archive
from ._common import build_filter, build_matcher
from ..archive import BackupError
from ..constants import *  # NOQA
from ..helpers import archivename_validator, PathSpec
from ..helpers import remove_surrogates
from ..helpers import HardLinkManager
from ..helpers import ProgressIndicatorPercent
from ..helpers import BackupWarning, IncludePatternNeverMatchedWarning
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class ExtractMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_extract(self, args, repository, manifest, archive):
        """Extracts archive contents."""
        # be restrictive when restoring files, restore permissions later
        if sys.getfilesystemencoding() == "ascii":
            logger.warning('Warning: Filesystem encoding is "ascii"; extracting non-ASCII filenames is not supported.')
            if sys.platform.startswith(("linux", "freebsd", "netbsd", "openbsd", "darwin")):
                logger.warning(
                    "Hint: You likely need to fix your locale setup. "
                    "For example, install locales and use: LANG=en_US.UTF-8"
                )

        matcher = build_matcher(args.patterns, args.paths)

        progress = args.progress
        output_list = args.output_list
        dry_run = args.dry_run
        stdout = args.stdout
        sparse = args.sparse
        strip_components = args.strip_components
        continue_extraction = args.continue_extraction
        dirs = []
        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> path

        filter = build_filter(matcher, strip_components)
        if progress:
            pi = ProgressIndicatorPercent(msg="%5.1f%% Extracting: %s", step=0.1, msgid="extract")
            pi.output(
                "Calculating total archive size for the progress indicator (might take a long time for large archives)"
            )
            extracted_size = sum(item.get_size() for item in archive.iter_items(filter))
            pi.total = extracted_size
        else:
            pi = None

        for item in archive.iter_items():
            orig_path = item.path
            if strip_components:
                stripped_path = "/".join(orig_path.split("/")[strip_components:])
                if not stripped_path:
                    continue
                item.path = stripped_path

            is_matched = matcher.match(orig_path)

            if output_list:
                log_prefix = "+" if is_matched else "-"
                logging.getLogger("borg.output.list").info(f"{log_prefix} {remove_surrogates(item.path)}")

            if is_matched:
                archive.preload_item_chunks(item, optimize_hardlinks=True)

                if not dry_run:
                    while dirs and not item.path.startswith(dirs[-1].path):
                        dir_item = dirs.pop(-1)
                        try:
                            archive.extract_item(dir_item, stdout=stdout)
                        except BackupError as e:
                            self.print_warning_instance(BackupWarning(remove_surrogates(dir_item.path), e))

                try:
                    if dry_run:
                        archive.extract_item(item, dry_run=True, hlm=hlm, pi=pi)
                    else:
                        if stat.S_ISDIR(item.mode):
                            dirs.append(item)
                            archive.extract_item(item, stdout=stdout, restore_attrs=False)
                        else:
                            archive.extract_item(
                                item,
                                stdout=stdout,
                                sparse=sparse,
                                hlm=hlm,
                                pi=pi,
                                continue_extraction=continue_extraction,
                            )
                except BackupError as e:
                    self.print_warning_instance(BackupWarning(remove_surrogates(orig_path), e))

        if pi:
            pi.finish()

        if not args.dry_run:
            pi = ProgressIndicatorPercent(
                total=len(dirs), msg="Setting directory permissions %3.0f%%", msgid="extract.permissions"
            )
            while dirs:
                pi.show()
                dir_item = dirs.pop(-1)
                try:
                    archive.extract_item(dir_item, stdout=stdout)
                except BackupError as e:
                    self.print_warning_instance(BackupWarning(remove_surrogates(dir_item.path), e))
        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning_instance(IncludePatternNeverMatchedWarning(pattern))
        if pi:
            # clear progress output
            pi.finish()

    def build_parser_extract(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group

        extract_epilog = process_epilog(
            """
        This command extracts the contents of an archive.

        By default, the entire archive is extracted, but a subset of files and directories
        can be selected by passing a list of ``PATH`` arguments. The default interpretation
        for the paths to extract is `pp:` which is a literal path-prefix match. If you want
        to use e.g. a wildcard, you must select a different pattern style such as `sh:` or
        `fm:`. See :ref:`borg_patterns` for more information.

        The file selection can be further restricted by using the ``--exclude`` option.
        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        By using ``--dry-run``, you can do all extraction steps except actually writing the
        output data: reading metadata and data chunks from the repository, checking the hash/HMAC,
        decrypting, and decompressing.

        ``--progress`` can be slower than no progress display, since it makes one additional
        pass over the archive metadata.

        .. note::

            Currently, extract always writes into the current working directory ("."),
            so make sure you ``cd`` to the right place before calling ``borg extract``.

            When parent directories are not extracted (because of using file/directory selection
            or any other reason), Borg cannot restore parent directories' metadata, e.g., owner,
            group, permissions, etc.
        """
        )
        subparser = subparsers.add_parser(
            "extract",
            parents=[common_parser],
            add_help=False,
            description=self.do_extract.__doc__,
            epilog=extract_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="extract archive contents",
        )
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output a verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not actually change any files"
        )
        subparser.add_argument(
            "--numeric-ids", dest="numeric_ids", action="store_true", help="only use numeric user and group identifiers"
        )
        subparser.add_argument(
            "--noflags", dest="noflags", action="store_true", help="do not extract/set flags (e.g. NODUMP, IMMUTABLE)"
        )
        subparser.add_argument("--noacls", dest="noacls", action="store_true", help="do not extract/set ACLs")
        subparser.add_argument("--noxattrs", dest="noxattrs", action="store_true", help="do not extract/set xattrs")
        subparser.add_argument(
            "--stdout", dest="stdout", action="store_true", help="write all extracted data to stdout"
        )
        subparser.add_argument(
            "--sparse",
            dest="sparse",
            action="store_true",
            help="create holes in the output sparse file from all-zero chunks",
        )
        subparser.add_argument(
            "--continue",
            dest="continue_extraction",
            action="store_true",
            help="continue a previously interrupted extraction of the same archive",
        )
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(subparser, strip_components=True)
