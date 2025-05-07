import argparse
from collections import defaultdict
import os

from ._common import with_repository, define_archive_filters_group
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, Error
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..remote import RemoteRepository
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()


class ArchiveAnalyzer:
    def __init__(self, args, repository, manifest):
        self.args = args
        self.repository = repository
        assert isinstance(repository, (Repository, RemoteRepository))
        self.manifest = manifest
        self.difference_by_path = defaultdict(int)  # directory path -> count of chunks changed

    def analyze(self):
        logger.info("Starting archives analysis...")
        self.analyze_archives()
        self.report()
        logger.info("Finished archives analysis.")

    def analyze_archives(self) -> None:
        """Analyze all archives matching the given selection criteria."""
        archive_infos = self.manifest.archives.list_considering(self.args)
        num_archives = len(archive_infos)
        if num_archives < 2:
            raise Error("Need at least 2 archives to analyze.")

        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Analyzing archives %3.1f%%", step=0.1, msgid="analyze.analyze_archives"
        )
        i = 0
        info = archive_infos[i]
        pi.show(i)
        logger.info(
            f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 1}/{num_archives})"
        )
        base = self.analyze_archive(info.id)
        for i, info in enumerate(archive_infos[1:]):
            pi.show(i + 1)
            logger.info(
                f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 2}/{num_archives})"
            )
            new = self.analyze_archive(info.id)
            self.analyze_change(base, new)
            base = new
        pi.finish()

    def analyze_archive(self, id):
        """compute the set of chunks for each directory in this archive"""
        archive = Archive(self.manifest, id)
        chunks_by_path = defaultdict(dict)  # collect all chunk IDs generated from files in this directory path
        for item in archive.iter_items():
            if "chunks" in item:
                item_chunks = dict(item.chunks)  # chunk id -> plaintext size
                directory_path = os.path.dirname(item.path)
                chunks_by_path[directory_path].update(item_chunks)
        return chunks_by_path

    def analyze_change(self, base, new):
        """for each directory path, sum up the changed (removed or added) chunks' sizes between base and new."""

        def analyze_path_change(path):
            base_chunks = base[path]
            new_chunks = new[path]
            # add up added chunks' sizes
            for id in new_chunks.keys() - base_chunks.keys():
                self.difference_by_path[directory_path] += new_chunks[id]
            # add up removed chunks' sizes
            for id in base_chunks.keys() - new_chunks.keys():
                self.difference_by_path[directory_path] += base_chunks[id]

        for directory_path in base:
            analyze_path_change(directory_path)
        for directory_path in new:
            if directory_path not in base:
                analyze_path_change(directory_path)

    def report(self):
        print()
        print("chunks added or removed by directory path")
        print("=========================================")
        for directory_path in sorted(self.difference_by_path, key=lambda p: self.difference_by_path[p], reverse=True):
            difference = self.difference_by_path[directory_path]
            print(f"{directory_path}: {difference}")


class AnalyzeMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_analyze(self, args, repository, manifest):
        """Analyze archives"""
        ArchiveAnalyzer(args, repository, manifest).analyze()

    def build_parser_analyze(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        analyze_epilog = process_epilog(
            """
            Analyze archives to find "hot spots".

            Borg analyze relies on the usual archive matching options to select the
            archives that should be considered for analysis (e.g. ``-a series_name``).
            Then it iterates over all matching archives, over all contained files and
            collects information about chunks stored in all directories it encountered.

            It considers chunk IDs and their plaintext sizes (we don't have the compressed
            size in the repository easily available) and adds up added/removed chunks'
            sizes per direct parent directory and outputs a list of "directory: size".

            You can use that list to find directories with a lot of "activity" - maybe
            some of these are temporary or cache directories you did forget to exclude.

            To not have these unwanted directories in your backups, you could carefully
            exclude these in ``borg create`` (for future backups) or use ``borg recreate``
            to re-create existing archives without these.
            """
        )
        subparser = subparsers.add_parser(
            "analyze",
            parents=[common_parser],
            add_help=False,
            description=self.do_analyze.__doc__,
            epilog=analyze_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="analyze archives",
        )
        subparser.set_defaults(func=self.do_analyze)
        define_archive_filters_group(subparser)
