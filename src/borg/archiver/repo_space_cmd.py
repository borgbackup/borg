import argparse
import math
import os

from jsonargparse import ArgumentParser

from borgstore.store import ItemInfo

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import parse_file_size, format_file_size

from ..logger import create_logger

logger = create_logger()


class RepoSpaceMixIn:
    @with_repository(lock=False, manifest=False)
    def do_repo_space(self, args, repository):
        """Manages reserved space in the repository."""
        # we work without locking here because locks don't work with full disk.
        if args.reserve_space > 0:
            storage_space_reserve_object_size = 64 * 2**20  # 64 MiB per object
            count = math.ceil(float(args.reserve_space) / storage_space_reserve_object_size)  # round up
            size = 0
            for i in range(count):
                data = os.urandom(storage_space_reserve_object_size)  # counter-act fs compression/dedup
                repository.store_store(f"config/space-reserve.{i}", data)
                size += len(data)
            print(f"There is {format_file_size(size, iec=False)} reserved space in this repository now.")
        elif args.free_space:
            infos = repository.store_list("config")
            size = 0
            for info in infos:
                info = ItemInfo(*info)  # RPC does not give namedtuple
                if info.name.startswith("space-reserve."):
                    size += info.size
                    repository.store_delete(f"config/{info.name}")
            print(f"Freed {format_file_size(size, iec=False)} in the repository.")
            print("Now run borg prune or borg delete plus borg compact to free more space.")
            print("After that, do not forget to reserve space again for next time!")
        else:  # print amount currently reserved
            infos = repository.store_list("config")
            size = 0
            for info in infos:
                info = ItemInfo(*info)  # RPC does not give namedtuple
                if info.name.startswith("space-reserve."):
                    size += info.size
            print(f"There is {format_file_size(size, iec=False)} reserved space in this repository.")
            print("In case you want to change the amount, use --free first to free all reserved space,")
            print("then use --reserve with the desired amount.")

    def build_parser_repo_space(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_space_epilog = process_epilog(
            """
        This command manages reserved space in a repository.

        Borg cannot work in disk-full conditions (it cannot lock a repository and thus cannot
        run prune/delete or compact operations to free disk space).

        To avoid running into such dead-end situations, you can put some objects into a
        repository that take up disk space. If you ever run into a disk-full situation, you
        can free that space, and then Borg will be able to run normally so you can free more
        disk space by using ``borg prune``/``borg delete``/``borg compact``. After that, do
        not forget to reserve space again, in case you run into that situation again later.

        Examples::

            # Create a new repository:
            $ borg repo-create ...
            # Reserve approx. 1 GiB of space for emergencies:
            $ borg repo-space --reserve 1G

            # Check the amount of reserved space in the repository:
            $ borg repo-space

            # EMERGENCY! Free all reserved space to get things back to normal:
            $ borg repo-space --free
            $ borg prune ...
            $ borg delete ...
            $ borg compact -v  # only this actually frees space of deleted archives
            $ borg repo-space --reserve 1G  # reserve space again for next time


        Reserved space is always rounded up to full reservation blocks of 64 MiB.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_space.__doc__,
            epilog=repo_space_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers.add_subcommand("repo-space", subparser, help="manage reserved space in a repository")
        subparser.add_argument(
            "--reserve",
            metavar="SPACE",
            dest="reserve_space",
            default=0,
            type=parse_file_size,
            action=Highlander,
            help="Amount of space to reserve (e.g. 100M, 1G). Default: 0.",
        )
        subparser.add_argument(
            "--free",
            dest="free_space",
            action="store_true",
            help="Free all reserved space. Do not forget to reserve space again later.",
        )
