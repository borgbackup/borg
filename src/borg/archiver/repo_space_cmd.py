import argparse
import math
import os

from borgstore.store import ItemInfo

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import parse_file_size, format_file_size

from ..logger import create_logger

logger = create_logger()


class RepoSpaceMixIn:
    @with_repository(lock=False, manifest=False)
    def do_repo_space(self, args, repository):
        """Manage reserved space in repository"""
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
            print(f"Freed {format_file_size(size, iec=False)} in repository.")
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

        Borg can not work in disk-full conditions (can not lock a repo and thus can
        not run prune/delete or compact operations to free disk space).

        To avoid running into dead-end situations like that, you can put some objects
        into a repository that take up some disk space. If you ever run into a
        disk-full situation, you can free that space and then borg will be able to
        run normally, so you can free more disk space by using prune/delete/compact.
        After that, don't forget to reserve space again, in case you run into that
        situation again at a later time.

        Examples::

            # Create a new repository:
            $ borg repo-create ...
            # Reserve approx. 1GB of space for emergencies:
            $ borg repo-space --reserve 1G

            # Check amount of reserved space in the repository:
            $ borg repo-space

            # EMERGENCY! Free all reserved space to get things back to normal:
            $ borg repo-space --free
            $ borg prune ...
            $ borg delete ...
            $ borg compact -v  # only this actually frees space of deleted archives
            $ borg repo-space --reserve 1G  # reserve space again for next time


        Reserved space is always rounded up to use full reservation blocks of 64MiB.
        """
        )
        subparser = subparsers.add_parser(
            "repo-space",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_space.__doc__,
            epilog=repo_space_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="manage reserved space in a repository",
        )
        subparser.set_defaults(func=self.do_repo_space)
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
            help="Free all reserved space. Don't forget to reserve space later again.",
        )
