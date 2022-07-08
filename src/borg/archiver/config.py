import sys
import argparse
import configparser
from binascii import unhexlify

from .common import with_repository
from ..cache import Cache, assert_secure
from ..constants import *  # NOQA
from ..helpers import EXIT_SUCCESS, EXIT_WARNING
from ..helpers import Error
from ..helpers import Location
from ..helpers import parse_file_size
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class ConfigMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_config(self, args, repository):
        """get, set, and delete values in a repository or cache config file"""

        def repo_validate(section, name, value=None, check_value=True):
            if section not in ["repository"]:
                raise ValueError("Invalid section")
            if name in ["segments_per_dir", "last_segment_checked"]:
                if check_value:
                    try:
                        int(value)
                    except ValueError:
                        raise ValueError("Invalid value") from None
            elif name in ["max_segment_size", "additional_free_space", "storage_quota"]:
                if check_value:
                    try:
                        parse_file_size(value)
                    except ValueError:
                        raise ValueError("Invalid value") from None
                    if name == "storage_quota":
                        if parse_file_size(value) < parse_file_size("10M"):
                            raise ValueError("Invalid value: storage_quota < 10M")
                    elif name == "max_segment_size":
                        if parse_file_size(value) >= MAX_SEGMENT_SIZE_LIMIT:
                            raise ValueError("Invalid value: max_segment_size >= %d" % MAX_SEGMENT_SIZE_LIMIT)
            elif name in ["append_only"]:
                if check_value and value not in ["0", "1"]:
                    raise ValueError("Invalid value")
            elif name in ["id"]:
                if check_value:
                    try:
                        bin_id = unhexlify(value)
                    except:
                        raise ValueError("Invalid value, must be 64 hex digits") from None
                    if len(bin_id) != 32:
                        raise ValueError("Invalid value, must be 64 hex digits")
            else:
                raise ValueError("Invalid name")

        def cache_validate(section, name, value=None, check_value=True):
            if section not in ["cache"]:
                raise ValueError("Invalid section")
            if name in ["previous_location"]:
                if check_value:
                    Location(value)
            else:
                raise ValueError("Invalid name")

        def list_config(config):
            default_values = {
                "version": "1",
                "segments_per_dir": str(DEFAULT_SEGMENTS_PER_DIR),
                "max_segment_size": str(MAX_SEGMENT_SIZE_LIMIT),
                "additional_free_space": "0",
                "storage_quota": repository.storage_quota,
                "append_only": repository.append_only,
            }
            print("[repository]")
            for key in [
                "version",
                "segments_per_dir",
                "max_segment_size",
                "storage_quota",
                "additional_free_space",
                "append_only",
                "id",
            ]:
                value = config.get("repository", key, fallback=False)
                if value is None:
                    value = default_values.get(key)
                    if value is None:
                        raise Error("The repository config is missing the %s key which has no default value" % key)
                print(f"{key} = {value}")
            for key in ["last_segment_checked"]:
                value = config.get("repository", key, fallback=None)
                if value is None:
                    continue
                print(f"{key} = {value}")

        if not args.list:
            if args.name is None:
                self.print_error("No config key name was provided.")
                return self.exit_code

            try:
                section, name = args.name.split(".")
            except ValueError:
                section = args.cache and "cache" or "repository"
                name = args.name

        if args.cache:
            manifest, key = Manifest.load(repository, (Manifest.Operation.WRITE,))
            assert_secure(repository, manifest, self.lock_wait)
            cache = Cache(repository, key, manifest, lock_wait=self.lock_wait)

        try:
            if args.cache:
                cache.cache_config.load()
                config = cache.cache_config._config
                save = cache.cache_config.save
                validate = cache_validate
            else:
                config = repository.config
                save = lambda: repository.save_config(repository.path, repository.config)  # noqa
                validate = repo_validate

            if args.delete:
                validate(section, name, check_value=False)
                config.remove_option(section, name)
                if len(config.options(section)) == 0:
                    config.remove_section(section)
                save()
            elif args.list:
                list_config(config)
            elif args.value:
                validate(section, name, args.value)
                if section not in config.sections():
                    config.add_section(section)
                config.set(section, name, args.value)
                save()
            else:
                try:
                    print(config.get(section, name))
                except (configparser.NoOptionError, configparser.NoSectionError) as e:
                    print(e, file=sys.stderr)
                    return EXIT_WARNING
            return EXIT_SUCCESS
        finally:
            if args.cache:
                cache.close()

    def build_parser_config(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

        config_epilog = process_epilog(
            """
        This command gets and sets options in a local repository or cache config file.
        For security reasons, this command only works on local repositories.

        To delete a config value entirely, use ``--delete``. To list the values
        of the configuration file or the default values, use ``--list``.  To get and existing
        key, pass only the key name. To set a key, pass both the key name and
        the new value. Keys can be specified in the format "section.name" or
        simply "name"; the section will default to "repository" and "cache" for
        the repo and cache configs, respectively.


        By default, borg config manipulates the repository config file. Using ``--cache``
        edits the repository cache's config file instead.
        """
        )
        subparser = subparsers.add_parser(
            "config",
            parents=[common_parser],
            add_help=False,
            description=self.do_config.__doc__,
            epilog=config_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="get and set configuration values",
        )
        subparser.set_defaults(func=self.do_config)
        subparser.add_argument(
            "-c", "--cache", dest="cache", action="store_true", help="get and set values from the repo cache"
        )

        group = subparser.add_mutually_exclusive_group()
        group.add_argument(
            "-d", "--delete", dest="delete", action="store_true", help="delete the key from the config file"
        )
        group.add_argument("-l", "--list", dest="list", action="store_true", help="list the configuration of the repo")

        subparser.add_argument("name", metavar="NAME", nargs="?", help="name of config key")
        subparser.add_argument("value", metavar="VALUE", nargs="?", help="new value for key")
