import argparse
import pytest

from ...helpers import parse_storage_quota
from . import ArchiverTestCaseBase, Archiver, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_bad_filters(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "delete", "--first", "1", "--last", "1", fork=True, exit_code=2)


def test_get_args():
    archiver = Archiver()
    # everything normal:
    # first param is argv as produced by ssh forced command,
    # second param is like from SSH_ORIGINAL_COMMAND env variable
    args = archiver.get_args(
        ["borg", "serve", "--umask=0027", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], "borg serve --info"
    )
    assert args.func == archiver.do_serve
    assert args.restrict_to_paths == ["/p1", "/p2"]
    assert args.umask == 0o027
    assert args.log_level == "info"
    # similar, but with --restrict-to-repository
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --info --umask=0027",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - break out of path restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], "borg serve --restrict-to-path=/"
    )
    assert args.restrict_to_paths == ["/p1", "/p2"]
    # trying to cheat - break out of repository restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --restrict-to-repository=/",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - break below repository restriction
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-repository=/r1", "--restrict-to-repository=/r2"],
        "borg serve --restrict-to-repository=/r1/below",
    )
    assert args.restrict_to_repositories == ["/r1", "/r2"]
    # trying to cheat - try to execute different subcommand
    args = archiver.get_args(
        ["borg", "serve", "--restrict-to-path=/p1", "--restrict-to-path=/p2"], f"borg --repo=/ rcreate {RK_ENCRYPTION}"
    )
    assert args.func == archiver.do_serve

    # Check that environment variables in the forced command don't cause issues. If the command
    # were not forced, environment variables would be interpreted by the shell, but this does not
    # happen for forced commands - we get the verbatim command line and need to deal with env vars.
    args = archiver.get_args(["borg", "serve"], "BORG_FOO=bar borg serve --info")
    assert args.func == archiver.do_serve


class TestCommonOptions:
    @staticmethod
    def define_common_options(add_common_option):
        add_common_option("-h", "--help", action="help", help="show this help message and exit")
        add_common_option(
            "--critical", dest="log_level", help="foo", action="store_const", const="critical", default="warning"
        )
        add_common_option(
            "--error", dest="log_level", help="foo", action="store_const", const="error", default="warning"
        )
        add_common_option("--append", dest="append", help="foo", action="append", metavar="TOPIC", default=[])
        add_common_option("-p", "--progress", dest="progress", action="store_true", help="foo")
        add_common_option(
            "--lock-wait", dest="lock_wait", type=int, metavar="N", default=1, help="(default: %(default)d)."
        )

    @pytest.fixture
    def basic_parser(self):
        parser = argparse.ArgumentParser(prog="test", description="test parser", add_help=False)
        parser.common_options = Archiver.CommonOptions(
            self.define_common_options, suffix_precedence=("_level0", "_level1")
        )
        return parser

    @pytest.fixture
    def subparsers(self, basic_parser):
        return basic_parser.add_subparsers(title="required arguments", metavar="<command>")

    @pytest.fixture
    def parser(self, basic_parser):
        basic_parser.common_options.add_common_group(basic_parser, "_level0", provide_defaults=True)
        return basic_parser

    @pytest.fixture
    def common_parser(self, parser):
        common_parser = argparse.ArgumentParser(add_help=False, prog="test")
        parser.common_options.add_common_group(common_parser, "_level1")
        return common_parser

    @pytest.fixture
    def parse_vars_from_line(self, parser, subparsers, common_parser):
        subparser = subparsers.add_parser(
            "subcommand",
            parents=[common_parser],
            add_help=False,
            description="foo",
            epilog="bar",
            help="baz",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparser.set_defaults(func=1234)
        subparser.add_argument("--append-only", dest="append_only", action="store_true")

        def parse_vars_from_line(*line):
            print(line)
            args = parser.parse_args(line)
            parser.common_options.resolve(args)
            return vars(args)

        return parse_vars_from_line

    def test_simple(self, parse_vars_from_line):
        assert parse_vars_from_line("--error") == {
            "append": [],
            "lock_wait": 1,
            "log_level": "error",
            "progress": False,
        }

        assert parse_vars_from_line("--error", "subcommand", "--critical") == {
            "append": [],
            "lock_wait": 1,
            "log_level": "critical",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }

        with pytest.raises(SystemExit):
            parse_vars_from_line("--append-only", "subcommand")

        assert parse_vars_from_line("--append=foo", "--append", "bar", "subcommand", "--append", "baz") == {
            "append": ["foo", "bar", "baz"],
            "lock_wait": 1,
            "log_level": "warning",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }

    @pytest.mark.parametrize("position", ("before", "after", "both"))
    @pytest.mark.parametrize("flag,args_key,args_value", (("-p", "progress", True), ("--lock-wait=3", "lock_wait", 3)))
    def test_flag_position_independence(self, parse_vars_from_line, position, flag, args_key, args_value):
        line = []
        if position in ("before", "both"):
            line.append(flag)
        line.append("subcommand")
        if position in ("after", "both"):
            line.append(flag)

        result = {
            "append": [],
            "lock_wait": 1,
            "log_level": "warning",
            "progress": False,
            "append_only": False,
            "func": 1234,
        }
        result[args_key] = args_value

        assert parse_vars_from_line(*line) == result


def test_parse_storage_quota():
    assert parse_storage_quota("50M") == 50 * 1000**2
    with pytest.raises(argparse.ArgumentTypeError):
        parse_storage_quota("5M")
