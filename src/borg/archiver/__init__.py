# borg cli interface / toplevel archiver code

import sys
import traceback

# quickfix to disallow running borg with assertions switched off
try:
    assert False
except AssertionError:
    pass  # OK
else:
    print(
        "Borg requires working assertions. Please run Python without -O and/or unset PYTHONOPTIMIZE.", file=sys.stderr
    )
    sys.exit(2)  # == EXIT_ERROR

try:
    import argparse
    import faulthandler
    import functools
    import inspect
    import itertools
    import json
    import logging
    import os
    import shlex
    import signal
    from datetime import datetime, timezone

    from ..logger import create_logger, setup_logging

    logger = create_logger()

    from ._common import Highlander
    from .. import __version__
    from ..constants import *  # NOQA
    from ..helpers import EXIT_WARNING, EXIT_ERROR, EXIT_SIGNAL_BASE, classify_ec
    from ..helpers import Error, CommandError, get_ec, modern_ec
    from ..helpers import add_warning, BorgWarning, BackupWarning
    from ..helpers import format_file_size
    from ..helpers import remove_surrogates, text_to_json
    from ..helpers import DatetimeWrapper, replace_placeholders
    from ..helpers import check_python, check_extension_modules
    from ..helpers import is_slow_msgpack, is_supported_msgpack, sysinfo
    from ..helpers import signal_handler, raising_signal_handler, SigHup, SigTerm
    from ..helpers import ErrorIgnoringTextIOWrapper
    from ..helpers import msgpack
    from ..helpers import sig_int
    from ..remote import RemoteRepository
    from ..selftest import selftest
except BaseException:
    # an unhandled exception in the try-block would cause the borg cli command to exit with rc 1 due to python's
    # default behavior, see issue #4424.
    # as borg defines rc 1 as WARNING, this would be a mismatch, because a crash should be an ERROR (rc 2).
    traceback.print_exc()
    sys.exit(2)  # == EXIT_ERROR

assert EXIT_ERROR == 2, "EXIT_ERROR is not 2, as expected - fix assert AND exception handler right above this line."


STATS_HEADER = "                       Original size    Deduplicated size"

PURE_PYTHON_MSGPACK_WARNING = "Using a pure-python msgpack! This will result in lower performance."


def get_func(args):
    # This works around https://bugs.python.org/issue9351
    # func is used at the leaf parsers of the argparse parser tree,
    # fallback_func at next level towards the root,
    # fallback2_func at the 2nd next level (which is root in our case).
    for name in "func", "fallback_func", "fallback2_func":
        func = getattr(args, name, None)
        if func is not None:
            return func
    raise Exception("expected func attributes not found")


from .analyze_cmd import AnalyzeMixIn
from .benchmark_cmd import BenchmarkMixIn
from .check_cmd import CheckMixIn
from .compact_cmd import CompactMixIn
from .create_cmd import CreateMixIn
from .debug_cmd import DebugMixIn
from .delete_cmd import DeleteMixIn
from .diff_cmd import DiffMixIn
from .extract_cmd import ExtractMixIn
from .help_cmd import HelpMixIn
from .info_cmd import InfoMixIn
from .key_cmds import KeysMixIn
from .list_cmd import ListMixIn
from .lock_cmds import LocksMixIn
from .mount_cmds import MountMixIn
from .prune_cmd import PruneMixIn
from .repo_compress_cmd import RepoCompressMixIn
from .recreate_cmd import RecreateMixIn
from .rename_cmd import RenameMixIn
from .repo_create_cmd import RepoCreateMixIn
from .repo_info_cmd import RepoInfoMixIn
from .repo_delete_cmd import RepoDeleteMixIn
from .repo_list_cmd import RepoListMixIn
from .repo_space_cmd import RepoSpaceMixIn
from .serve_cmd import ServeMixIn
from .tag_cmd import TagMixIn
from .tar_cmds import TarMixIn
from .transfer_cmd import TransferMixIn
from .undelete_cmd import UnDeleteMixIn
from .version_cmd import VersionMixIn


class Archiver(
    AnalyzeMixIn,
    BenchmarkMixIn,
    CheckMixIn,
    CompactMixIn,
    CreateMixIn,
    DebugMixIn,
    DeleteMixIn,
    DiffMixIn,
    ExtractMixIn,
    HelpMixIn,
    InfoMixIn,
    KeysMixIn,
    ListMixIn,
    LocksMixIn,
    MountMixIn,
    PruneMixIn,
    RecreateMixIn,
    RenameMixIn,
    RepoCompressMixIn,
    RepoCreateMixIn,
    RepoDeleteMixIn,
    RepoInfoMixIn,
    RepoListMixIn,
    RepoSpaceMixIn,
    ServeMixIn,
    TagMixIn,
    TarMixIn,
    TransferMixIn,
    UnDeleteMixIn,
    VersionMixIn,
):
    def __init__(self, lock_wait=None, prog=None):
        self.lock_wait = lock_wait
        self.prog = prog
        self.start_backup = None

    def print_warning(self, msg, *args, **kw):
        warning_code = kw.get("wc", EXIT_WARNING)  # note: wc=None can be used to not influence exit code
        warning_type = kw.get("wt", "percent")
        assert warning_type in ("percent", "curly")
        warning_msgid = kw.get("msgid")
        if warning_code is not None:
            add_warning(msg, *args, wc=warning_code, wt=warning_type)
        if warning_type == "percent":
            output = args and msg % args or msg
        else:  # == "curly"
            output = args and msg.format(*args) or msg
        logger.warning(output, msgid=warning_msgid) if warning_msgid else logger.warning(output)

    def print_warning_instance(self, warning):
        assert isinstance(warning, BorgWarning)
        # if it is a BackupWarning, use the wrapped BackupError exception instance:
        cls = type(warning.args[1]) if isinstance(warning, BackupWarning) else type(warning)
        msg, msgid, args, wc = cls.__doc__, cls.__qualname__, warning.args, warning.exit_code
        self.print_warning(msg, *args, wc=wc, wt="curly", msgid=msgid)

    def print_file_status(self, status, path):
        # if we get called with status == None, the final file status was already printed
        if self.output_list and status is not None and (self.output_filter is None or status in self.output_filter):
            if self.log_json:
                json_data = {"type": "file_status", "status": status}
                json_data.update(text_to_json("path", path))
                print(json.dumps(json_data), file=sys.stderr)
            else:
                logging.getLogger("borg.output.list").info("%1s %s", status, remove_surrogates(path))

    def preprocess_args(self, args):
        deprecations = [
            # ('--old', '--new' or None, 'Warning: "--old" has been deprecated. Use "--new" instead.'),
        ]
        for i, arg in enumerate(args[:]):
            for old_name, new_name, warning in deprecations:
                if arg.startswith(old_name):
                    if new_name is not None:
                        args[i] = arg.replace(old_name, new_name)
                    print(warning, file=sys.stderr)
        return args

    class CommonOptions:
        """
        Support class to allow specifying common options directly after the top-level command.

        Normally options can only be specified on the parser defining them, which means
        that generally speaking *all* options go after all sub-commands. This is annoying
        for common options in scripts, e.g. --remote-path or logging options.

        This class allows adding the same set of options to both the top-level parser
        and the final sub-command parsers (but not intermediary sub-commands, at least for now).

        It does so by giving every option's target name ("dest") a suffix indicating its level
        -- no two options in the parser hierarchy can have the same target --
        then, after parsing the command line, multiple definitions are resolved.

        Defaults are handled by only setting them on the top-level parser and setting
        a sentinel object in all sub-parsers, which then allows one to discern which parser
        supplied the option.
        """

        def __init__(self, define_common_options, suffix_precedence):
            """
            *define_common_options* should be a callable taking one argument, which
            will be a argparse.Parser.add_argument-like function.

            *define_common_options* will be called multiple times, and should call
            the passed function to define common options exactly the same way each time.

            *suffix_precedence* should be a tuple of the suffixes that will be used.
            It is ordered from lowest precedence to highest precedence:
            An option specified on the parser belonging to index 0 is overridden if the
            same option is specified on any parser with a higher index.
            """
            self.define_common_options = define_common_options
            self.suffix_precedence = suffix_precedence

            # Maps suffixes to sets of target names.
            # E.g. common_options["_subcommand"] = {..., "log_level", ...}
            self.common_options = dict()
            # Set of options with the 'append' action.
            self.append_options = set()
            # This is the sentinel object that replaces all default values in parsers
            # below the top-level parser.
            self.default_sentinel = object()

        def add_common_group(self, parser, suffix, provide_defaults=False):
            """
            Add common options to *parser*.

            *provide_defaults* must only be True exactly once in a parser hierarchy,
            at the top level, and False on all lower levels. The default is chosen
            accordingly.

            *suffix* indicates the suffix to use internally. It also indicates
            which precedence the *parser* has for common options. See *suffix_precedence*
            of __init__.
            """
            assert suffix in self.suffix_precedence

            def add_argument(*args, **kwargs):
                if "dest" in kwargs:
                    kwargs.setdefault("action", "store")
                    assert kwargs["action"] in (
                        Highlander,
                        "help",
                        "store_const",
                        "store_true",
                        "store_false",
                        "store",
                        "append",
                    )
                    is_append = kwargs["action"] == "append"
                    if is_append:
                        self.append_options.add(kwargs["dest"])
                        assert (
                            kwargs["default"] == []
                        ), "The default is explicitly constructed as an empty list in resolve()"
                    else:
                        self.common_options.setdefault(suffix, set()).add(kwargs["dest"])
                    kwargs["dest"] += suffix
                    if not provide_defaults:
                        # Interpolate help now, in case the %(default)d (or so) is mentioned,
                        # to avoid producing incorrect help output.
                        # Assumption: Interpolated output can safely be interpolated again,
                        # which should always be the case.
                        # Note: We control all inputs.
                        kwargs["help"] = kwargs["help"] % kwargs
                        if not is_append:
                            kwargs["default"] = self.default_sentinel

                common_group.add_argument(*args, **kwargs)

            common_group = parser.add_argument_group("Common options")
            self.define_common_options(add_argument)

        def resolve(self, args: argparse.Namespace):  # Namespace has "in" but otherwise is not like a dict.
            """
            Resolve the multiple definitions of each common option to the final value.
            """
            for suffix in self.suffix_precedence:
                # From highest level to lowest level, so the "most-specific" option wins, e.g.
                # "borg --debug create --info" shall result in --info being effective.
                for dest in self.common_options.get(suffix, []):
                    # map_from is this suffix' option name, e.g. log_level_subcommand
                    # map_to is the target name, e.g. log_level
                    map_from = dest + suffix
                    map_to = dest
                    # Retrieve value; depending on the action it may not exist, but usually does
                    # (store_const/store_true/store_false), either because the action implied a default
                    # or a default is explicitly supplied.
                    # Note that defaults on lower levels are replaced with default_sentinel.
                    # Only the top level has defaults.
                    value = getattr(args, map_from, self.default_sentinel)
                    if value is not self.default_sentinel:
                        # value was indeed specified on this level. Transfer value to target,
                        # and un-clobber the args (for tidiness - you *cannot* use the suffixed
                        # names for other purposes, obviously).
                        setattr(args, map_to, value)
                    try:
                        delattr(args, map_from)
                    except AttributeError:
                        pass

            # Options with an "append" action need some special treatment. Instead of
            # overriding values, all specified values are merged together.
            for dest in self.append_options:
                option_value = []
                for suffix in self.suffix_precedence:
                    # Find values of this suffix, if any, and add them to the final list
                    extend_from = dest + suffix
                    if extend_from in args:
                        values = getattr(args, extend_from)
                        delattr(args, extend_from)
                        option_value.extend(values)
                setattr(args, dest, option_value)

    def build_parser(self):
        from ._common import define_common_options

        parser = argparse.ArgumentParser(prog=self.prog, description="Borg - Deduplicated Backups", add_help=False)
        # paths and patterns must have an empty list as default everywhere
        parser.set_defaults(fallback2_func=functools.partial(self.do_maincommand_help, parser), paths=[], patterns=[])
        parser.common_options = self.CommonOptions(
            define_common_options, suffix_precedence=("_maincommand", "_midcommand", "_subcommand")
        )
        parser.add_argument(
            "-V", "--version", action="version", version="%(prog)s " + __version__, help="show version number and exit"
        )
        parser.common_options.add_common_group(parser, "_maincommand", provide_defaults=True)

        common_parser = argparse.ArgumentParser(add_help=False, prog=self.prog)
        common_parser.set_defaults(paths=[], patterns=[])
        parser.common_options.add_common_group(common_parser, "_subcommand")

        mid_common_parser = argparse.ArgumentParser(add_help=False, prog=self.prog)
        mid_common_parser.set_defaults(paths=[], patterns=[])
        parser.common_options.add_common_group(mid_common_parser, "_midcommand")

        if parser.prog == "borgfs":
            return self.build_parser_borgfs(parser)

        subparsers = parser.add_subparsers(title="required arguments", metavar="<command>")

        self.build_parser_analyze(subparsers, common_parser, mid_common_parser)
        self.build_parser_benchmarks(subparsers, common_parser, mid_common_parser)
        self.build_parser_check(subparsers, common_parser, mid_common_parser)
        self.build_parser_compact(subparsers, common_parser, mid_common_parser)
        self.build_parser_create(subparsers, common_parser, mid_common_parser)
        self.build_parser_debug(subparsers, common_parser, mid_common_parser)
        self.build_parser_delete(subparsers, common_parser, mid_common_parser)
        self.build_parser_diff(subparsers, common_parser, mid_common_parser)
        self.build_parser_extract(subparsers, common_parser, mid_common_parser)
        self.build_parser_help(subparsers, common_parser, mid_common_parser, parser)
        self.build_parser_info(subparsers, common_parser, mid_common_parser)
        self.build_parser_keys(subparsers, common_parser, mid_common_parser)
        self.build_parser_list(subparsers, common_parser, mid_common_parser)
        self.build_parser_locks(subparsers, common_parser, mid_common_parser)
        self.build_parser_mount_umount(subparsers, common_parser, mid_common_parser)
        self.build_parser_prune(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_compress(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_create(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_delete(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_info(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_list(subparsers, common_parser, mid_common_parser)
        self.build_parser_recreate(subparsers, common_parser, mid_common_parser)
        self.build_parser_rename(subparsers, common_parser, mid_common_parser)
        self.build_parser_repo_space(subparsers, common_parser, mid_common_parser)
        self.build_parser_serve(subparsers, common_parser, mid_common_parser)
        self.build_parser_tag(subparsers, common_parser, mid_common_parser)
        self.build_parser_tar(subparsers, common_parser, mid_common_parser)
        self.build_parser_transfer(subparsers, common_parser, mid_common_parser)
        self.build_parser_undelete(subparsers, common_parser, mid_common_parser)
        self.build_parser_version(subparsers, common_parser, mid_common_parser)
        return parser

    def get_args(self, argv, cmd):
        """usually, just returns argv, except if we deal with a ssh forced command for borg serve."""
        result = self.parse_args(argv[1:])
        if cmd is not None and result.func == self.do_serve:
            # borg serve case:
            # - "result" is how borg got invoked (e.g. via forced command from authorized_keys),
            # - "client_result" (from "cmd") refers to the command the client wanted to execute,
            #   which might be different in the case of a forced command or same otherwise.
            client_argv = shlex.split(cmd)
            # Drop environment variables (do *not* interpret them) before trying to parse
            # the borg command line.
            client_argv = list(itertools.dropwhile(lambda arg: "=" in arg, client_argv))
            client_result = self.parse_args(client_argv[1:])
            if client_result.func == result.func:
                # make sure we only process like normal if the client is executing
                # the same command as specified in the forced command, otherwise
                # just skip this block and return the forced command (== result).
                # client is allowed to specify the allowlisted options,
                # everything else comes from the forced "borg serve" command (or the defaults).
                # stuff from denylist must never be used from the client.
                denylist = {"restrict_to_paths", "restrict_to_repositories", "umask", "permissions"}
                allowlist = {"debug_topics", "lock_wait", "log_level"}
                not_present = object()
                for attr_name in allowlist:
                    assert attr_name not in denylist, "allowlist has denylisted attribute name %s" % attr_name
                    value = getattr(client_result, attr_name, not_present)
                    if value is not not_present:
                        # note: it is not possible to specify a allowlisted option via a forced command,
                        # it always gets overridden by the value specified (or defaulted to) by the client command.
                        setattr(result, attr_name, value)

        return result

    def parse_args(self, args=None):
        if args:
            args = self.preprocess_args(args)
        parser = self.build_parser()
        args = parser.parse_args(args or ["-h"])
        parser.common_options.resolve(args)
        func = get_func(args)
        if func == self.do_create and args.paths and args.paths_from_stdin:
            parser.error("Must not pass PATH with --paths-from-stdin.")
        if args.progress and getattr(args, "output_list", False) and not args.log_json:
            parser.error("Options --progress and --list do not play nicely together.")
        if func == self.do_create and not args.paths:
            if args.content_from_command or args.paths_from_command:
                parser.error("No command given.")
            elif not args.paths_from_stdin:
                # need at least 1 path but args.paths may also be populated from patterns
                parser.error("Need at least one PATH argument.")
        # we can only have a complete knowledge of placeholder replacements we should do **after** arg parsing,
        # e.g. due to options like --timestamp that override the current time.
        # thus we have to initialize replace_placeholders here and process all args that need placeholder replacement.
        if getattr(args, "timestamp", None):
            replace_placeholders.override("now", DatetimeWrapper(args.timestamp))
            replace_placeholders.override("utcnow", DatetimeWrapper(args.timestamp.astimezone(timezone.utc)))
            args.location = args.location.with_timestamp(args.timestamp)
        for name in "name", "other_name", "newname", "comment":
            value = getattr(args, name, None)
            if value is not None:
                setattr(args, name, replace_placeholders(value))
        for name in ("match_archives",):  # lists
            value = getattr(args, name, None)
            if value:
                setattr(args, name, [replace_placeholders(elem) for elem in value])

        return args

    def prerun_checks(self, logger, is_serve):
        if not is_serve:
            # this is the borg *client*, we need to check the python:
            check_python()
        check_extension_modules()
        selftest(logger)

    def _setup_implied_logging(self, args):
        """turn on INFO level logging for args that imply that they will produce output"""
        # map of option name to name of logger for that option
        option_logger = {
            "show_version": "borg.output.show-version",
            "show_rc": "borg.output.show-rc",
            "stats": "borg.output.stats",
            "progress": "borg.output.progress",
        }
        for option, logger_name in option_logger.items():
            option_set = args.get(option, False)
            logging.getLogger(logger_name).setLevel("INFO" if option_set else "WARN")

        # special-case --list / --list-kept / --list-pruned as they all work on same logger
        options = [args.get(name, False) for name in ("output_list", "list_kept", "list_pruned")]
        logging.getLogger("borg.output.list").setLevel("INFO" if any(options) else "WARN")

    def _setup_topic_debugging(self, args):
        """Turn on DEBUG level logging for specified --debug-topics."""
        for topic in args.debug_topics:
            if "." not in topic:
                topic = "borg.debug." + topic
            logger.debug("Enabling debug topic %s", topic)
            logging.getLogger(topic).setLevel("DEBUG")

    def run(self, args):
        os.umask(args.umask)  # early, before opening files
        self.lock_wait = args.lock_wait
        func = get_func(args)
        # do not use loggers before this!
        is_serve = func == self.do_serve
        self.log_json = args.log_json and not is_serve
        func_name = getattr(func, "__name__", "none")
        setup_logging(level=args.log_level, is_serve=is_serve, log_json=self.log_json, func=func_name)
        args.progress |= is_serve
        self._setup_implied_logging(vars(args))
        self._setup_topic_debugging(args)
        if getattr(args, "stats", False) and getattr(args, "dry_run", False):
            # the data needed for --stats is not computed when using --dry-run, so we can't do it.
            # for ease of scripting, we just ignore --stats when given with --dry-run.
            logger.warning("Ignoring --stats. It is not supported when using --dry-run.")
            args.stats = False
        if args.show_version:
            logging.getLogger("borg.output.show-version").info("borgbackup version %s" % __version__)
        self.prerun_checks(logger, is_serve)
        if not is_supported_msgpack():
            logger.error("You do not have a supported version of the msgpack python package installed. Terminating.")
            logger.error("This should never happen as specific, supported versions are required by our pyproject.toml.")
            logger.error("Do not contact borgbackup support about this.")
            raise Error("unsupported msgpack version")
        if is_slow_msgpack():
            logger.warning(PURE_PYTHON_MSGPACK_WARNING)
        if args.debug_profile:
            # Import only when needed - avoids a further increase in startup time
            import cProfile
            import marshal

            logger.debug("Writing execution profile to %s", args.debug_profile)
            # Open the file early, before running the main program, to avoid
            # a very late crash in case the specified path is invalid.
            with open(args.debug_profile, "wb") as fd:
                profiler = cProfile.Profile()
                variables = dict(locals())
                profiler.enable()
                try:
                    return get_ec(func(args))
                finally:
                    profiler.disable()
                    profiler.snapshot_stats()
                    if args.debug_profile.endswith(".pyprof"):
                        marshal.dump(profiler.stats, fd)
                    else:
                        # We use msgpack here instead of the marshal module used by cProfile itself,
                        # because the latter is insecure. Since these files may be shared over the
                        # internet we don't want a format that is impossible to interpret outside
                        # an insecure implementation.
                        # See scripts/msgpack2marshal.py for a small script that turns a msgpack file
                        # into a marshal file that can be read by e.g. pyprof2calltree.
                        # For local use it's unnecessary hassle, though, that's why .pyprof makes
                        # it compatible (see above).
                        msgpack.pack(profiler.stats, fd, use_bin_type=True)
        else:
            rc = func(args)
            assert rc is None
            return get_ec(rc)


def sig_info_handler(sig_no, stack):  # pragma: no cover
    """search the stack for infos about the currently processed file and print them"""
    with signal_handler(sig_no, signal.SIG_IGN):
        for frame in inspect.getouterframes(stack):
            func, loc = frame[3], frame[0].f_locals
            if func in ("process_file", "_rec_walk"):  # create op
                path = loc["path"]
                try:
                    pos = loc["fd"].tell()
                    total = loc["st"].st_size
                except Exception:
                    pos, total = 0, 0
                logger.info(f"{path} {format_file_size(pos)}/{format_file_size(total)}")
                break
            if func in ("extract_item",):  # extract op
                path = loc["item"].path
                try:
                    pos = loc["fd"].tell()
                except Exception:
                    pos = 0
                logger.info(f"{path} {format_file_size(pos)}/???")
                break


def sig_trace_handler(sig_no, stack):  # pragma: no cover
    print("\nReceived SIGUSR2 at %s, dumping trace..." % datetime.now().replace(microsecond=0), file=sys.stderr)
    faulthandler.dump_traceback()


def format_tb(exc):
    qualname = type(exc).__qualname__
    remote = isinstance(exc, RemoteRepository.RPCError)
    if remote:
        prefix = "Borg server: "
        trace_back = "\n".join(prefix + line for line in exc.exception_full.splitlines())
        sys_info = "\n".join(prefix + line for line in exc.sysinfo.splitlines())
    else:
        trace_back = traceback.format_exc()
        sys_info = sysinfo()
    result = f"""
Error:

{qualname}: {exc}

If reporting bugs, please include the following:

{trace_back}
{sys_info}
"""
    return result


def main():  # pragma: no cover
    # Make sure stdout and stderr have errors='replace' to avoid unicode
    # issues when print()-ing unicode file names
    sys.stdout = ErrorIgnoringTextIOWrapper(sys.stdout.buffer, sys.stdout.encoding, "replace", line_buffering=True)
    sys.stderr = ErrorIgnoringTextIOWrapper(sys.stderr.buffer, sys.stderr.encoding, "replace", line_buffering=True)

    # If we receive SIGINT (ctrl-c), SIGTERM (kill) or SIGHUP (kill -HUP),
    # catch them and raise a proper exception that can be handled for an
    # orderly exit.
    # SIGHUP is important especially for systemd systems, where logind
    # sends it when a session exits, in addition to any traditional use.
    # Output some info if we receive SIGUSR1 or SIGINFO (ctrl-t).

    # Register fault handler for SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL.
    faulthandler.enable()
    with (
        signal_handler("SIGINT", raising_signal_handler(KeyboardInterrupt)),
        signal_handler("SIGHUP", raising_signal_handler(SigHup)),
        signal_handler("SIGTERM", raising_signal_handler(SigTerm)),
        signal_handler("SIGUSR1", sig_info_handler),
        signal_handler("SIGUSR2", sig_trace_handler),
        signal_handler("SIGINFO", sig_info_handler),
    ):
        archiver = Archiver()
        msg = msgid = tb = None
        tb_log_level = logging.ERROR
        try:
            args = archiver.get_args(sys.argv, os.environ.get("SSH_ORIGINAL_COMMAND"))
        except Error as e:
            # we might not have logging setup yet, so get out quickly
            msg = e.get_message()
            print(msg, file=sys.stderr)
            if e.traceback:
                tb = format_tb(e)
                print(tb, file=sys.stderr)
            sys.exit(e.exit_code)
        except argparse.ArgumentTypeError as e:
            # we might not have logging setup yet, so get out quickly
            print(str(e), file=sys.stderr)
            sys.exit(CommandError.exit_mcode if modern_ec else EXIT_ERROR)
        except Exception:
            msg = "Local Exception"
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            # we might not have logging setup yet, so get out quickly
            print(msg, file=sys.stderr)
            print(tb, file=sys.stderr)
            sys.exit(EXIT_ERROR)
        try:
            with sig_int:
                exit_code = archiver.run(args)
        except Error as e:
            msg = e.get_message()
            msgid = type(e).__qualname__
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = format_tb(e)
            exit_code = e.exit_code
        except RemoteRepository.RPCError as e:
            important = e.traceback
            msg = e.exception_full if important else e.get_message()
            msgid = e.exception_class
            tb_log_level = logging.ERROR if important else logging.DEBUG
            tb = format_tb(e)
            exit_code = EXIT_ERROR
        except Exception as e:
            msg = "Local Exception"
            msgid = "Exception"
            tb_log_level = logging.ERROR
            tb = format_tb(e)
            exit_code = EXIT_ERROR
        except KeyboardInterrupt as e:
            msg = "Keyboard interrupt"
            tb_log_level = logging.DEBUG
            tb = format_tb(e)
            exit_code = EXIT_SIGNAL_BASE + 2
        except SigTerm as e:
            msg = "Received SIGTERM"
            msgid = "Signal.SIGTERM"
            tb_log_level = logging.DEBUG
            tb = format_tb(e)
            exit_code = EXIT_SIGNAL_BASE + 15
        except SigHup as e:
            msg = "Received SIGHUP."
            msgid = "Signal.SIGHUP"
            tb_log_level = logging.DEBUG
            tb = format_tb(e)
            exit_code = EXIT_SIGNAL_BASE + 1
        if msg:
            logger.error(msg, msgid=msgid)
        if tb:
            logger.log(tb_log_level, tb)
        if args.show_rc:
            rc_logger = logging.getLogger("borg.output.show-rc")
            exit_msg = "terminating with %s status, rc %d"
            try:
                ec_class = classify_ec(exit_code)
            except ValueError:
                rc_logger.error(exit_msg % ("abnormal", exit_code or 666))
            else:
                if ec_class == "success":
                    rc_logger.info(exit_msg % (ec_class, exit_code))
                elif ec_class == "warning":
                    rc_logger.warning(exit_msg % (ec_class, exit_code))
                elif ec_class == "error":
                    rc_logger.error(exit_msg % (ec_class, exit_code))
                elif ec_class == "signal":
                    rc_logger.error(exit_msg % (ec_class, exit_code))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
