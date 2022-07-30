# borg cli interface / toplevel archiver code

import sys
import traceback

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
    import time
    from datetime import datetime

    from ..logger import create_logger, setup_logging

    logger = create_logger()

    from .. import __version__
    from ..constants import *  # NOQA
    from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR, EXIT_SIGNAL_BASE
    from ..helpers import Error, set_ec
    from ..helpers import format_file_size
    from ..helpers import remove_surrogates
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


from .benchmarks import BenchmarkMixIn
from .check import CheckMixIn
from .compact import CompactMixIn
from .config import ConfigMixIn
from .create import CreateMixIn
from .debug import DebugMixIn
from .delete import DeleteMixIn
from .diff import DiffMixIn
from .extract import ExtractMixIn
from .help import HelpMixIn
from .info import InfoMixIn
from .keys import KeysMixIn
from .list_cmd import ListMixIn
from .locks import LocksMixIn
from .mount import MountMixIn
from .prune import PruneMixIn
from .recreate import RecreateMixIn
from .rename import RenameMixIn
from .rcreate import RCreateMixIn
from .rinfo import RInfoMixIn
from .rdelete import RDeleteMixIn
from .rlist import RListMixIn
from .serve import ServeMixIn
from .tar import TarMixIn
from .transfer import TransferMixIn


class Archiver(
    BenchmarkMixIn,
    CheckMixIn,
    CompactMixIn,
    ConfigMixIn,
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
    RCreateMixIn,
    RDeleteMixIn,
    RInfoMixIn,
    RListMixIn,
    ServeMixIn,
    TarMixIn,
    TransferMixIn,
):
    def __init__(self, lock_wait=None, prog=None):
        self.exit_code = EXIT_SUCCESS
        self.lock_wait = lock_wait
        self.prog = prog
        self.last_checkpoint = time.monotonic()

    def print_error(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_ERROR
        logger.error(msg)

    def print_warning(self, msg, *args):
        msg = args and msg % args or msg
        self.exit_code = EXIT_WARNING  # we do not terminate here, so it is a warning
        logger.warning(msg)

    def print_file_status(self, status, path):
        # if we get called with status == None, the final file status was already printed
        if self.output_list and status is not None and (self.output_filter is None or status in self.output_filter):
            if self.log_json:
                print(
                    json.dumps({"type": "file_status", "status": status, "path": remove_surrogates(path)}),
                    file=sys.stderr,
                )
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
                    assert kwargs["action"] in ("help", "store_const", "store_true", "store_false", "store", "append")
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
        from .common import define_common_options

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

        self.build_parser_benchmarks(subparsers, common_parser, mid_common_parser)
        self.build_parser_check(subparsers, common_parser, mid_common_parser)
        self.build_parser_compact(subparsers, common_parser, mid_common_parser)
        self.build_parser_config(subparsers, common_parser, mid_common_parser)
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
        self.build_parser_rcreate(subparsers, common_parser, mid_common_parser)
        self.build_parser_rdelete(subparsers, common_parser, mid_common_parser)
        self.build_parser_rinfo(subparsers, common_parser, mid_common_parser)
        self.build_parser_rlist(subparsers, common_parser, mid_common_parser)
        self.build_parser_recreate(subparsers, common_parser, mid_common_parser)
        self.build_parser_rename(subparsers, common_parser, mid_common_parser)
        self.build_parser_serve(subparsers, common_parser, mid_common_parser)
        self.build_parser_tar(subparsers, common_parser, mid_common_parser)
        self.build_parser_transfer(subparsers, common_parser, mid_common_parser)
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
                denylist = {"restrict_to_paths", "restrict_to_repositories", "append_only", "storage_quota", "umask"}
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
        # We can't use argparse for "serve" since we don't want it to show up in "Available commands"
        if args:
            args = self.preprocess_args(args)
        parser = self.build_parser()
        args = parser.parse_args(args or ["-h"])
        parser.common_options.resolve(args)
        func = get_func(args)
        if func == self.do_create and args.paths and args.paths_from_stdin:
            parser.error("Must not pass PATH with ``--paths-from-stdin``.")
        if func == self.do_create and not args.paths:
            if args.content_from_command or args.paths_from_command:
                parser.error("No command given.")
            elif not args.paths_from_stdin:
                # need at least 1 path but args.paths may also be populated from patterns
                parser.error("Need at least one PATH argument.")
        if not getattr(args, "lock", True):  # Option --bypass-lock sets args.lock = False
            bypass_allowed = {
                self.do_check,
                self.do_config,
                self.do_diff,
                self.do_export_tar,
                self.do_extract,
                self.do_info,
                self.do_rinfo,
                self.do_list,
                self.do_rlist,
                self.do_mount,
                self.do_umount,
            }
            if func not in bypass_allowed:
                raise Error("Not allowed to bypass locking mechanism for chosen command")
        if getattr(args, "timestamp", None):
            args.location = args.location.with_timestamp(args.timestamp)
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
            "output_list": "borg.output.list",
            "show_version": "borg.output.show-version",
            "show_rc": "borg.output.show-rc",
            "stats": "borg.output.stats",
            "progress": "borg.output.progress",
        }
        for option, logger_name in option_logger.items():
            option_set = args.get(option, False)
            logging.getLogger(logger_name).setLevel("INFO" if option_set else "WARN")

    def _setup_topic_debugging(self, args):
        """Turn on DEBUG level logging for specified --debug-topics."""
        for topic in args.debug_topics:
            if "." not in topic:
                topic = "borg.debug." + topic
            logger.debug("Enabling debug topic %s", topic)
            logging.getLogger(topic).setLevel("DEBUG")

    def maybe_checkpoint(self, *, checkpoint_func, checkpoint_interval):
        checkpointed = False
        sig_int_triggered = sig_int and sig_int.action_triggered()
        if sig_int_triggered or checkpoint_interval and time.monotonic() - self.last_checkpoint > checkpoint_interval:
            if sig_int_triggered:
                logger.info("checkpoint requested: starting checkpoint creation...")
            checkpoint_func()
            checkpointed = True
            self.last_checkpoint = time.monotonic()
            if sig_int_triggered:
                sig_int.action_completed()
                logger.info("checkpoint requested: finished checkpoint creation!")
        return checkpointed

    def run(self, args):
        os.umask(args.umask)  # early, before opening files
        self.lock_wait = args.lock_wait
        func = get_func(args)
        # do not use loggers before this!
        is_serve = func == self.do_serve
        setup_logging(level=args.log_level, is_serve=is_serve, json=args.log_json)
        self.log_json = args.log_json
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
            logger.error("This should never happen as specific, supported versions are required by our setup.py.")
            logger.error("Do not contact borgbackup support about this.")
            return set_ec(EXIT_ERROR)
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
                    return set_ec(func(args))
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
            return set_ec(func(args))


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
    with signal_handler("SIGINT", raising_signal_handler(KeyboardInterrupt)), signal_handler(
        "SIGHUP", raising_signal_handler(SigHup)
    ), signal_handler("SIGTERM", raising_signal_handler(SigTerm)), signal_handler(
        "SIGUSR1", sig_info_handler
    ), signal_handler(
        "SIGUSR2", sig_trace_handler
    ), signal_handler(
        "SIGINFO", sig_info_handler
    ):
        archiver = Archiver()
        msg = msgid = tb = None
        tb_log_level = logging.ERROR
        try:
            args = archiver.get_args(sys.argv, os.environ.get("SSH_ORIGINAL_COMMAND"))
        except Error as e:
            msg = e.get_message()
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            # we might not have logging setup yet, so get out quickly
            print(msg, file=sys.stderr)
            if tb_log_level == logging.ERROR:
                print(tb, file=sys.stderr)
            sys.exit(e.exit_code)
        try:
            with sig_int:
                exit_code = archiver.run(args)
        except Error as e:
            msg = e.get_message()
            msgid = type(e).__qualname__
            tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = e.exit_code
        except RemoteRepository.RPCError as e:
            important = e.exception_class not in ("LockTimeout",) and e.traceback
            msgid = e.exception_class
            tb_log_level = logging.ERROR if important else logging.DEBUG
            if important:
                msg = e.exception_full
            else:
                msg = e.get_message()
            tb = "\n".join("Borg server: " + l for l in e.sysinfo.splitlines())
            tb += "\n" + sysinfo()
            exit_code = EXIT_ERROR
        except Exception:
            msg = "Local Exception"
            msgid = "Exception"
            tb_log_level = logging.ERROR
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_ERROR
        except KeyboardInterrupt:
            msg = "Keyboard interrupt"
            tb_log_level = logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_SIGNAL_BASE + 2
        except SigTerm:
            msg = "Received SIGTERM"
            msgid = "Signal.SIGTERM"
            tb_log_level = logging.DEBUG
            tb = f"{traceback.format_exc()}\n{sysinfo()}"
            exit_code = EXIT_SIGNAL_BASE + 15
        except SigHup:
            msg = "Received SIGHUP."
            msgid = "Signal.SIGHUP"
            exit_code = EXIT_SIGNAL_BASE + 1
        if msg:
            logger.error(msg, msgid=msgid)
        if tb:
            logger.log(tb_log_level, tb)
        if args.show_rc:
            rc_logger = logging.getLogger("borg.output.show-rc")
            exit_msg = "terminating with %s status, rc %d"
            if exit_code == EXIT_SUCCESS:
                rc_logger.info(exit_msg % ("success", exit_code))
            elif exit_code == EXIT_WARNING:
                rc_logger.warning(exit_msg % ("warning", exit_code))
            elif exit_code == EXIT_ERROR:
                rc_logger.error(exit_msg % ("error", exit_code))
            elif exit_code >= EXIT_SIGNAL_BASE:
                rc_logger.error(exit_msg % ("signal", exit_code))
            else:
                rc_logger.error(exit_msg % ("abnormal", exit_code or 666))
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
