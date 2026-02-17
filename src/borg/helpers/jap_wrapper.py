"""Borg-specific ArgumentParser wrapping jsonargparse.

This module provides a compatibility layer between Borg's argparse patterns
and jsonargparse's API. Key adaptations:

1. type+action combination: jsonargparse forbids combining type= and action=
   in add_argument(). Our override keeps type= at call sites for readability
   and wraps both into a composite action class that jsonargparse accepts.

2. Namespace flattening: jsonargparse creates nested namespaces for subcommands
   (args.create.name instead of args.name). flatten_namespace() merges these
   into a flat namespace compatible with Borg's command handlers.
"""

import argparse

from jsonargparse import ArgumentParser as _JAPArgumentParser
from jsonargparse._core import ArgumentGroup as _JAPArgumentGroup


def _make_type_converting_action(base_action_name, type_fn):
    """Create a custom action class that wraps a standard action and applies type conversion.

    jsonargparse forbids type+action, so we strip both from kwargs and replace
    them with a single composite action class that does type conversion + action.
    """
    _action_map = {"append": argparse._AppendAction, "store": argparse._StoreAction}
    base_cls = _action_map.get(base_action_name)
    if base_cls is None:
        return None

    class TypeConvertingAction(base_cls):
        def __call__(self, parser, namespace, values, option_string=None):
            if type_fn is not None and isinstance(values, str):
                try:
                    values = type_fn(values)
                except argparse.ArgumentTypeError as e:
                    raise argparse.ArgumentError(self, str(e))
            super().__call__(parser, namespace, values, option_string)

    TypeConvertingAction.__name__ = f"TypeConverting{base_action_name.title()}Action"
    return TypeConvertingAction


class BorgAddArgumentMixin:
    """Mixin that handles the type+action combination jsonargparse forbids.

    Call sites can use both type= and action= naturally (e.g. type=parse_exclude_pattern,
    action="append"). This mixin intercepts the call, strips both, and creates a
    composite action class that jsonargparse accepts.
    """

    def add_argument(self, *args, **kwargs):
        action = kwargs.get("action")
        if action is not None and "type" in kwargs and isinstance(action, str):
            type_fn = kwargs.pop("type")
            wrapper = _make_type_converting_action(action, type_fn)
            if wrapper is not None:
                kwargs["action"] = wrapper
            else:
                # Unknown action string, put type back and hope for the best.
                kwargs["type"] = type_fn
        return super().add_argument(*args, **kwargs)


class ArgumentGroup(BorgAddArgumentMixin, _JAPArgumentGroup):
    """ArgumentGroup that supports Borg's add_argument patterns."""

    pass


class ArgumentParser(BorgAddArgumentMixin, _JAPArgumentParser):
    """ArgumentParser bridging Borg's argparse patterns with jsonargparse."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Force jsonargparse to use our ArgumentGroup class instead of trying to
        # auto-generate one from source code (which is fragile and fails on Windows CI).
        self._group_class = ArgumentGroup


def flatten_namespace(args):
    """Flatten jsonargparse's nested namespace into a flat one.

    jsonargparse creates nested namespaces for subcommands:
        args.subcommand = "create"
        args.create = Namespace(name="myarchive", ...)

    Borg expects a flat namespace:
        args.name = "myarchive"

    For nested subcommands (key export, debug info, benchmark crud):
        args.subcommand = "key"
        args.key.subcommand = "export"
        args.key.export = Namespace(path="/tmp/k", ...)
    becomes:
        args.subcommand = "key"
        args.path = "/tmp/k"
    """
    subcmd = getattr(args, "subcommand", None)
    if subcmd is None:
        return args

    subcmd_ns = getattr(args, subcmd, None)
    if subcmd_ns is None:
        return args

    # Handle nested subcommand (e.g., "key export")
    nested_subcmd = getattr(subcmd_ns, "subcommand", None)
    if nested_subcmd is not None:
        nested_ns = getattr(subcmd_ns, nested_subcmd, None)
        if nested_ns is not None:
            for key, val in vars(nested_ns).items():
                if key != "subcommand":
                    setattr(args, key, val)

    # Flatten the direct subcommand namespace
    for key, val in vars(subcmd_ns).items():
        if key == "subcommand":
            continue
        if isinstance(val, argparse.Namespace):
            continue  # Skip nested namespace (already handled above)
        setattr(args, key, val)

    # Ensure paths and patterns exist as lists (used as accumulation targets during parsing).
    # jsonargparse may set these to None rather than omitting them.
    if not getattr(args, "paths", None):
        args.paths = []
    if not getattr(args, "patterns", None):
        args.patterns = []

    # Merge roots from pattern files (R lines in --patterns-from) with CLI paths.
    # Pattern file roots are stored separately during parsing to avoid being
    # overwritten by the positional "paths" argument.
    from ..patterns import ArgparsePatternFileAction

    roots_from_patterns = ArgparsePatternFileAction.roots_from_patterns
    if roots_from_patterns:
        args.paths = list(roots_from_patterns) + args.paths
        ArgparsePatternFileAction.roots_from_patterns.clear()

    return args
