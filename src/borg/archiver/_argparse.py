"""Borg-specific ArgumentParser wrapping jsonargparse.

This module provides a compatibility layer between Borg's argparse patterns
and jsonargparse's API. Key adaptations:

1. type+action combination: jsonargparse forbids combining type= and action=
   in add_argument(). Our override strips type= from kwargs and ensures
   type conversion happens within the action itself:
   - Highlander action class: handles type via _type_fn (pops type in __init__)
   - Standard actions (append, store, etc.): wrapped in TypeConvertingAction
   - Custom action classes: type is popped and stored on the action after creation

2. Namespace flattening: jsonargparse creates nested namespaces for subcommands
   (args.create.name instead of args.name). flatten_namespace() merges these
   into a flat namespace compatible with Borg's command handlers.
"""

import argparse

from jsonargparse import ArgumentParser as _JAPArgumentParser


def _is_highlander_action(action):
    """Check if action is a Highlander subclass."""
    try:
        from ..helpers.parseformat import Highlander
    except ImportError:
        return False
    return isinstance(action, type) and issubclass(action, Highlander)


def _make_type_converting_action(base_action_name, type_fn):
    """Create a custom action class that wraps a standard action and applies type conversion.

    This is used for standard string actions (e.g. 'append', 'store') when combined with type=.
    jsonargparse forbids type+action, so we strip type= and wrap the action to do conversion.
    """
    # Map action name to argparse's built-in action class
    _action_map = {"append": argparse._AppendAction, "store": argparse._StoreAction}

    base_cls = _action_map.get(base_action_name)
    if base_cls is None:
        # Unknown action string - can't wrap it
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


class ArgumentParser(_JAPArgumentParser):
    """ArgumentParser bridging Borg's argparse patterns with jsonargparse."""

    def add_argument(self, *args, **kwargs):
        """Handle type+action combination that jsonargparse forbids.

        jsonargparse raises ValueError when both type= and action= are given.
        We strip type= from kwargs and ensure the action handles type conversion:
        - Highlander/subclasses: type bound as class attribute _type_fn_override
        - Standard string actions: wrapped in TypeConvertingAction
        - Other custom actions: type stored as _type_fn on action instance
        """
        action = kwargs.get("action")
        if action is not None and "type" in kwargs:
            type_fn = kwargs.pop("type")

            if _is_highlander_action(action):
                # Create a dynamic subclass with _type_fn pre-bound as a class attribute.
                # Highlander's __init__ will pick this up.
                action_cls = action

                class BoundHighlander(action_cls):
                    _type_fn_override = type_fn

                BoundHighlander.__name__ = action_cls.__name__
                BoundHighlander.__qualname__ = action_cls.__qualname__
                kwargs["action"] = BoundHighlander
                return super().add_argument(*args, **kwargs)

            if isinstance(action, str):
                # Standard action string like 'append', 'store'
                wrapper = _make_type_converting_action(action, type_fn)
                if wrapper is not None:
                    kwargs["action"] = wrapper
                    return super().add_argument(*args, **kwargs)
                else:
                    # Unknown standard action, put type back and try anyway
                    kwargs["type"] = type_fn

            elif isinstance(action, type) and issubclass(action, argparse.Action):
                # Custom action class - register without type, then patch the action
                result = super().add_argument(*args, **kwargs)
                # Store type_fn on the action for potential manual use
                if hasattr(result, "_type_fn"):
                    pass  # already handled
                else:
                    result._type_fn = type_fn
                return result

        return super().add_argument(*args, **kwargs)


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

    return args
