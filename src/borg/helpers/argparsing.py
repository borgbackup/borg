from typing import Any

# here are the only imports from argparse and jsonargparse,
# all other imports of these names import them from here:
from argparse import Action, ArgumentError, ArgumentTypeError, RawDescriptionHelpFormatter  # noqa: F401
from jsonargparse import ArgumentParser, Namespace, SUPPRESS, REMAINDER  # noqa: F401

# borg completion uses these private symbols, so we need to import them:
from jsonargparse._actions import _ActionSubCommands  # noqa: F401
from jsonargparse._completions import prepare_actions_context, shtab_prepare_actions  # noqa: F401
from jsonargparse._completions import bash_compgen_typehint  # noqa: F401


def flatten_namespace(ns: Any) -> Namespace:
    """
    Recursively flattens a nested namespace into a single-level namespace.
    JSONArgparse uses nested namespaces for subcommands, whereas borg's
    internal dispatch and logic expect a flat namespace.
    """
    flat = Namespace()

    # Extract the nested path of subcommands
    subcmds = []
    current = ns
    while current and hasattr(current, "subcommand") and current.subcommand:
        subcmds.append(current.subcommand)
        current = getattr(current, current.subcommand, None)

    if subcmds:
        flat.subcommand = " ".join(subcmds)

    def _flatten(source, target):
        items = (
            vars(source).items() if hasattr(source, "__dict__") else source.items() if hasattr(source, "items") else []
        )
        for k, v in items:
            if isinstance(v, Namespace) or type(v).__name__ == "Namespace":
                _flatten(v, target)
            else:
                if k != "subcommand" and not hasattr(target, k):
                    setattr(target, k, v)

    _flatten(ns, flat)
    return flat
