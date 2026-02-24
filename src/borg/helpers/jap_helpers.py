import argparse
from typing import Any


def flatten_namespace(ns: Any) -> argparse.Namespace:
    """
    Recursively flattens a nested namespace into a single-level namespace.
    JSONArgparse uses nested namespaces for subcommands, whereas borg's
    internal dispatch and logic expect a flat namespace.
    """
    flat = argparse.Namespace()
    
    # Extract the nested path of subcommands
    subcmds = []
    current = ns
    while current and hasattr(current, "subcommand") and current.subcommand:
        subcmds.append(current.subcommand)
        current = getattr(current, current.subcommand, None)
        
    if subcmds:
        flat.subcommand = " ".join(subcmds)
    
    def _flatten(source, target):
        items = vars(source).items() if hasattr(source, '__dict__') else source.items() if hasattr(source, 'items') else []
        for k, v in items:
            if isinstance(v, argparse.Namespace) or type(v).__name__ == 'Namespace':
                _flatten(v, target)
            else:
                if k != "subcommand" and not hasattr(target, k):
                    setattr(target, k, v)
                    
    _flatten(ns, flat)
    return flat
