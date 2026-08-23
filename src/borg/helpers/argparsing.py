"""
Borg argument-parsing layer
===========================

All imports of ``ArgumentParser``, ``Namespace``, ``SUPPRESS``, etc. come
from this module.  It is the single seam between borg and the underlying
parser library (jsonargparse).

Library choice
--------------
Borg uses **jsonargparse** instead of plain argparse.  jsonargparse is a
superset of argparse that additionally supports:

* reading arguments from YAML/JSON config files (``--config``)
* reading arguments from environment variables
* nested namespaces for subcommands (each subcommand's arguments live in
  their own ``Namespace`` object rather than the flat top-level namespace)

Parser hierarchy
----------------
Borg's command line has up to three levels::

    borg [common-opts] <command> [common-opts] [<subcommand> [common-opts] [args]]

    e.g.  borg --info create ...
          borg create --info ...
          borg debug info --debug ...

Three ``ArgumentParser`` instances are constructed in ``build_parser()``:

``parser`` (top-level)
    The root parser.  Common options are registered here **with real
    defaults** (``provide_defaults=True``).

``common_parser``
    A helper parser (``add_help=False``) passed as ``parents=[common_parser]``
    to every *leaf* subcommand parser (e.g. ``create``, ``repo-create``, …).
    Common options are registered here **with** ``default=SUPPRESS`` so that
    an option not given on the command line leaves no attribute at all in the
    subcommand namespace.

``mid_common_parser``
    Same as ``common_parser`` but used as the parent for *group* subcommand
    parsers that introduce a second level (e.g. ``debug``, ``key``,
    ``benchmark``).  Their *leaf* subcommand parsers also use
    ``mid_common_parser`` as a parent.

Common options (``--info``, ``--debug``, ``--repo``, ``--lock-wait``, …)
are managed by ``Archiver.CommonOptions``, which calls
``define_common_options()`` once per parser so the same options appear at
every level with identical ``dest`` names.

Namespace flattening and precedence
-------------------------------------
jsonargparse stores each subcommand's parsed values in a nested
``Namespace`` object::

    # borg --info create --debug ...
    Namespace(
        log_level = "info",          # top-level
        subcommand = "create",
        create = Namespace(
            log_level = "debug",     # subcommand level
            ...
        )
    )

After ``parser.parse_args()`` returns, ``flatten_namespace()`` collapses
this tree into a single ``Namespace`` that borg's dispatch and command
implementations expect.

Precedence rule:  the **most-specific** (innermost) value wins.
``flatten_namespace`` uses ``Namespace.as_flat()`` (provided by jsonargparse)
to linearise the nested tree into a flat dict with dotted keys encoding
depth, for example::

    log_level            = "info"     # top-level (0 dots)
    create.log_level     = "debug"    # one level deep (1 dot)
    debug.info.log_level = "critical" # two levels deep (2 dots)

The entries are then sorted deepest-first so the most-specific value is
encountered first and wins.  Shallower values only fill in if the key
has not been set yet.

Special case — append-action options (e.g. ``--debug-topic``):
If a key already holds a list and the outer level also supplies a list,
the two lists are **merged** (outer values first, inner values last) so
that ``borg --debug-topic foo create --debug-topic bar`` accumulates
``["foo", "bar"]`` rather than losing one of the values.

The ``SUPPRESS`` default on sub-parsers is essential: if a common option
is not given at the subcommand level, it simply produces no attribute in
the subcommand namespace and the outer (top-level) default flows through
unchanged.
"""

import re
from typing import Any

# here are the only imports from argparse and jsonargparse,
# all other imports of these names import them from here:
from argparse import Action, ArgumentError, ArgumentTypeError, RawDescriptionHelpFormatter  # noqa: F401
from jsonargparse import ArgumentParser as _ArgumentParser  # we subclass that to add custom behavior
from jsonargparse import Namespace, ActionSubCommands, SUPPRESS, REMAINDER  # noqa: F401
from jsonargparse.typing import register_type, PositiveInt  # noqa: F401


# jsonargparse reports a missing required argument by its config key (the dotted path it has in a
# config file), e.g. "repo-create.encryption". On the command line that argument is "--encryption"
# though, so translate the message, see #3086.
MISSING_REQUIRED_RE = re.compile(r"^Option '(?P<key>[^']+)' is required but not provided or its value is None\.$")


class ArgumentParser(_ArgumentParser):
    # the borg code always uses RawDescriptionHelpFormatter and add_help=False:
    def __init__(self, *args, formatter_class=RawDescriptionHelpFormatter, add_help=False, **kwargs):
        super().__init__(*args, formatter_class=formatter_class, add_help=add_help, **kwargs)

    def _find_by_key(self, key):
        """Resolve a jsonargparse config key to the (sub)parser it belongs to and its action."""
        *subcommands, dest = key.split(".")
        parser = self
        for subcommand in subcommands:
            action = next((a for a in parser._actions if isinstance(a, ActionSubCommands)), None)
            if action is None or subcommand not in action.choices:
                return None, None
            parser = action.choices[subcommand]
        return parser, next((a for a in parser._actions if a.dest == dest), None)

    def error(self, message: str, ex=None):
        match = MISSING_REQUIRED_RE.match(message)
        if match:
            parser, action = self._find_by_key(match["key"])
            if action is not None:
                # name it as argparse does: all option strings for an option, the metavar otherwise
                name = "/".join(action.option_strings) or action.metavar or action.dest
                message = f"the following arguments are required: {name}"
                if ex is not None and parser is not self:
                    # make the usage/help hints refer to the subcommand the argument belongs to
                    ex.subcommand_parser = parser
        super().error(message, ex)


def flatten_namespace(ns: Any) -> Namespace:
    """
    Flattens the nested namespace jsonargparse produces for subcommands into a
    single-level namespace that borg's dispatch and command implementations expect.

    Inner (subcommand) values take precedence over outer (top-level) values.
    For list-typed values (append-action options like --debug-topic) that appear
    at multiple levels, the lists are merged: outer values first, inner values last.
    """
    flat = Namespace()

    # Extract the joined subcommand path from the nested namespace tree.
    subcmds = []
    current = ns
    while current and hasattr(current, "subcommand") and current.subcommand:
        subcmds.append(current.subcommand)
        current = getattr(current, current.subcommand, None)

    if subcmds:
        flat.subcommand = " ".join(subcmds)

    # as_flat() linearises the nested tree into dotted-key entries, e.g.:
    #   log_level='info'               (outer, 0 dots)
    #   create.log_level='debug'       (subcommand, 1 dot)
    #   debug.info.log_level='crit'    (two-level subcommand, 2 dots)
    # Sorting deepest-first ensures the most-specific value is processed first and therefore wins ("inner wins" rule).
    all_items = sorted(vars(ns.as_flat()).items(), key=lambda kv: kv[0].count("."), reverse=True)

    for dotted_key, value in all_items:
        dest = dotted_key.rsplit(".", 1)[-1]  # e.g. "create.log_level" -> "log_level"
        if dest == "subcommand":
            continue
        existing = getattr(flat, dest, None)
        if existing is None:
            setattr(flat, dest, value)
        elif isinstance(existing, list) and isinstance(value, list):
            # Append-action options (e.g. --debug-topic): outer values come first.
            setattr(flat, dest, list(value) + list(existing))

    return flat
