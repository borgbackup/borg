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

import difflib
import os
import re
import shlex
import sys
from typing import Any

# here are the only imports from argparse and jsonargparse,
# all other imports of these names import them from here:
from argparse import Action, ArgumentError, ArgumentTypeError, RawDescriptionHelpFormatter  # noqa: F401
from jsonargparse import ArgumentParser as _ArgumentParser  # we subclass that to add custom behavior
from jsonargparse import Namespace, ActionSubCommands, SUPPRESS, REMAINDER  # noqa: F401
from jsonargparse.typing import register_type, PositiveInt  # noqa: F401

# Borg 1.x / informal names -> borg2 top-level subcommand (same list as parser choices targets).
_TOP_COMMAND_SYNONYMS = {
    "init": "repo-create",
    "rcreate": "repo-create",
    "repocreate": "repo-create",
    "rm": "delete",
    "clean": "compact",
    "unrm": "undelete",
    "undel": "undelete",
    "restore": "undelete",
}

# Example line after 'Maybe you meant `<canonical>` not `<typed>`:\n\t' (placeholders intentionally generic).
_TOP_COMMAND_EXAMPLES = {
    "repo-create": "borg -r REPO repo-create -e repokey-aes-ocb",
    "delete": "borg -r REPO delete ARCHIVE_OR_AID",
    "compact": "borg -r REPO compact",
    "undelete": "borg -r REPO undelete …",
    "list": "borg -r REPO list ARCHIVE",
}

# Top-level subcommand names (must match build_parser / <command> choices).
_TOP_LEVEL_COMMANDS = frozenset(
    {
        "analyze",
        "benchmark",
        "check",
        "compact",
        "completion",
        "create",
        "debug",
        "delete",
        "diff",
        "extract",
        "help",
        "info",
        "key",
        "list",
        "break-lock",
        "with-lock",
        "mount",
        "umount",
        "prune",
        "repo-compress",
        "repo-create",
        "repo-delete",
        "repo-info",
        "repo-list",
        "recreate",
        "rename",
        "repo-space",
        "serve",
        "tag",
        "export-tar",
        "import-tar",
        "transfer",
        "undelete",
        "version",
    }
)


def _parse_unrecognized_arguments_raw(message: str) -> str | None:
    if "unrecognized arguments" not in message.lower():
        return None
    m = re.search(r"Unrecognized arguments:\s*(.+?)(?:\n|$)", message, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return m.group(1).strip()


def _find_contiguous_subsequence(haystack: list[str], needle: list[str]) -> int | None:
    if not needle or len(needle) > len(haystack):
        return None
    for i in range(len(haystack) - len(needle) + 1):
        if haystack[i : i + len(needle)] == needle:
            return i
    return None


def _remove_contiguous_subsequence(haystack: list[str], needle: list[str]) -> list[str] | None:
    i = _find_contiguous_subsequence(haystack, needle)
    if i is None:
        return None
    return haystack[:i] + haystack[i + len(needle) :]


def _suggest_move_options_after_subcommand(message: str) -> str | None:
    """
    If the user put subcommand-specific flags before <command> (e.g. borg --stats create ...),
    suggest the same argv with those flags after the subcommand.
    """
    raw = _parse_unrecognized_arguments_raw(message)
    if not raw:
        return None
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return None
    if not tokens:
        return None
    argv = sys.argv
    sub_idx = None
    for i, a in enumerate(argv):
        if a in _TOP_LEVEL_COMMANDS:
            sub_idx = i
            break
    if sub_idx is None or sub_idx < 2:
        return None
    prefix = argv[1:sub_idx]
    if _find_contiguous_subsequence(prefix, tokens) is None:
        return None
    keep = _remove_contiguous_subsequence(prefix, tokens)
    if keep is None:
        return None
    corrected = [argv[0]] + keep + [argv[sub_idx]] + tokens + argv[sub_idx + 1 :]
    return " ".join(shlex.quote(c) for c in corrected)


def _argv_tail_after_invalid_choice(invalid: str) -> list[str]:
    """Tokens after the invalid top-level subcommand in sys.argv, if any."""
    try:
        idx = sys.argv.index(invalid)
    except ValueError:
        return []
    return sys.argv[idx + 1 :]


def _argv_display_for_hint(argv: list[str]) -> list[str]:
    """Normalize argv to a readable `borg ...` line when launched via python -m or a borg binary."""
    if (
        len(argv) >= 3
        and os.path.basename(argv[0]).lower().startswith("python")
        and argv[1] == "-m"
        and argv[2] == "borg"
    ):
        return ["borg"] + argv[3:]
    if len(argv) >= 1 and os.path.basename(argv[0]).lower() in ("borg", "borg.exe"):
        return ["borg"] + argv[1:]
    return list(argv)


def _corrected_command_line_for_invalid_subcommand(invalid: str, canonical: str) -> str | None:
    """Replace invalid with canonical in sys.argv; keep all other tokens (same order)."""
    try:
        idx = sys.argv.index(invalid)
    except ValueError:
        return None
    if idx < 1:
        return None
    argv = list(sys.argv)
    argv[idx] = canonical
    display = _argv_display_for_hint(argv)
    if not display:
        return None
    return " ".join(shlex.quote(a) for a in display)


def _apply_argv_tail_to_example(canonical: str, example: str, argv_tail: list[str]) -> str:
    """Replace generic placeholders with argv tokens the user actually typed after the bad command."""
    if not argv_tail:
        return example
    tail = " ".join(shlex.quote(a) for a in argv_tail)
    if canonical == "delete" and "ARCHIVE_OR_AID" in example:
        return example.replace("ARCHIVE_OR_AID", tail)
    if canonical == "list" and "ARCHIVE" in example:
        return example.replace("ARCHIVE", tail)
    if canonical == "undelete" and "…" in example:
        return example.replace("…", tail)
    return example


class ArgumentParser(_ArgumentParser):
    # the borg code always uses RawDescriptionHelpFormatter and add_help=False:
    def __init__(self, *args, formatter_class=RawDescriptionHelpFormatter, add_help=False, **kwargs):
        super().__init__(*args, formatter_class=formatter_class, add_help=add_help, **kwargs)

    def _top_command_choice_hint(self, message: str) -> str | None:
        match = re.search(r"invalid choice: '([^']+)' \(choose from ([^)]+)\)", message)
        if not match:
            return None
        invalid = match.group(1)
        choices = [choice.strip().strip("'\"") for choice in match.group(2).split(",")]
        canonical = _TOP_COMMAND_SYNONYMS.get(invalid)
        if canonical is None:
            candidates = difflib.get_close_matches(invalid, choices, n=1, cutoff=0.6)
            if not candidates:
                return None
            canonical = candidates[0]
        if canonical == invalid:
            return None
        example = _corrected_command_line_for_invalid_subcommand(invalid, canonical)
        if example is None:
            example = _TOP_COMMAND_EXAMPLES.get(canonical, f"borg -r REPO {canonical}")
            example = _apply_argv_tail_to_example(canonical, example, _argv_tail_after_invalid_choice(invalid))
        return f"Maybe you meant `{canonical}` not `{invalid}`:\n\t{example}"

    def _common_fix_hints(self, message: str) -> list[str]:
        hints = []
        reorder = _suggest_move_options_after_subcommand(message)
        if reorder:
            hints.append(f"Put subcommand-specific options after `<command>`: {reorder}")
        if "missing repository" in message.lower():
            hints.append("Set the repository via --repo REPO or BORG_REPO.")
        if "list.name is none" in message.lower() or ("list.name" in message and "is None" in message):
            hints.append("For 'borg list', set repository via -r/--repo or BORG_REPO and pass an archive name.")
        if "repo::archive" in message or "::archive" in message:
            hints.append("Borg 2 uses --repo/BORG_REPO and separate archive arguments.")
        if "invalid choice" in message and "<command>" in message:
            cmd_hint = self._top_command_choice_hint(message)
            if cmd_hint:
                hints.append(cmd_hint)
            hints.append("Run 'borg help' to list valid borg2 commands.")
        return hints

    def error(self, message, *args, **kwargs):
        message = str(message)
        if "Option 'repo-create.encryption' is required but not provided" in message:
            from ..crypto.key import key_argument_names

            modes = key_argument_names()
            mode_list = ", ".join(modes)
            message = (
                f"{message}\n"
                "Use -e/--encryption to choose a mode, for example: -e repokey-aes-ocb\n"
                f"Available encryption modes: {mode_list}"
            )
        if "Option 'list.paths' is required but not provided" in message:
            message = (
                f"{message}\n"
                "borg list requires an archive NAME to list contents.\n"
                "Common fixes:\n"
                "- Provide archive name: borg list NAME\n"
                "- To list archives in a repository, use: borg -r REPO repo-list"
            )
        common_hints = self._common_fix_hints(message)
        if common_hints:
            message = f"{message}\nCommon fixes:\n- " + "\n- ".join(common_hints)
        super().error(message, *args, **kwargs)


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
