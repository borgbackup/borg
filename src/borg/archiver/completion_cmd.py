import argparse

import shtab

from ._common import process_epilog
from ..constants import *  # NOQA
from ..helpers import archivename_validator, SortBySpec  # used to detect ARCHIVE args for dynamic completion
from ..manifest import AI_HUMAN_SORT_KEYS

# Dynamic completion for archive IDs (aid:...)
#
# This integrates with shtab by:
# - tagging argparse actions that accept an ARCHIVE (identified by type == archivename_validator)
#   with a .complete mapping pointing to our helper function.
# - using shtab.complete's 'preamble' parameter to inject the helper into the
#   generated completion script for supported shells.
#
# Notes / constraints (per plan):
# - Calls `borg repo-list --format ...` and filters results by the typed aid: hex prefix.
# - Non-interactive only. We rely on Borg to fail fast without prompting in non-interactive contexts.
#   If it cannot, we simply return no suggestions.

# Name of the helper function inserted into the generated completion script(s)
AID_BASH_FN_NAME = "_borg_complete_aid"
AID_ZSH_FN_NAME = "_borg_complete_aid"

# Name of the helper function inserted for completing SortBySpec options
SORTBY_BASH_FN_NAME = "_borg_complete_sortby"
SORTBY_ZSH_FN_NAME = "_borg_complete_sortby"

# Global bash preamble that is prepended to the generated completion script.
# It aggregates only what we need:
# - wordbreak fixes for ':' and '=' so tokens like 'aid:' and '--repo=/path' stay intact
# - a minimal dynamic completion helper for aid: archive IDs
BASH_PREAMBLE_TMPL = r"""
# keep ':' and '=' intact so tokens like 'aid:' and '--repo=/path' stay whole
if [[ ${COMP_WORDBREAKS-} == *:* ]]; then COMP_WORDBREAKS=${COMP_WORDBREAKS//:}; fi
if [[ ${COMP_WORDBREAKS-} == *=* ]]; then COMP_WORDBREAKS=${COMP_WORDBREAKS//=}; fi

# Complete aid:<hex-prefix> archive IDs by querying "borg repo-list --short"
# Note: we only suggest the first 8 hex digits (short ID) for completion.
_borg_complete_aid() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  [[ "$cur" == aid:* ]] || return 0

  local prefix="${cur#aid:}"
  [[ -n "$prefix" && ! "$prefix" =~ ^[0-9a-fA-F]*$ ]] && return 0

  # derive repo context from words: --repo=V, --repo V, -r=V, -rV, or -r V
  local repo_arg=()
  local i w
  for (( i=0; i<${#COMP_WORDS[@]}; i++ )); do
    w="${COMP_WORDS[i]}"
    if [[ "$w" == --repo=* ]]; then repo_arg=( --repo "${w#--repo=}" ); break
    elif [[ "$w" == -r=* ]]; then repo_arg=( -r "${w#-r=}" ); break
    elif [[ "$w" == -r* && "$w" != "-r" ]]; then repo_arg=( -r "${w#-r}" ); break
    elif [[ "$w" == "--repo" || "$w" == "-r" ]]; then
      if (( i+1 < ${#COMP_WORDS[@]} )); then repo_arg=( "$w" "${COMP_WORDS[i+1]}" ); fi
      break
    fi
  done

  # ask borg for raw IDs; avoid prompts and suppress stderr
  local out
  if [[ -n "${repo_arg[*]}" ]]; then
    out=$( borg repo-list "${repo_arg[@]}" --short 2>/dev/null </dev/null )
  else
    out=$( borg repo-list --short 2>/dev/null </dev/null )
  fi
  [[ -z "$out" ]] && return 0

  # filter by (case-insensitive) hex prefix and emit candidates
  local IFS=$'\n' id prelower idlower
  prelower="$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')"
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    idlower="$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')"
    # Print only the first 8 hex digits of the ID for completion suggestions.
    [[ "$idlower" == "$prelower"* ]] && printf 'aid:%s\n' "${id:0:8}"
  done <<< "$out"
  return 0
}

# Complete comma-separated sort keys for any option with type=SortBySpec.
# Keys are validated against Borg's AI_HUMAN_SORT_KEYS.
_borg_complete_sortby() {
  local cur="${COMP_WORDS[COMP_CWORD]}"

  # Extract value part for --opt=value forms; otherwise the value is the word itself
  local val prefix_eq
  if [[ "$cur" == *=* ]]; then
    prefix_eq="${cur%%=*}="
    val="${cur#*=}"
  else
    prefix_eq=""
    val="$cur"
  fi

  # Split into head (selected keys + trailing comma if any) and fragment (last token being typed)
  local head frag
  if [[ "$val" == *,* ]]; then
    head="${val%,*},"
    frag="${val##*,}"
  else
    head=""
    frag="$val"
  fi

  # Build a comma-delimited list for cheap membership testing
  local headlist
  if [[ -n "$head" ]]; then
    headlist=",${head%,},"
  else
    headlist=","  # nothing selected yet
  fi

  # Valid keys (embedded at generation time)
  local keys=(___SORT_KEYS___)

  local k
  for k in "${keys[@]}"; do
    # skip already-selected keys
    [[ "$headlist" == *",${k},"* ]] && continue
    # match prefix of last fragment
    [[ -n "$frag" && "$k" != "$frag"* ]] && continue
    printf '%s\n' "${prefix_eq}${head}${k}"
  done
}
"""


# Global zsh preamble providing dynamic completion for aid:<hex> archive IDs.
#
# Notes:
# - We use zsh's $words/$CURRENT arrays to inspect the command line.
# - Candidates are returned via `compadd`.
# - We try to detect repo context from --repo=V, --repo V, -r=V, -rV, -r V.
ZSH_PREAMBLE_TMPL = r"""
# Complete aid:<hex-prefix> archive IDs by querying "borg repo-list --short"
# Note: we only suggest the first 8 hex digits (short ID) for completion.
_borg_complete_aid() {
  local cur
  cur="${words[$CURRENT]}"
  [[ "$cur" == aid:* ]] || return 0

  local prefix="${cur#aid:}"
  # allow only hex digits as prefix; empty prefix also allowed (list all)
  [[ -n "$prefix" && ! "$prefix" == [0-9a-fA-F]# ]] && return 0

  # derive repo context from words: --repo=V, --repo V, -r=V, -rV, or -r V
  local -a repo_arg=()
  local i w
  for i in {1..$#words}; do
    w="$words[$i]"
    if [[ "$w" == --repo=* ]]; then repo_arg=( --repo "${w#--repo=}" ); break
    elif [[ "$w" == -r=* ]]; then repo_arg=( -r "${w#-r=}" ); break
    elif [[ "$w" == -r* && "$w" != "-r" ]]; then repo_arg=( -r "${w#-r}" ); break
    elif [[ "$w" == "--repo" || "$w" == "-r" ]]; then
      if (( i+1 <= $#words )); then repo_arg=( "$w" "${words[$((i+1))]}" ); fi
      break
    fi
  done

  # ask borg for raw IDs; avoid prompts and suppress stderr
  local out
  if (( ${#repo_arg[@]} > 0 )); then
    out=$( borg repo-list "${repo_arg[@]}" --short 2>/dev/null </dev/null )
  else
    out=$( borg repo-list --short 2>/dev/null </dev/null )
  fi
  [[ -z "$out" ]] && return 0

  # filter by (case-insensitive) hex prefix and emit candidates
  local prelower id idlower
  prelower="${prefix:l}"
  local -a candidates=()
  for id in ${(f)out}; do
    [[ -z "$id" ]] && continue
    idlower="${id:l}"
    if [[ "$idlower" == "$prelower"* ]]; then
      candidates+=( "aid:${id[1,8]}" )
    fi
  done
  # -Q: do not escape special chars, so ':' remains as-is
  compadd -Q -- $candidates
  return 0
}

# Complete comma-separated sort keys for any option with type=SortBySpec.
_borg_complete_sortby() {
  local cur
  cur="${words[$CURRENT]}"

  local val prefix_eq
  if [[ "$cur" == *"="* ]]; then
    prefix_eq="${cur%%\=*}="
    val="${cur#*=}"
  else
    prefix_eq=""
    val="$cur"
  fi

  local head frag
  if [[ "$val" == *","* ]]; then
    head="${val%,*},"
    frag="${val##*,}"
  else
    head=""
    frag="$val"
  fi

  local headlist
  if [[ -n "$head" ]]; then
    headlist=",${head%,},"
  else
    headlist=","  # nothing selected yet
  fi

  # Valid keys (embedded at generation time)
  local -a keys=(___SORT_KEYS___)

  local -a candidates=()
  local k
  for k in ${keys[@]}; do
    [[ "$headlist" == *",${k},"* ]] && continue
    [[ -n "$frag" && "$k" != "$frag"* ]] && continue
    candidates+=( "${prefix_eq}${head}${k}" )
  done
  compadd -Q -- $candidates
  return 0
}
"""


def _attach_aid_completion(parser: argparse.ArgumentParser):
    """Tag all arguments that accept an ARCHIVE with aid:-completion.

    We detect ARCHIVE arguments by their type being archivename_validator.
    This function mutates the parser actions to add a .complete mapping used by shtab.
    """

    for action in parser._actions:
        # Recurse into subparsers
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                _attach_aid_completion(sub)
            continue

        # Assign dynamic completion only for arguments that take an archive name.
        if action.type is archivename_validator:
            action.complete = {"bash": AID_BASH_FN_NAME, "zsh": AID_ZSH_FN_NAME}  # type: ignore[attr-defined]


def _attach_sortby_completion(parser: argparse.ArgumentParser):
    """Tag all arguments with type SortBySpec with sort-key completion."""

    for action in parser._actions:
        # Recurse into subparsers
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                _attach_sortby_completion(sub)
            continue

        if action.type is SortBySpec:
            action.complete = {"bash": SORTBY_BASH_FN_NAME, "zsh": SORTBY_ZSH_FN_NAME}  # type: ignore[attr-defined]


class CompletionMixIn:
    def do_completion(self, args):
        """Output shell completion script for the given shell."""
        # Automagically generates completions for subcommands and options. Also
        # adds dynamic completion for archive IDs with the aid: prefix for all ARCHIVE
        # arguments (identified by archivename_validator). It reuses `borg repo-list`
        # to enumerate archives and does not introduce any new commands or caching.
        parser = self.build_parser()
        _attach_aid_completion(parser)
        _attach_sortby_completion(parser)

        # Build preambles with embedded SortBy keys
        sort_keys = " ".join(AI_HUMAN_SORT_KEYS)
        bash_preamble = BASH_PREAMBLE_TMPL.replace("___SORT_KEYS___", sort_keys)
        zsh_preamble = ZSH_PREAMBLE_TMPL.replace("___SORT_KEYS___", sort_keys)
        preamble = {"bash": bash_preamble, "zsh": zsh_preamble}
        script = shtab.complete(parser, shell=args.shell, preamble=preamble)  # nosec B604
        print(script)

    def build_parser_completion(self, subparsers, common_parser, mid_common_parser):
        shells = tuple(shtab.SUPPORTED_SHELLS)

        completion_epilog = process_epilog(
            """
        This command prints a shell completion script for the given shell.

        Please note that for some dynamic completions (like archive IDs), the shell
        completion script will call borg to query the repository. This will work best
        if that call can be made without prompting for user input, so you may want to
        set BORG_REPO and BORG_PASSPHRASE environment variables.
        """
        )

        subparser = subparsers.add_parser(
            "completion",
            parents=[common_parser],
            add_help=False,
            description=self.do_completion.__doc__,
            epilog=completion_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="output shell completion script",
        )
        subparser.set_defaults(func=self.do_completion)
        subparser.add_argument(
            "shell", metavar="SHELL", choices=shells, help="shell to generate completion for (one of: %(choices)s)"
        )
