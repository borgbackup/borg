import argparse

import shtab

from ._common import process_epilog
from ..constants import *  # NOQA
from ..helpers import archivename_validator, SortBySpec, FilesCacheMode, PathSpec, ChunkerParams
from ..compress import CompressionSpec
from ..helpers.parseformat import partial_format
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
# - Calls `borg repo-list --format ...` and filters results by the typed prefix (archive name or aid: hex).
# - Non-interactive only. We rely on Borg to fail fast without prompting in non-interactive contexts.
#   If it cannot, we simply return no suggestions.



# Global bash preamble that is prepended to the generated completion script.
# It aggregates only what we need:
# - wordbreak fixes for ':' and '=' so tokens like 'aid:' and '--repo=/path' stay intact
# - a minimal dynamic completion helper for aid: archive IDs
BASH_PREAMBLE_TMPL = r"""
# keep ':' and '=' intact so tokens like 'aid:' and '--repo=/path' stay whole
if [[ ${COMP_WORDBREAKS-} == *:* ]]; then COMP_WORDBREAKS=${COMP_WORDBREAKS//:}; fi
if [[ ${COMP_WORDBREAKS-} == *=* ]]; then COMP_WORDBREAKS=${COMP_WORDBREAKS//=}; fi

_borg_complete_archive() {
  local cur="${COMP_WORDS[COMP_CWORD]}"

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

  # Check if completing aid: prefix
  if [[ "$cur" == aid:* ]]; then
    local prefix="${cur#aid:}"
    [[ -n "$prefix" && ! "$prefix" =~ ^[0-9a-fA-F]*$ ]] && return 0

    # ask borg for raw IDs; avoid prompts and suppress stderr
    local out
    if [[ -n "${repo_arg[*]}" ]]; then
      out=$( borg repo-list "${repo_arg[@]}" --format '{id}{NL}' 2>/dev/null </dev/null )
    else
      out=$( borg repo-list --format '{id}{NL}' 2>/dev/null </dev/null )
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
  else
    # Complete archive names
    local out
    if [[ -n "${repo_arg[*]}" ]]; then
      out=$( borg repo-list "${repo_arg[@]}" --format '{archive}{NL}' 2>/dev/null </dev/null )
    else
      out=$( borg repo-list --format '{archive}{NL}' 2>/dev/null </dev/null )
    fi
    [[ -z "$out" ]] && return 0

    # filter by prefix and emit candidates
    local IFS=$'\n' name
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      [[ -z "$cur" || "$name" == "$cur"* ]] && printf '%s\n' "$name"
    done <<< "$out"
  fi
  return 0
}

# Complete compression spec options
_borg_complete_compression_spec() {
  local choices="{COMP_SPEC_CHOICES}"
  local IFS=$' \t\n'
  compgen -W "${choices}" -- "$1"
}

# Complete chunker params options
_borg_complete_chunker_params() {
  local choices="{CHUNKER_PARAMS_CHOICES}"
  local IFS=$' \t\n'
  compgen -W "${choices}" -- "$1"
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
  local keys=({SORT_KEYS})

  local k
  for k in "${keys[@]}"; do
    # skip already-selected keys
    [[ "$headlist" == *",${k},"* ]] && continue
    # match prefix of last fragment
    [[ -n "$frag" && "$k" != "$frag"* ]] && continue
    printf '%s\n' "${prefix_eq}${head}${k}"
  done
}

# Complete comma-separated files cache mode tokens for options with type=FilesCacheMode.
_borg_complete_filescachemode() {
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

  # Valid tokens (embedded at generation time)
  local keys=({FCM_KEYS})

  # If 'disabled' is already selected, there is nothing else to suggest.
  if [[ "$headlist" == *",disabled,"* ]]; then
    return 0
  fi

  local k
  for k in "${keys[@]}"; do
    # skip duplicates
    [[ "$headlist" == *",${k},"* ]] && continue
    # do not suggest 'disabled' if any other token is already selected
    if [[ -n "$head" && "$k" == "disabled" ]]; then
      continue
    fi
    # ctime/mtime are mutually exclusive: don't suggest the other if one is present
    if [[ "$k" == "ctime" && "$headlist" == *",mtime,"* ]]; then
      continue
    fi
    if [[ "$k" == "mtime" && "$headlist" == *",ctime,"* ]]; then
      continue
    fi
    # match prefix of last fragment
    [[ -n "$frag" && "$k" != "$frag"* ]] && continue
    printf '%s\n' "${prefix_eq}${head}${k}"
  done
}

_borg_help_topics() {
    local choices="{HELP_CHOICES}"
    local IFS=$' \t\n'
    compgen -W "${choices}" -- "$1"
}
"""


# Global zsh preamble providing dynamic completion for aid:<hex> archive IDs.
#
# Notes:
# - We use zsh's $words/$CURRENT arrays to inspect the command line.
# - Candidates are returned via `compadd`.
# - We try to detect repo context from --repo=V, --repo V, -r=V, -rV, -r V.
ZSH_PREAMBLE_TMPL = r"""
_borg_complete_archive() {
  local cur
  cur="${words[$CURRENT]}"

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

  # Check if completing aid: prefix
  if [[ "$cur" == aid:* ]]; then
    local prefix="${cur#aid:}"
    # allow only hex digits as prefix; empty prefix also allowed (list all)
    [[ -n "$prefix" && ! "$prefix" == [0-9a-fA-F]# ]] && return 0

    # ask borg for raw IDs; avoid prompts and suppress stderr
    local out
    if (( ${#repo_arg[@]} > 0 )); then
      out=$( borg repo-list "${repo_arg[@]}" --format '{id}{NL}' 2>/dev/null </dev/null )
    else
      out=$( borg repo-list --format '{id}{NL}' 2>/dev/null </dev/null )
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
  else
    # Complete archive names
    local out
    if (( ${#repo_arg[@]} > 0 )); then
      out=$( borg repo-list "${repo_arg[@]}" --format '{archive}{NL}' 2>/dev/null </dev/null )
    else
      out=$( borg repo-list --format '{archive}{NL}' 2>/dev/null </dev/null )
    fi
    [[ -z "$out" ]] && return 0

    # filter by prefix and emit candidates
    local -a candidates=()
    local name
    for name in ${(f)out}; do
      [[ -z "$name" ]] && continue
      if [[ -z "$cur" || "$name" == "$cur"* ]]; then
        candidates+=( "$name" )
      fi
    done
    compadd -Q -- $candidates
  fi
  return 0
}

# Complete compression spec options
_borg_complete_compression_spec() {
  local choices=({COMP_SPEC_CHOICES})
  # use compadd -V to preserve order (do not sort)
  compadd -V 'compression algorithms' -Q -a choices
}

# Complete chunker params options
_borg_complete_chunker_params() {
  local choices=({CHUNKER_PARAMS_CHOICES})
  # use compadd -V to preserve order (do not sort)
  compadd -V 'chunker params' -Q -a choices
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
  local -a keys=({SORT_KEYS})

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

# Complete comma-separated files cache mode tokens for options with type=FilesCacheMode.
_borg_complete_filescachemode() {
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

  # Valid tokens (embedded at generation time)
  local -a keys=({FCM_KEYS})

  # If 'disabled' is already selected, there is nothing else to suggest.
  if [[ "$headlist" == *",disabled,"* ]]; then
    return 0
  fi

  local -a candidates=()
  local k
  for k in ${keys[@]}; do
    [[ "$headlist" == *",${k},"* ]] && continue
    if [[ -n "$head" && "$k" == "disabled" ]]; then
      continue
    fi
    if [[ "$k" == "ctime" && "$headlist" == *",mtime,"* ]]; then
      continue
    fi
    if [[ "$k" == "mtime" && "$headlist" == *",ctime,"* ]]; then
      continue
    fi
    [[ -n "$frag" && "$k" != "$frag"* ]] && continue
    candidates+=( "${prefix_eq}${head}${k}" )
  done
  compadd -Q -- $candidates
  return 0
}

_borg_help_topics() {
    local choices=({HELP_CHOICES})
    _describe 'help topics' choices
}
"""


def _attach_completion(parser: argparse.ArgumentParser, type_class, completion_dict: dict):
    """Tag all arguments with type `type_class` with completion choices from `completion_dict`."""

    for action in parser._actions:
        # Recurse into subparsers
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                _attach_completion(sub, type_class, completion_dict)
            continue

        if action.type is type_class:
            action.complete = completion_dict  # type: ignore[attr-defined]


def _attach_help_completion(parser: argparse.ArgumentParser, completion_dict: dict):
    """Tag the 'topic' argument of the 'help' command with static completion choices."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                _attach_help_completion(sub, completion_dict)
            continue

        if action.dest == "topic":
            action.complete = completion_dict  # type: ignore[attr-defined]


class CompletionMixIn:
    def do_completion(self, args):
        """Output shell completion script for the given shell."""
        # Automagically generates completions for subcommands and options. Also
        # adds dynamic completion for archive IDs with the aid: prefix for all ARCHIVE
        # arguments (identified by archivename_validator). It reuses `borg repo-list`
        # to enumerate archives and does not introduce any new commands or caching.
        parser = self.build_parser()
        _attach_completion(
            parser, archivename_validator, {"bash": "_borg_complete_archive", "zsh": "_borg_complete_archive"}
        )
        _attach_completion(parser, SortBySpec, {"bash": "_borg_complete_sortby", "zsh": "_borg_complete_sortby"})
        _attach_completion(
            parser, FilesCacheMode, {"bash": "_borg_complete_filescachemode", "zsh": "_borg_complete_filescachemode"}
        )
        _attach_completion(
            parser,
            CompressionSpec,
            {"bash": "_borg_complete_compression_spec", "zsh": "_borg_complete_compression_spec"},
        )
        _attach_completion(parser, PathSpec, shtab.DIRECTORY)
        _attach_completion(
            parser,
            ChunkerParams,
            {"bash": "_borg_complete_chunker_params", "zsh": "_borg_complete_chunker_params"},
        )

        # Collect all commands and help topics for "borg help" completion
        help_choices = list(self.helptext.keys())
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                help_choices.extend(action.choices.keys())

        help_completion_fn = "_borg_help_topics"
        _attach_help_completion(parser, {"bash": help_completion_fn, "zsh": help_completion_fn})

        # Build preambles using partial_format to avoid escaping braces etc.
        sort_keys = " ".join(AI_HUMAN_SORT_KEYS)
        fcm_keys = " ".join(["ctime", "mtime", "size", "inode", "rechunk", "disabled"])  # keep in sync with parser

        # Help completion templates
        help_choices = " ".join(sorted(help_choices))

        # Compression spec choices (static list)
        comp_spec_choices = [
            "lz4",
            "zstd,3",
            "auto,zstd,10",
            "zlib,6",
            "lzma,6",
            "obfuscate,250,lz4",
            "none",
        ]
        comp_spec_choices_str = " ".join(comp_spec_choices)

        # Chunker params choices (static list)
        chunker_params_choices = [
            "default",
            "fixed,4194304",
            "buzhash,19,23,21,4095",
            "buzhash64,19,23,21,4095",
        ]
        chunker_params_choices_str = " ".join(chunker_params_choices)

        mapping = {
            "SORT_KEYS": sort_keys,
            "FCM_KEYS": fcm_keys,
            "COMP_SPEC_CHOICES": comp_spec_choices_str,
            "CHUNKER_PARAMS_CHOICES": chunker_params_choices_str,
            "HELP_CHOICES": help_choices,
        }
        bash_preamble = partial_format(BASH_PREAMBLE_TMPL, mapping)
        zsh_preamble = partial_format(ZSH_PREAMBLE_TMPL, mapping)
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
