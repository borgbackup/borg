"""
Shell completion support for Borg commands.

This module implements the `borg completion` command, which generates shell completion
scripts for bash, zsh, tcsh and fish. It uses the shtab library for basic completion
generation and extends it with custom dynamic completions for Borg-specific argument
types, via a per-shell preamble of completion functions that the generated script
refers to.

Dynamic Completions
-------------------

The following argument types have intelligent, context-aware completion:

1. Archive names/IDs (archivename_validator):
   - Completes archive names by default (e.g., "my-backup-2024")
   - Completes archive IDs when prefixed with "aid:" (e.g., "aid:12345678")
   - In zsh and fish, shows archive metadata (name, timestamp, user@host) as descriptions
   - Respects --repo/-r flags to query the correct repository

2. Sort keys (SortBySpec):
   - Completes comma-separated sort keys (timestamp, archive, name, id, tags, host, user)
   - Prevents duplicate keys in the same option

3. Files cache mode (FilesCacheMode):
   - Completes comma-separated cache mode tokens (ctime, mtime, size, inode, rechunk, disabled)
   - Enforces mutual exclusivity (e.g., ctime vs mtime, disabled vs others)

4. Compression algorithms (CompressionSpec):
   - Suggests compression specs with examples (lz4, zstd,3, auto,zstd,10, etc.)

5. Chunker parameters (ChunkerParams):
   - Suggests chunker param examples (default, fixed,4194304, buzhash,19,23,21,4095, etc.)

6. Paths (PathSpec, FilesystemPathSpec, FilesystemDirSpec):
   - Completes files and directories for arguments taking a filesystem path
     (FilesystemPathSpec, e.g. PATH, EXCLUDEFILE, TARFILE), and directories only
     for arguments taking a directory (FilesystemDirSpec, e.g. MOUNTPOINT)

7. Help topics:
   - Completes help command topics and subcommand names

8. Tags (tag_validator):
   - Completes existing tags from the repository

9. Relative time markers (relative_time_marker_validator):
   - Suggests common time intervals (60S, 60M, 24H, 7d, 4w, 12m, 1000y)

10. Timestamps (timestamp):
   - Completes file paths when starting with / or .
   - Otherwise suggests current timestamp in ISO format

11. File sizes (parse_file_size):
   - Suggests common file size values (500M, 1G, 10G, 100G, 1T, etc.)
"""

import shtab

from ._common import process_epilog
from ..constants import *  # NOQA
from ..helpers import (
    archivename_validator,
    SortBySpec,
    FilesCacheMode,
    PathSpec,
    FilesystemPathSpec,
    FilesystemDirSpec,
    ChunkerParams,
    CompressionSpec,
    tag_validator,
    relative_time_marker_validator,
    parse_file_size,
)
from ..helpers.argparsing import ArgumentParser
from ..helpers.argparsing import ActionSubCommands
from ..helpers.time import timestamp
from ..helpers.parseformat import partial_format
from ..manifest import AI_HUMAN_SORT_KEYS

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

# Complete tags from repository
_borg_complete_tags() {
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

  # ask borg for tags; avoid prompts and suppress stderr
  local out
  if [[ -n "${repo_arg[*]}" ]]; then
    out=$( borg repo-list "${repo_arg[@]}" --format '{tags}{NL}' 2>/dev/null </dev/null )
  else
    out=$( borg repo-list --format '{tags}{NL}' 2>/dev/null </dev/null )
  fi
  [[ -z "$out" ]] && return 0

  # extract unique tags and filter by prefix
  local IFS=$'\n' line tag
  local -A seen
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # tags are comma-separated, split and deduplicate
    IFS=',' read -ra tags <<< "$line"
    for tag in "${tags[@]}"; do
      tag="${tag# }"
      tag="${tag% }"
      [[ -z "$tag" ]] && continue
      [[ -n "${seen[$tag]}" ]] && continue
      seen[$tag]=1
      [[ -z "$cur" || "$tag" == "$cur"* ]] && printf '%s\n' "$tag"
    done
  done <<< "$out"
  return 0
}

# Complete relative time markers
_borg_complete_relative_time() {
  local choices="{RELATIVE_TIME_CHOICES}"
  local IFS=$' \t\n'
  compgen -W "${choices}" -- "$1"
}

# Complete timestamp (file path or ISO timestamp)
_borg_complete_timestamp() {
  local cur="${COMP_WORDS[COMP_CWORD]}"

  # If starts with / or ., complete as file path
  if [[ "$cur" == /* || "$cur" == ./* || "$cur" == ../* || "$cur" == . || "$cur" == .. ]]; then
    compgen -f -- "$cur"
  else
    # Suggest current timestamp in ISO format
    date +"%Y-%m-%dT%H:%M:%S%z" | sed 's/\([0-9]\{2\}\)$/:\1/'
  fi
}

# Complete file size values
_borg_complete_file_size() {
  local choices="{FILE_SIZE_CHOICES}"
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

    # ask borg for IDs with metadata; avoid prompts and suppress stderr
    # Use tab as delimiter to avoid issues with spaces in archive names
    local out
    if (( ${#repo_arg[@]} > 0 )); then
      out=$( borg repo-list "${repo_arg[@]}" --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
             2>/dev/null </dev/null )
    else
      out=$( borg repo-list --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
             2>/dev/null </dev/null )
    fi
    [[ -z "$out" ]] && return 0

    # filter by (case-insensitive) hex prefix and build candidates with descriptions
    local prelower id idlower line
    prelower="${prefix:l}"
    local -a candidates=()
    local -a descriptions=()
    while IFS=$'\t' read -r id archive time userhost; do
      [[ -z "$id" ]] && continue
      idlower="${id:l}"
      if [[ "$idlower" == "$prelower"* ]]; then
        candidates+=( "aid:${id[1,8]}" )
        # Description: show full ID, archive name, time, user@host
        descriptions+=( "${id[1,8]}: ${archive} (${time} ${userhost})" )
      fi
    done <<< "$out"
    # -Q: do not escape special chars, -d: provide descriptions, -l: one per line
    compadd -Q -l -d descriptions -- $candidates
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

# Complete tags from repository
_borg_complete_tags() {
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

  # ask borg for tags; avoid prompts and suppress stderr
  local out
  if (( ${#repo_arg[@]} > 0 )); then
    out=$( borg repo-list "${repo_arg[@]}" --format '{tags}{NL}' 2>/dev/null </dev/null )
  else
    out=$( borg repo-list --format '{tags}{NL}' 2>/dev/null </dev/null )
  fi
  [[ -z "$out" ]] && return 0

  # extract unique tags and filter by prefix
  local line tag
  local -A seen
  local -a candidates=()
  for line in ${(f)out}; do
    [[ -z "$line" ]] && continue
    # tags are comma-separated, split and deduplicate
    for tag in ${(s:,:)line}; do
      tag="${tag## }"
      tag="${tag%% }"
      [[ -z "$tag" ]] && continue
      [[ -n "${seen[$tag]}" ]] && continue
      seen[$tag]=1
      if [[ -z "$cur" || "$tag" == "$cur"* ]]; then
        candidates+=( "$tag" )
      fi
    done
  done
  compadd -Q -- $candidates
  return 0
}

# Complete relative time markers
_borg_complete_relative_time() {
  local choices=({RELATIVE_TIME_CHOICES})
  # use compadd -V to preserve order (do not sort)
  compadd -V 'relative time' -Q -a choices
}

# Complete timestamp (file path or ISO timestamp)
_borg_complete_timestamp() {
  local cur
  cur="${words[$CURRENT]}"

  # If starts with / or ., complete as file path
  if [[ "$cur" == /* || "$cur" == ./* || "$cur" == ../* || "$cur" == . || "$cur" == .. ]]; then
    _files
  else
    # Suggest current timestamp in ISO format
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S%z" | sed 's/\([0-9]\{2\}\)$/:\1/')
    compadd -Q -- "$timestamp"
  fi
}

# Complete file size values
_borg_complete_file_size() {
  local choices=({FILE_SIZE_CHOICES})
  # use compadd -V to preserve order (do not sort)
  compadd -V 'file size' -Q -a choices
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

# Global fish preamble providing the dynamic completion functions the generated
# script refers to (the fish counterparts of the bash/zsh ones above).
FISH_PREAMBLE_TMPL = r"""
# derive repo context from the command line: --repo=V, --repo V, -r=V, -rV, or -r V
function _borg_repo_args
    set -l tokens (commandline -opc)
    set -l n (count $tokens)
    for i in (seq 2 $n)
        set -l w $tokens[$i]
        switch "$w"
            case '--repo=*'
                printf '%s\n' --repo (string replace -- '--repo=' '' $w)
                return
            case '-r=*'
                printf '%s\n' -r (string replace -- '-r=' '' $w)
                return
            case '--repo' '-r'
                if test $i -lt $n
                    printf '%s\n' $w $tokens[(math $i + 1)]
                end
                return
            case '-r*'
                printf '%s\n' -r (string replace -r -- '^-r' '' $w)
                return
        end
    end
end

# Complete archive names, or archive IDs when the current token starts with "aid:"
function _borg_complete_archive
    set -l cur (commandline -ct)
    set -l repo_args (_borg_repo_args)
    if string match -q -- 'aid:*' $cur
        set -l prefix (string replace -- 'aid:' '' $cur)
        if test -n "$prefix"; and not string match -qr -- '^[0-9a-fA-F]+$' $prefix
            return
        end
        # ask borg for IDs with metadata; avoid prompts and suppress stderr
        borg repo-list $repo_args --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
            2>/dev/null </dev/null | while read -l -d \t id archive atime userhost
            test -z "$id"; and continue
            # Print only the first 8 hex digits of the ID, with metadata as description.
            printf 'aid:%s\t%s (%s %s)\n' (string sub -l 8 -- $id) $archive $atime $userhost
        end
    else
        borg repo-list $repo_args --format '{archive}{NL}' 2>/dev/null </dev/null
    end
end

# Complete tags from the repository
function _borg_complete_tags
    set -l repo_args (_borg_repo_args)
    borg repo-list $repo_args --format '{tags}{NL}' 2>/dev/null </dev/null \
        | string split ',' | string trim | string match -v '' | sort -u
end

# Complete compression spec options
function _borg_complete_compression_spec
    printf '%s\n' {COMP_SPEC_CHOICES}
end

# Complete chunker params options
function _borg_complete_chunker_params
    printf '%s\n' {CHUNKER_PARAMS_CHOICES}
end

# Complete relative time markers
function _borg_complete_relative_time
    printf '%s\n' {RELATIVE_TIME_CHOICES}
end

# Complete file size values
function _borg_complete_file_size
    printf '%s\n' {FILE_SIZE_CHOICES}
end

function _borg_help_topics
    printf '%s\n' {HELP_CHOICES}
end

# Complete timestamp (file path or ISO timestamp)
function _borg_complete_timestamp
    set -l cur (commandline -ct)
    if string match -qr -- '^(/|\.)' $cur
        __fish_complete_path $cur
    else
        # Suggest current timestamp in ISO format
        date +%Y-%m-%dT%H:%M:%S%z | string replace -r -- '(\d\d)$' ':$1'
    end
end

# Split the current token into an --opt= prefix (if any), the already selected
# comma-separated keys (with trailing comma) and set $_borg_csv_prefix_eq,
# $_borg_csv_head and $_borg_csv_selected accordingly.
function _borg_csv_scan
    set -l cur (commandline -ct)
    set -g _borg_csv_prefix_eq ''
    set -l val $cur
    if string match -q -- '*=*' $cur
        set -g _borg_csv_prefix_eq (string replace -r -- '=.*$' '=' $cur)
        set val (string replace -r -- '^[^=]*=' '' $cur)
    end
    set -g _borg_csv_head ''
    if string match -q -- '*,*' $val
        set -g _borg_csv_head (string replace -r -- '[^,]*$' '' $val)
    end
    set -g _borg_csv_selected (string split -- ',' $_borg_csv_head)
end

# Emit one candidate for a comma-separated list option, in both the plain and
# the --opt=value form (fish matches whichever fits the current token).
function _borg_csv_emit
    printf '%s\n' "$_borg_csv_head$argv"
    if test -n "$_borg_csv_prefix_eq"
        printf '%s\n' "$_borg_csv_prefix_eq$_borg_csv_head$argv"
    end
end

# Complete comma-separated sort keys for any option with type=SortBySpec.
function _borg_complete_sortby
    _borg_csv_scan
    for k in {SORT_KEYS}
        if contains -- $k $_borg_csv_selected
            continue
        end
        _borg_csv_emit $k
    end
end

# Complete comma-separated files cache mode tokens for options with type=FilesCacheMode.
function _borg_complete_filescachemode
    _borg_csv_scan
    # If 'disabled' is already selected, there is nothing else to suggest.
    if contains -- disabled $_borg_csv_selected
        return
    end
    for k in {FCM_KEYS}
        # skip duplicates
        if contains -- $k $_borg_csv_selected
            continue
        end
        # do not suggest 'disabled' if any other token is already selected
        if test -n "$_borg_csv_head"; and test "$k" = disabled
            continue
        end
        # ctime/mtime are mutually exclusive: don't suggest the other if one is present
        if test "$k" = ctime; and contains -- mtime $_borg_csv_selected
            continue
        end
        if test "$k" = mtime; and contains -- ctime $_borg_csv_selected
            continue
        end
        _borg_csv_emit $k
    end
end
"""


def _attach_completion(parser: ArgumentParser, type_class, completion_dict: dict):
    """Tag all arguments with type `type_class` with completion choices from `completion_dict`."""

    for action in parser._actions:
        if isinstance(action, ActionSubCommands):
            for sub in action.choices.values():
                _attach_completion(sub, type_class, completion_dict)
            continue

        if action.type is type_class:
            action.complete = completion_dict  # type: ignore[attr-defined]


def _attach_help_completion(parser: ArgumentParser, completion_dict: dict):
    """Tag the 'topic' argument of the 'help' command with static completion choices."""
    for action in parser._actions:
        if isinstance(action, ActionSubCommands):
            for sub in action.choices.values():
                _attach_help_completion(sub, completion_dict)
            continue

        if action.dest == "topic":
            action.complete = completion_dict  # type: ignore[attr-defined]


# File completion. shtab's fish variant calls __fish_complete_path without arguments,
# which only completes paths relative to the cwd - pass the current token, so that
# absolute paths (and paths in other directories) complete as well, see tqdm/shtab#245.
FILE = {**shtab.FILE, "fish": "(__fish_complete_path (commandline -ct))"}


class CompletionMixIn:
    def do_completion(self, args):
        """Output shell completion script for the given shell."""
        # Automagically generates completions for subcommands and options. Also
        # adds dynamic completion for archive IDs with the aid: prefix for all ARCHIVE
        # arguments (identified by archivename_validator). It reuses `borg repo-list`
        # to enumerate archives and does not introduce any new commands or caching.

        # The script shall always complete the "borg" command, no matter how borg was
        # invoked while generating it (e.g. as "python -m borg", where prog would be
        # "__main__.py" - the shells would then complete that instead of "borg").
        prog, self.prog = self.prog, "borg"
        try:
            parser = self.build_parser()
        finally:
            self.prog = prog

        def for_all_shells(fn_name):
            # same-named completion function in the bash, zsh and fish preambles;
            # fish needs a command substitution to call it
            return {"bash": fn_name, "zsh": fn_name, "fish": f"({fn_name})"}

        _attach_completion(parser, archivename_validator, for_all_shells("_borg_complete_archive"))
        _attach_completion(parser, SortBySpec, for_all_shells("_borg_complete_sortby"))
        _attach_completion(parser, FilesCacheMode, for_all_shells("_borg_complete_filescachemode"))
        _attach_completion(parser, CompressionSpec, for_all_shells("_borg_complete_compression_spec"))
        _attach_completion(parser, PathSpec, shtab.DIRECTORY)
        _attach_completion(parser, FilesystemPathSpec, FILE)
        _attach_completion(parser, FilesystemDirSpec, shtab.DIRECTORY)
        _attach_completion(parser, ChunkerParams, for_all_shells("_borg_complete_chunker_params"))
        _attach_completion(parser, tag_validator, for_all_shells("_borg_complete_tags"))
        _attach_completion(parser, relative_time_marker_validator, for_all_shells("_borg_complete_relative_time"))
        _attach_completion(parser, timestamp, for_all_shells("_borg_complete_timestamp"))
        _attach_completion(parser, parse_file_size, for_all_shells("_borg_complete_file_size"))

        # Collect all commands and help topics for "borg help" completion
        help_choices = list(self.helptext.keys())
        for action in parser._actions:
            if isinstance(action, ActionSubCommands):
                help_choices.extend(action.choices.keys())

        _attach_help_completion(parser, for_all_shells("_borg_help_topics"))

        # Build preambles using partial_format to avoid escaping braces etc.
        sort_keys = " ".join(AI_HUMAN_SORT_KEYS)
        fcm_keys = " ".join(["ctime", "mtime", "size", "inode", "rechunk", "disabled"])  # keep in sync with parser

        # Help completion templates
        help_choices = " ".join(sorted(help_choices))

        # Compression spec choices (static list)
        comp_spec_choices = ["lz4", "zstd,3", "auto,zstd,10", "zlib,6", "lzma,6", "obfuscate,250,lz4", "none"]
        comp_spec_choices_str = " ".join(comp_spec_choices)

        # Chunker params choices (static list)
        chunker_params_choices = [
            "default",
            "fixed,4194304",
            "buzhash,19,23,21,4095",
            "buzhash64,19,23,21,4095,2",
            "fastcdc,19,23,21,2",
            "rabin-aes,19,23,21,2",
            "goldilocks-aes,19,23,21,2",
            "toeplitz-aes,19,23,21,2",
        ]
        chunker_params_choices_str = " ".join(chunker_params_choices)

        # Relative time marker choices (static list)
        relative_time_choices = ["60S", "60M", "24H", "7d", "4w", "12m", "1000y"]
        relative_time_choices_str = " ".join(relative_time_choices)

        # File size choices (static list)
        file_size_choices = ["500M", "1G", "10G", "100G", "1T"]
        file_size_choices_str = " ".join(file_size_choices)

        mapping = {
            "SORT_KEYS": sort_keys,
            "FCM_KEYS": fcm_keys,
            "COMP_SPEC_CHOICES": comp_spec_choices_str,
            "CHUNKER_PARAMS_CHOICES": chunker_params_choices_str,
            "RELATIVE_TIME_CHOICES": relative_time_choices_str,
            "FILE_SIZE_CHOICES": file_size_choices_str,
            "HELP_CHOICES": help_choices,
        }
        preamble_templates = {"bash": BASH_PREAMBLE_TMPL, "zsh": ZSH_PREAMBLE_TMPL, "fish": FISH_PREAMBLE_TMPL}
        template = preamble_templates.get(args.shell)
        # Build the preamble using partial_format to avoid escaping braces etc.
        preambles = [partial_format(template, mapping)] if template else []
        script = parser.get_completion_script(f"shtab-{args.shell}", preambles=preambles)
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

        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_completion.__doc__, epilog=completion_epilog
        )
        subparsers.add_subcommand("completion", subparser, help="output shell completion script")
        subparser.add_argument(
            "shell", metavar="SHELL", choices=shells, help="shell to generate completion for (one of: %(choices)s)"
        )
