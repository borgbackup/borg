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
     (tcsh has no completion descriptions)
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

12. Repositories (location_validator):
   - Completes directories for -r/--repo and --other-repo (a local repository is a
     directory; remote locations like ssh://... just do not match one)

13. Encryption modes (the --encryption choices):
   - Completes the repo-create encryption modes, in zsh and fish with a short
     description of what each mode does (bash and tcsh have no descriptions)
"""

import os
import re
import shlex
import sys

import shtab

from ._common import process_epilog
from .diff_cmd import DIFF_SORT_KEYS, diff_sort_spec
from .list_cmd import ITEM_SORT_KEYS, item_sort_spec
from .repo_create_cmd import ENCRYPTION_DESCRIPTIONS
from ..constants import *  # NOQA
from ..crypto.key import encryption_argument_names
from ..helpers import (
    archivename_validator,
    location_validator,
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
      out=$( {PROG} repo-list "${repo_arg[@]}" --format '{id}{NL}' 2>/dev/null </dev/null )
    else
      out=$( {PROG} repo-list --format '{id}{NL}' 2>/dev/null </dev/null )
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
      out=$( {PROG} repo-list "${repo_arg[@]}" --format '{archive}{NL}' 2>/dev/null </dev/null )
    else
      out=$( {PROG} repo-list --format '{archive}{NL}' 2>/dev/null </dev/null )
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

# Complete encryption modes (bash has no completion descriptions, so just the mode names)
_borg_complete_encryption() {
  local choices="{ENCRYPTION_CHOICES}"
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
    out=$( {PROG} repo-list "${repo_arg[@]}" --format '{tags}{NL}' 2>/dev/null </dev/null )
  else
    out=$( {PROG} repo-list --format '{tags}{NL}' 2>/dev/null </dev/null )
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

{SORTBY_FUNCS}
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
      out=$( {PROG} repo-list "${repo_arg[@]}" --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
             2>/dev/null </dev/null )
    else
      out=$( {PROG} repo-list --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
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
      out=$( {PROG} repo-list "${repo_arg[@]}" --format '{archive}{NL}' 2>/dev/null </dev/null )
    else
      out=$( {PROG} repo-list --format '{archive}{NL}' 2>/dev/null </dev/null )
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

# Complete encryption modes, with a short description of each mode
_borg_complete_encryption() {
  local choices=({ENCRYPTION_CHOICES})
  local descriptions=({ENCRYPTION_DESCRIPTIONS})
  # -V: preserve order (do not sort), -l: one per line, -d: descriptions
  compadd -V 'encryption modes' -Q -l -d descriptions -a choices
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
    out=$( {PROG} repo-list "${repo_arg[@]}" --format '{tags}{NL}' 2>/dev/null </dev/null )
  else
    out=$( {PROG} repo-list --format '{tags}{NL}' 2>/dev/null </dev/null )
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

{SORTBY_FUNCS}
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
        {PROG} repo-list $repo_args --format '{id}{TAB}{archive}{TAB}{time}{TAB}{username}@{hostname}{NL}' \
            2>/dev/null </dev/null | while read -l -d \t id archive atime userhost
            test -z "$id"; and continue
            # Print only the first 8 hex digits of the ID, with metadata as description.
            printf 'aid:%s\t%s (%s %s)\n' (string sub -l 8 -- $id) $archive $atime $userhost
        end
    else
        {PROG} repo-list $repo_args --format '{archive}{NL}' 2>/dev/null </dev/null
    end
end

# Complete tags from the repository
function _borg_complete_tags
    set -l repo_args (_borg_repo_args)
    {PROG} repo-list $repo_args --format '{tags}{NL}' 2>/dev/null </dev/null \
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

# Complete encryption modes, with a short description of each mode
function _borg_complete_encryption
    printf '%s\n' {ENCRYPTION_DESCRIPTIONS}
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

{SORTBY_FUNCS}
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


TCSH_PREAMBLE_TMPL = r"""
# Dynamic completion helpers for tcsh

alias _borg_complete_timestamp 'date +"%Y-%m-%dT%H:%M:%S"'


{SORTBY_FUNCS}
alias _borg_complete_filescachemode "echo {FCM_KEYS}"
alias _borg_help_topics "echo {HELP_CHOICES}"
alias _borg_complete_compression_spec "echo {COMP_SPEC_CHOICES}"
alias _borg_complete_chunker_params "echo {CHUNKER_PARAMS_CHOICES}"
# tcsh has no completion descriptions either, so just the mode names
alias _borg_complete_encryption "echo {ENCRYPTION_CHOICES}"
alias _borg_complete_relative_time "echo {RELATIVE_TIME_CHOICES}"
alias _borg_complete_file_size "echo {FILE_SIZE_CHOICES}"

# Complete archive names (archive IDs when the current token starts with "aid:") and tags.
# These need the command line (for --repo/-r) and some logic, which tcsh cannot do itself:
# it has no functions, and an alias cannot use backquotes here because the completion rule
# calling the alias is backquoted already. So the work is done by a POSIX sh script, kept in
# a variable (a single-quoted csh string, hence no single quotes in it) and run via "sh -c".
set _borg_sh_complete = '{SH_COMPLETE}'

alias _borg_complete_archive 'sh -c "$_borg_sh_complete" borg-completion archive "$COMMAND_LINE"'
alias _borg_complete_tags 'sh -c "$_borg_sh_complete" borg-completion tags "$COMMAND_LINE"'
"""

# the sh script the tcsh preamble runs, as one line (`sh -c <script> borg-completion <mode> <line>`).
# It must not contain single quotes (it goes into a single-quoted csh string) nor backquotes (the
# completion rule invoking it is backquoted already).
TCSH_SH_COMPLETE = (
    "mode=$1; line=$2; "
    # derive repo context from the command line: --repo=V, --repo V, -r=V, -rV, or -r V
    "repo=; prev=; "
    "for w in $line; do "
    "case $w in --repo=*) repo=${w#--repo=};; -r=*) repo=${w#-r=};; -r?*) repo=${w#-r};; esac; "
    "case $prev in --repo|-r) repo=$w;; esac; "
    "prev=$w; "
    "done; "
    'set --; if [ -n "$repo" ]; then set -- --repo "$repo"; fi; '
    # the token being completed: the last one, empty if the line ends with a space
    "cur=${line##* }; "
    # avoid prompts and suppress errors, the output is used as completion candidates
    "if [ $mode = tags ]; then "
    '{PROG} repo-list "$@" --format "{tags}{NL}" 2>/dev/null </dev/null'
    ' | tr , "\\n" | sed "s/^ *//;s/ *$//" | grep . | sort -u; '
    'elif [ "${cur#aid:}" != "$cur" ]; then '
    # print only the first 8 hex digits of the ID, like the other shells do
    '{PROG} repo-list "$@" --format "aid:{id}{NL}" 2>/dev/null </dev/null | cut -c1-12; '
    "else "
    '{PROG} repo-list "$@" --format "{archive}{NL}" 2>/dev/null </dev/null; '
    "fi"
)


# There is more than one kind of --sort-by (archives, items, item diffs), each with its own set of
# valid sort keys. The completion code is the same for all of them - only the helper's name and the
# key list differ - so it is generated from one template per shell, rendered once per key set, see
# SORTBY_COMPLETERS and _sortby_functions.
BASH_SORTBY_FN_TMPL = r"""
# Complete comma-separated sort keys for the options using this set of keys.
{FN_NAME}() {
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
  local keys=({KEYS})

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

ZSH_SORTBY_FN_TMPL = r"""
# Complete comma-separated sort keys for the options using this set of keys.
{FN_NAME}() {
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
  local -a keys=({KEYS})

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

FISH_SORTBY_FN_TMPL = r"""
# Complete comma-separated sort keys for the options using this set of keys.
function {FN_NAME}
    _borg_csv_scan
    for k in {KEYS}
        if contains -- $k $_borg_csv_selected
            continue
        end
        _borg_csv_emit $k
    end
end
"""

TCSH_SORTBY_FN_TMPL = 'alias {FN_NAME} "echo {KEYS}"\n'

SORTBY_FN_TMPLS = {
    "bash": BASH_SORTBY_FN_TMPL,
    "zsh": ZSH_SORTBY_FN_TMPL,
    "fish": FISH_SORTBY_FN_TMPL,
    "tcsh": TCSH_SORTBY_FN_TMPL,
}

# tcsh matches completion rules by option name only, in one flat namespace for all subcommands,
# so it can not tell `borg list --sort-by` from `borg repo-list --sort-by`. Thus, it gets a single
# helper offering the union of all sort keys, see for_all_shells(tcsh_fn=...).
TCSH_SORTBY_FN = "_borg_complete_sortby"

# the --sort-by flavours: (argparse type, name of the shell helper completing it, valid sort keys)
SORTBY_COMPLETERS = [
    (SortBySpec, "_borg_complete_sortby", AI_HUMAN_SORT_KEYS),  # archives: repo-list, ...
    (item_sort_spec, "_borg_complete_item_sortby", ITEM_SORT_KEYS),  # items: list
    (diff_sort_spec, "_borg_complete_diff_sortby", DIFF_SORT_KEYS),  # item diffs: diff
]


def _sortby_functions(shell, completers):
    """Render the --sort-by completion helpers for shell, one per set of sort keys."""
    template = SORTBY_FN_TMPLS[shell]
    if shell == "tcsh":
        union = sorted({key for _, _, keys in completers for key in keys})
        completers = [(None, TCSH_SORTBY_FN, union)]
    return "".join(
        partial_format(template, {"FN_NAME": fn_name, "KEYS": " ".join(keys)}) for _, fn_name, keys in completers
    )


# in a `p@N@`...`@` rule, one `if (...) <action>` clause, e.g.
# `if ( $#cmd >= 3 && ("$cmd[2]" == "key") && ("$cmd[3]" == "export") ) f`
TCSH_CLAUSE_RE = re.compile(r"if \( \$#cmd >= \d+ && (?P<checks>.*?) \) (?P<action>.*)")
TCSH_CHECK_RE = re.compile(r'\("\$cmd\[\d+\]" == "(?P<word>[^"]+)"\)')
# a `p@N@` rule as a whole
TCSH_RULE_RE = re.compile(r"^(?P<indent>\s*)'p@(?P<idx>\d+)@`(?P<setup>set cmd=[^;]+; )(?P<clauses>.*)`@' \\$")


def _tcsh_anchor_positional_patterns(script):
    """
    Complete files/dirs for positionals of a subcommand, e.g. `borg umount <MOUNTPOINT>`.

    shtab puts such completions into the `p@N@` rule of that positional, as a bare completion
    pattern (`f`, `d`, ...) in an `if (...) <action>` clause. But tcsh runs these clauses as
    commands and only uses their *output*, so a pattern there does nothing. tcsh can only apply
    a pattern via a rule of its own, keyed off the preceding word - which works whenever the
    positional directly follows its (sub)command.

    TODO: remove this once we require a shtab release that includes tqdm/shtab#241 - with such
    a shtab, no clause has a bare pattern as its action and this is a no-op.
    """
    lines = []
    for line in script.splitlines():
        rule = TCSH_RULE_RE.match(line)
        if not rule:
            lines.append(line)
            continue
        keep = []
        for clause in rule["clauses"].split("; "):
            match = TCSH_CLAUSE_RE.fullmatch(clause)
            action = match["action"] if match else None
            if action is None or action.startswith(("echo ", "eval ")):
                keep.append(clause)  # not a pattern, tcsh can run this
                continue
            words = TCSH_CHECK_RE.findall(match["checks"])
            # the positional is at index `idx`, the (sub)command words are at 2..len(words) + 1
            if words and int(rule["idx"]) == len(words) + 1:
                lines.append(f"{rule['indent']}'n/{words[-1]}/{action}/' \\")
            # else: the pattern is for a later positional, tcsh cannot express that - drop it
        if keep:
            lines.append(f"{rule['indent']}'p@{rule['idx']}@`{rule['setup']}{'; '.join(keep)}`@' \\")
    return "\n".join(lines)


def _attach_completion(parser: ArgumentParser, type_class, completion_dict: dict):
    """Tag all arguments with type `type_class` with completion choices from `completion_dict`."""

    for action in parser._actions:
        if isinstance(action, ActionSubCommands):
            for sub in action.choices.values():
                _attach_completion(sub, type_class, completion_dict)
            continue

        if action.type is type_class:
            action.complete = completion_dict  # type: ignore[attr-defined]


def _attach_completion_by_dest(parser: ArgumentParser, dest: str, completion_dict: dict):
    """Tag all arguments with destination `dest` with completion choices from `completion_dict`."""

    for action in parser._actions:
        if isinstance(action, ActionSubCommands):
            for sub in action.choices.values():
                _attach_completion_by_dest(sub, dest, completion_dict)
            continue

        if action.dest == dest:
            action.complete = completion_dict  # type: ignore[attr-defined]


# RST inline markup used in the help texts: ``literal`` and **bold**. The shells show the help
# as the completion description, where the markup is just noise, see #3086.
RST_MARKUP_RE = re.compile(r"``(?P<literal>.+?)``|\*\*(?P<bold>.+?)\*\*")


def _strip_rst_markup(parser: ArgumentParser):
    """Remove RST inline markup from all help texts, keeping the text they mark up."""

    for action in parser._actions:
        if isinstance(action, ActionSubCommands):
            for sub in action.choices.values():
                _strip_rst_markup(sub)
            continue

        if isinstance(action.help, str):
            action.help = RST_MARKUP_RE.sub(lambda m: m["literal"] or m["bold"], action.help)


class CompletionMixIn:
    def do_completion(self, args):
        """Output shell completion script for the given shell."""
        # Automagically generates completions for subcommands and options. Also
        # adds dynamic completion for archive IDs with the aid: prefix for all ARCHIVE
        # arguments (identified by archivename_validator). It reuses `borg repo-list`
        # to enumerate archives and does not introduce any new commands or caching.

        # The script completes the command borg was invoked as - usually "borg", but e.g. "borg2"
        # if borg was installed under that name to have it alongside a borg 1.x (#3086). The
        # dynamic completions call that same command to query the repository, so they must not
        # end up calling some other borg. Only names starting with "borg" are used: borg is also
        # invoked in ways that do not give a usable command name (e.g. "python -m borg", where the
        # name would be "__main__.py", or in-process from the test suite).
        # self.prog is usually None, the parser then derives it from sys.argv[0], like argparse.
        completion_prog = self.prog or os.path.basename(sys.argv[0])
        if not completion_prog.startswith("borg"):
            completion_prog = "borg"
        prog, self.prog = self.prog, completion_prog
        try:
            parser = self.build_parser()
        finally:
            self.prog = prog

        def for_all_shells(fn_name, tcsh_fn=None):
            # same-named completion helper in the bash, zsh, tcsh and fish preambles;
            # fish needs a command substitution to call it, tcsh backquotes.
            # tcsh matches rules by option name only, over all subcommands, so options needing
            # different completions per subcommand have to share one tcsh helper.
            return {"bash": fn_name, "zsh": fn_name, "tcsh": f"`{tcsh_fn or fn_name}`", "fish": f"({fn_name})"}

        _attach_completion(parser, archivename_validator, for_all_shells("_borg_complete_archive"))
        # -r/--repo and --other-repo: complete local repository directories (remote locations
        # like ssh://... simply do not match anything then), see #3086.
        _attach_completion(parser, location_validator(other=False), shtab.DIRECTORY)
        _attach_completion(parser, location_validator(other=True), shtab.DIRECTORY)
        for sortby_type, sortby_fn, _ in SORTBY_COMPLETERS:
            _attach_completion(parser, sortby_type, for_all_shells(sortby_fn, tcsh_fn=TCSH_SORTBY_FN))
        _attach_completion(parser, FilesCacheMode, for_all_shells("_borg_complete_filescachemode"))
        _attach_completion(parser, CompressionSpec, for_all_shells("_borg_complete_compression_spec"))
        _attach_completion(parser, PathSpec, shtab.DIRECTORY)
        _attach_completion(parser, FilesystemPathSpec, shtab.FILE)
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

        _attach_completion_by_dest(parser, "topic", for_all_shells("_borg_help_topics"))
        _attach_completion_by_dest(parser, "encryption", for_all_shells("_borg_complete_encryption"))
        _strip_rst_markup(parser)

        # Build preambles using partial_format to avoid escaping braces etc.
        fcm_keys = " ".join(["ctime", "mtime", "size", "inode", "rechunk", "disabled"])  # keep in sync with parser

        # Help completion templates
        help_choices = " ".join(sorted(help_choices))

        # Compression spec choices (static list)
        comp_spec_choices = [
            "lz4",
            "zstd,3",
            "zstd,-4",
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

        # encryption modes, and the same list with a short description appended to each mode
        encryption_choices = encryption_argument_names()
        encryption_descriptions = [
            f"{name}\t{ENCRYPTION_DESCRIPTIONS[name]}" if name in ENCRYPTION_DESCRIPTIONS else name
            for name in encryption_choices
        ]
        if args.shell == "zsh":  # zsh wants the mode name in the description, and shell-quoted items
            encryption_descriptions = [shlex.quote(d.replace("\t", "  -- ")) for d in encryption_descriptions]
        elif args.shell == "fish":  # fish reads "value<TAB>description" lines, printf gets one arg per line
            encryption_descriptions = [shlex.quote(d) for d in encryption_descriptions]

        mapping = {
            "FCM_KEYS": fcm_keys,
            "ENCRYPTION_CHOICES": " ".join(encryption_choices),
            "ENCRYPTION_DESCRIPTIONS": " ".join(encryption_descriptions),
            "COMP_SPEC_CHOICES": comp_spec_choices_str,
            "CHUNKER_PARAMS_CHOICES": chunker_params_choices_str,
            "RELATIVE_TIME_CHOICES": relative_time_choices_str,
            "FILE_SIZE_CHOICES": file_size_choices_str,
            "HELP_CHOICES": help_choices,
            "SH_COMPLETE": TCSH_SH_COMPLETE,
            # after SH_COMPLETE, so that the {PROG} in there is substituted as well
            "PROG": completion_prog,
            # last, so that the rendered helpers are not scanned for the placeholders above
            "SORTBY_FUNCS": _sortby_functions(args.shell, SORTBY_COMPLETERS) if args.shell in SORTBY_FN_TMPLS else "",
        }
        preamble_templates = {
            "bash": BASH_PREAMBLE_TMPL,
            "zsh": ZSH_PREAMBLE_TMPL,
            "tcsh": TCSH_PREAMBLE_TMPL,
            "fish": FISH_PREAMBLE_TMPL,
        }
        template = preamble_templates.get(args.shell)
        # Build the preamble using partial_format to avoid escaping braces etc.
        preambles = [partial_format(template, mapping)] if template else []
        script = parser.get_completion_script(f"shtab-{args.shell}", preambles=preambles)
        if args.shell == "tcsh":
            script = _tcsh_anchor_positional_patterns(script)
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

        In tcsh, completions for positional arguments are matched by word position, so
        e.g. an archive name is only completed if no options precede it - one more
        reason to use BORG_REPO there rather than --repo. Also, options are matched by
        name only, so --sort-by offers the union of the sort keys valid for list, diff
        and the commands filtering archives.
        """
        )

        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_completion.__doc__, epilog=completion_epilog
        )
        subparsers.add_subcommand("completion", subparser, help="output shell completion script")
        subparser.add_argument(
            "shell", metavar="SHELL", choices=shells, help="shell to generate completion for (one of: %(choices)s)"
        )
