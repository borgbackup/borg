#!/usr/bin/env bash
#
# rest_perf_test.sh - borg2 performance harness for rest:// repositories.
#
# Runs a fixed workload (repo-create -> backup -> backup again -> dry-run extract
# -> check) against a rest:// repo served over a localhost sshd, under several
# network conditions emulated by borgstore (BORGSTORE_LATENCY / BORGSTORE_BANDWIDTH).
# LAN and WAN use the SAME bandwidth (1 Gbit/s) and differ only in latency (0.3ms vs
# 30ms), to isolate latency's effect; raw is a no-emulation baseline. Prints a table.
#
# The borgstore latency/bandwidth emulation runs client-side (it sleeps inside
# Store._backend_call), so the env vars are set where borg runs, on top of real
# localhost cost: treat the numbers as a controlled *relative* comparison.
#
# Usage:
#   bash scripts/rest_perf_test.sh            # full run: raw, lan, wan over ~7.4GB mix
#   bash scripts/rest_perf_test.sh --clean    # delete repo + cached test data, exit
#
# Tunables can be overridden from the environment, e.g. a quick smoke test:
#   GROUPS_SPEC="tiny:50:20480 med:5:5242880" PROFILES=raw bash scripts/rest_perf_test.sh

set -euo pipefail

# ----------------------------------------------------------------------------
# Config (override via environment)
# ----------------------------------------------------------------------------
: "${VENV:=/Users/tw/w/borg-env}"                       # borg virtualenv to activate
: "${SSH_KEY:=$HOME/.ssh/id_ed25519-mbp-testing}"       # passphrase-less key for tw@localhost
: "${REPO_TARGET:=tw@localhost}"                        # ssh user@host for the rest server
: "${REPO_PATH:=/tmp/REPO}"                             # abs. path of the repo on the server
: "${DATA_DIR:=$HOME/borg-perftest-data}"               # cached test data (generated once)
: "${PROFILES:=raw lan wan}"                            # which network profiles to run

# Test data: a natural mix of file sizes, given as "name:count:bytes" groups.
# Default ~7.4GB: 20000x20KiB + 1000x5MiB + 2x1GiB. Override GROUPS_SPEC for smoke tests.
: "${GROUPS_SPEC:=tiny:20000:20480 med:1000:5242880 big:2:1073741824}"

# rest://user@host//abs/path  (the double slash is intentional: //tmp/REPO is absolute)
REPO_URL="rest://${REPO_TARGET}/${REPO_PATH}"

# Per-profile emulation values: LATENCY in microseconds, BANDWIDTH in bits/s (0 = off).
# lan and wan share the SAME bandwidth (1 Gbit/s); only latency differs, to isolate how
# much latency alone costs (raw = no emulation baseline).
profile_params() {
    case "$1" in
        raw) LAT=0;     BW=0          ;;   # no emulation: baseline localhost+rest overhead
        lan) LAT=300;   BW=1000000000 ;;   # ~0.3 ms / 1 Gbit/s
        wan) LAT=30000; BW=1000000000 ;;   # ~30  ms / 1 Gbit/s (same bandwidth as lan)
        *)   echo "unknown profile: $1" >&2; exit 2 ;;
    esac
}

# Suppress borg's interactive prompts (unencrypted repo access, repo deletion) and
# point borg at the venv borg on the *remote* side (a bare 'borg' would not resolve
# in a non-interactive ssh session's minimal PATH). rest:// is served by 'borg serve
# --rest', so BORG_REMOTE_PATH is the command the server runs.
export BORG_REMOTE_PATH="$VENV/bin/borg"
export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes
export BORG_DELETE_I_KNOW_WHAT_I_AM_DOING=YES

RESULTS="$(mktemp -t rest_perf_results.XXXXXX)"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# Run a borg command, timing wall-clock with python (macOS `date` has no %N).
# Sets globals: WALL (seconds, 3dp) and OUT (captured stdout, e.g. --json). borg's
# own stderr is forwarded; the command's exit status is returned.
run_borg() {
    local outfile errfile rc
    outfile="$(mktemp)"; errfile="$(mktemp)"
    python3 - borg "$@" >"$outfile" 2>"$errfile" <<'PY' || true
import sys, subprocess, time
t = time.perf_counter()
rc = subprocess.call(sys.argv[1:])
sys.stderr.write("__WALL__ %.3f\n" % (time.perf_counter() - t))
sys.exit(rc)
PY
    rc=$?
    WALL="$(grep '^__WALL__' "$errfile" | awk '{print $2}' || true)"
    OUT="$(cat "$outfile")"
    grep -v '^__WALL__' "$errfile" >&2 || true     # surface borg's progress/errors
    rm -f "$outfile" "$errfile"
    return "$rc"
}

# Parse "original_size duration" out of `borg create --json` stdout.
# (borg2's create stats expose original_size + duration; there is no dedup/compressed
# size field, so dedup effectiveness is read off backup2's wall time instead.)
parse_create_json() {
    python3 -c '
import sys, json
d = json.load(sys.stdin)
a = d.get("archive", {}); s = a.get("stats", {})
print("%d %s" % (s.get("original_size", 0), a.get("duration", 0)))
' <<<"$1"
}

fmt_gb() { awk -v b="$1" 'BEGIN { printf "%.3f", b / 1e9 }'; }

# Append a result row (tab-separated): profile step wall_s borg_dur_s orig_GB
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RESULTS"; }

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
preflight() {
    [ -f "$VENV/bin/activate" ] || { echo "ERROR: no venv at $VENV" >&2; exit 1; }
    # venv activate may reference unbound vars under `set -u`
    set +u; # shellcheck disable=SC1090,SC1091
    source "$VENV/bin/activate"; set -u
    echo "borg: $(command -v borg) ($(borg --version))" >&2

    if [ -f "$SSH_KEY" ]; then
        ssh-add "$SSH_KEY" 2>/dev/null || echo "WARN: ssh-add failed (agent running?)" >&2
    else
        echo "WARN: ssh key $SSH_KEY not found" >&2
    fi

    # borg reaches the server with a plain 'ssh user@host'; verify that works.
    if ! ssh -o BatchMode=yes "$REPO_TARGET" true 2>/dev/null; then
        echo "ERROR: cannot ssh to $REPO_TARGET non-interactively." >&2
        echo "       Ensure sshd is on, the key is authorized, and 'ssh-add $SSH_KEY' succeeded." >&2
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# Test data: a natural mix of file sizes, incompressible, generated once and cached.
# Each "name:count:bytes" group lives in its own subdir; the backup target is the whole
# $DATA_DIR. Files are cut from a single AES-CTR keystream via `split`, so generating
# 20000 tiny files is one pipeline, not 20000 process spawns.
# ----------------------------------------------------------------------------
generate_data() {
    local g name count bytes gdir total have
    mkdir -p "$DATA_DIR"
    for g in $GROUPS_SPEC; do
        IFS=: read -r name count bytes <<<"$g"
        gdir="$DATA_DIR/$name"
        if [ -d "$gdir" ]; then
            have=$(find "$gdir" -type f | wc -l | tr -d ' ')
        else
            have=0
        fi
        if [ "$have" -eq "$count" ]; then
            echo "test data ready: $name ($count x $bytes B)" >&2
            continue
        fi
        echo "generating $name: $count x $bytes B ..." >&2
        rm -rf "$gdir"; mkdir -p "$gdir"
        total=$(( count * bytes ))
        # head bounds the infinite keystream; split cuts it into exactly $count files.
        # head closing the pipe makes openssl exit via SIGPIPE (expected; hence || true).
        openssl enc -aes-256-ctr -nosalt -pass "pass:seed-$name" -in /dev/zero 2>/dev/null \
            | head -c "$total" \
            | split -b "$bytes" -a 7 - "$gdir/f" || true
    done
    echo "test data ready in $DATA_DIR" >&2
}

# ----------------------------------------------------------------------------
# One profile: fresh repo, two backups, dry-run extract, check
# ----------------------------------------------------------------------------
run_profile() {
    local profile="$1" orig dur
    profile_params "$profile"
    export BORGSTORE_LATENCY="$LAT" BORGSTORE_BANDWIDTH="$BW"
    echo >&2; echo "=== profile=$profile  latency=${LAT}us  bandwidth=${BW}bit/s ===" >&2

    # fresh repo (tolerate "no repo yet" on the first run)
    run_borg repo-delete --repo "$REPO_URL" >/dev/null 2>&1 || true
    # start each profile with a cold pack cache (only when the opt-in cache is enabled)
    if [ -n "${BORG_PACKCACHE_URL:-}" ]; then rm -rf "${BORG_PACKCACHE_URL#file://}"; fi
    run_borg repo-create --encryption none --repo "$REPO_URL"

    # backup 1 (cold)
    run_borg create --stats --json --repo "$REPO_URL" backup1 "$DATA_DIR"
    read -r orig dur <<<"$(parse_create_json "$OUT")"
    record "$profile" backup1 "$WALL" "$dur" "$(fmt_gb "$orig")"

    # backup 2 (same data -> dedup; expect wall time << backup1)
    run_borg create --stats --json --repo "$REPO_URL" backup2 "$DATA_DIR"
    read -r orig dur <<<"$(parse_create_json "$OUT")"
    record "$profile" backup2 "$WALL" "$dur" "$(fmt_gb "$orig")"

    # dry-run extract of backup2
    run_borg extract --dry-run --repo "$REPO_URL" backup2
    record "$profile" extract-n "$WALL" - -

    # repository check
    run_borg check --repo "$REPO_URL"
    record "$profile" check "$WALL" - -
}

# ----------------------------------------------------------------------------
# Cleanup mode
# ----------------------------------------------------------------------------
clean() {
    preflight
    run_borg repo-delete --repo "$REPO_URL" >/dev/null 2>&1 || true
    rm -rf "$DATA_DIR"
    echo "cleaned: repo $REPO_URL and data $DATA_DIR" >&2
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
    if [ "${1:-}" = "--clean" ]; then clean; exit 0; fi
    preflight
    generate_data
    for p in $PROFILES; do run_profile "$p"; done

    echo; echo "==================== SUMMARY ===================="
    { printf 'profile\tstep\twall_s\tborg_dur_s\torig_GB\n'; cat "$RESULTS"; } \
        | column -t -s "$(printf '\t')"
    echo "(raw results: $RESULTS)"
}

main "$@"
