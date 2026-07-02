#!/bin/sh
# Run a command under bpftrace+post_process to get a trace_v3-comparable
# dependency summary. Used by both the correctness harness and the timing /
# throughput benchmarks.
#
# Usage:
#   run.sh --dep-file <path|-> --events-file <path|-|/dev/null> -- <cmd> <args>...
#
# bpftrace and post-processing run as a pipeline: bpftrace prints TSV events
# to stdout; post_process.py reads them in real time. We use bpftrace's -c
# flag so the BEGIN block fires *before* the target's first syscall — this is
# the critical property for not racing on the first openat.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BT_SCRIPT="${SCRIPT_DIR}/trace_deps.bt"
POST="${SCRIPT_DIR}/post_process.py"

DEP_FILE="-"
EVENTS_FILE="/dev/null"

while [ $# -gt 0 ]; do
    case "$1" in
        --dep-file)    DEP_FILE="$2"; shift 2 ;;
        --events-file) EVENTS_FILE="$2"; shift 2 ;;
        --)            shift; break ;;
        *)             echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ $# -eq 0 ]; then
    echo "usage: run.sh [--dep-file F] [--events-file F] -- CMD ARGS..." >&2
    exit 2
fi

# bpftrace stores strings on the 512-byte BPF stack (iovisor/bpftrace#305),
# and the two-path probes (renameat/linkat) are the binding constraint:
# empirically 140 is the ceiling on 0.20 — 160 fails verifier with "BPF
# stack limit exceeded" on sys_enter_renameat. trace_v3 uses PATH_MAX
# dynptr scratch-maps, so paths >140 B truncate on the bpftrace leg only;
# call this out as a known asymmetry in the writeup.
export BPFTRACE_MAX_STRLEN="${BPFTRACE_MAX_STRLEN:-140}"
export BPFTRACE_STRLEN="${BPFTRACE_STRLEN:-140}"
export BPFTRACE_PERF_RB_PAGES="${BPFTRACE_PERF_RB_PAGES:-1024}"
export BPFTRACE_MAP_KEYS_MAX="${BPFTRACE_MAP_KEYS_MAX:-65536}"

CWD_AT_RUN="$(pwd)"

# bpftrace 0.17's -c parser doesn't reliably handle shell quoting (anything
# with spaces or quotes leaks through), so we bake the command directly into
# a single-path wrapper script and hand bpftrace that path. The wrapper does
# its own argv reconstruction with sh-quoted arguments, so commands that
# contain spaces/quotes (e.g. `sh -c "find / >/dev/null"`) survive intact.
quote_one() {
    # POSIX-portable single-quote shell-escape: surround in '...' and
    # replace each embedded ' with '\''.
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

QUOTED_CMD=""
for a in "$@"; do
    QUOTED_CMD="${QUOTED_CMD} $(quote_one "$a")"
done

WRAPPER=$(mktemp /tmp/bpftrace_run_cmd.XXXXXX.sh)
trap 'rm -f "$WRAPPER"' EXIT
cat > "$WRAPPER" <<EOF
#!/bin/sh
cd $(quote_one "$CWD_AT_RUN")
exec${QUOTED_CMD}
EOF
chmod +x "$WRAPPER"

# bpftrace 0.17's -c rejects #! scripts (only ELF binaries pass its
# pre-fork executable check). Invoke /bin/sh on the wrapper so the entry
# point is ELF; sh then sources our quoted argv reconstruction.
CMD_STR="/bin/sh $WRAPPER"

# bpftrace stderr carries lost-event counts and parse warnings; we want to
# see them. Pipe to a sibling file when the caller gave us one, otherwise let
# them surface on the calling shell's stderr.
if [ "$EVENTS_FILE" = "/dev/null" ]; then
    BT_ERR=/dev/stderr
else
    BT_ERR="${EVENTS_FILE}.bpftrace.stderr"
fi

# Don't double-invoke sudo when we're already root (smoke.sh + harness drive
# us under sudo); use it only when needed. The double sudo path was hiding
# the wrapper-script error.
if [ "$(id -u)" -eq 0 ]; then
    BT_INVOKE="bpftrace"
else
    BT_INVOKE="sudo -E bpftrace"
fi

# Scrub the wrapper *and* the shell binary the wrapper invokes from the dep
# set. trace_v3 execs the target directly; our bpftrace pipeline goes
# through /bin/sh + a /tmp wrapper to clear the 0.17 ELF-only and quoting
# limitations, so the wrapper path itself plus /bin/sh and its loader-
# touched ancestors are extra noise the trace_v3 leg doesn't see. Excluding
# at insert time (post_process.py) means ancestors of these paths (e.g.
# /tmp, /bin) also don't pollute the read set unless the real workload
# touches them independently.
EXCLUDE_FLAGS="--exclude-prefix=$WRAPPER --exclude-prefix=/bin/sh"

if [ "$EVENTS_FILE" = "/dev/null" ]; then
    $BT_INVOKE -B none -q -c "${CMD_STR}" "$BT_SCRIPT" \
        | python3 "$POST" - --cwd "$CWD_AT_RUN" --out "$DEP_FILE" $EXCLUDE_FLAGS
else
    $BT_INVOKE -B none -q -c "${CMD_STR}" "$BT_SCRIPT" 2>"$BT_ERR" \
        | tee "$EVENTS_FILE" \
        | python3 "$POST" - --cwd "$CWD_AT_RUN" --out "$DEP_FILE" $EXCLUDE_FLAGS
fi
