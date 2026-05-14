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

# bpftrace 0.17 keeps strings on the 512-byte BPF stack. Probes that read
# *two* paths (linkat, renameat[2]) blow the stack with STRLEN=200 (≥400 B
# of strings alone, plus probe locals and printf scratch). Cap at 100 so the
# two-path probes load — this is the apples-to-oranges asymmetry vs trace_v3
# (which uses PATH_MAX dynptr scratch-maps) we should call out in the writeup.
# Newer bpftrace (>= 0.18) replaced stack strings with per-cpu arrays and
# doesn't have this constraint.
export BPFTRACE_STRLEN="${BPFTRACE_STRLEN:-100}"
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

# Two scrubs to match trace_v3's "execs the workload directly" perspective:
#   --exclude-prefix kills any dep-set entries that mention the wrapper path
#   --skip-bootstrap discards events up to the second sys_enter_execve, so
#                    /bin/sh (the wrapper exec) and its libc/locale opens
#                    don't leak into deps; the real workload's /bin/sh
#                    re-loads them after the second execve.
EXCLUDE_FLAG="--exclude-prefix=$WRAPPER"
POST_ARGS="--cwd $CWD_AT_RUN --out $DEP_FILE $EXCLUDE_FLAG --skip-bootstrap"

if [ "$EVENTS_FILE" = "/dev/null" ]; then
    $BT_INVOKE -B none -q -c "${CMD_STR}" "$BT_SCRIPT" \
        | python3 "$POST" - $POST_ARGS
else
    $BT_INVOKE -B none -q -c "${CMD_STR}" "$BT_SCRIPT" 2>"$BT_ERR" \
        | tee "$EVENTS_FILE" \
        | python3 "$POST" - $POST_ARGS
fi
