#!/bin/bash
# One-shot smoke test for the bpftrace + post_process pipeline.
#
# Two modes, picked automatically:
#
#   1. trace_v3 is on PATH  -> runs the full dep-harness (diff vs trace_v3).
#   2. trace_v3 is missing  -> runs the bpftrace pipeline alone and dumps
#                              its dep set so we can eyeball it.
#
# Invoke once with `sudo bash tests/bpftrace/smoke.sh`. Outputs land under
# /tmp/bpftrace-smoke/ which is world-rw so the calling user can read them.

set -e

PROJ_ROOT="${PROJ_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT_BASE=/tmp/bpftrace-smoke
mkdir -p "${OUT_BASE}"
chmod 777 "${OUT_BASE}"

cd "${PROJ_ROOT}/tests/correctness"

# Sudo strips PATH; trace_v3 normally lives in /usr/local/bin.
if ! command -v trace_v3 >/dev/null 2>&1; then
    for p in /usr/local/bin/trace_v3 "${PROJ_ROOT}/target/release/trace_v3" \
             "${PROJ_ROOT}/target/debug/trace_v3"; do
        if [ -x "$p" ]; then
            export PATH="$(dirname "$p"):$PATH"
            break
        fi
    done
fi

echo "=== bpftrace -d (parse-only) ==="
bpftrace -d -c /bin/true "${PROJ_ROOT}/tests/bpftrace/trace_deps.bt" \
    >/dev/null 2>"${OUT_BASE}/parse.err" \
    && echo "parse OK" \
    || { echo "PARSE FAILED — see ${OUT_BASE}/parse.err"
         tail -40 "${OUT_BASE}/parse.err"; exit 1; }

if command -v trace_v3 >/dev/null 2>&1; then
    echo "=== trace_v3 install ==="
    trace_v3 install || true

    export TEST_OUTPUT="${OUT_BASE}"
    echo "=== dep-harness on test-ls.sh ==="
    ./dep-harness.sh ./test-ls.sh || true
else
    # bpftrace-only mode. Run the same test the harness would have driven and
    # dump just our pipeline's output so we can validate it in isolation.
    echo "=== trace_v3 NOT installed — running bpftrace pipeline alone ==="
    mkdir -p "${OUT_BASE}/test-ls"
    "${PROJ_ROOT}/tests/bpftrace/run.sh" \
        --dep-file    "${OUT_BASE}/test-ls/bpftrace.deps" \
        --events-file "${OUT_BASE}/test-ls/bpftrace.events" \
        -- ./test-ls.sh \
        >"${OUT_BASE}/test-ls/bpftrace.stdout" 2>"${OUT_BASE}/test-ls/bpftrace.stderr" \
        || true

    echo "--- bpftrace.deps (first 40 lines) ---"
    head -n 40 "${OUT_BASE}/test-ls/bpftrace.deps" 2>/dev/null || echo "(empty)"

    echo "--- event log size ---"
    wc -l "${OUT_BASE}/test-ls/bpftrace.events" 2>/dev/null || echo "(none)"

    echo "--- bpftrace stderr (last 30 lines) ---"
    tail -n 30 "${OUT_BASE}/test-ls/bpftrace.stderr" 2>/dev/null || true
fi

# Permission-recover for the calling user so they can read everything.
chown -R "$(stat -c '%U:%G' "${PROJ_ROOT}")" "${OUT_BASE}" 2>/dev/null || true

echo
echo "===== artifacts under ${OUT_BASE}/test-ls/ ====="
ls -la "${OUT_BASE}/test-ls/" 2>/dev/null || true
