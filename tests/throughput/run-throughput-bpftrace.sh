#!/bin/bash
# bpftrace contender for the trace_v3 throughput-boundary test.
#
# Same shape as run-throughput.sh: binary-search the maximum number of
# parallel test-throughput workers (each issuing 5M openat calls) under
# which the tracer drops zero events. The knob we vary is
# BPFTRACE_PERF_RB_PAGES (per-CPU perf buffer size) — the bpftrace analog
# of --ringbuf-size in trace_v3. We detect drops by parsing bpftrace's
# "Lost N events" stderr line.

set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/throughput"

cc -O3 -o test-throughput test-throughput.c

BT_DIR="${PROJ_ROOT}/tests/bpftrace"

mkdir -p output
RESULTS_CSV="output/results_bpftrace.csv"
PLOT_PNG="output/throughput_boundary_bpftrace.png"

echo "PerfRbPages,MaxProcs" > "$RESULTS_CSV"

# Per-CPU perf-buffer page counts. bpftrace's default is 64; we try a
# matching power-of-2 sweep.
PAGES=("64" "256" "1024" "4096")

procs=1
for pages in "${PAGES[@]}"; do
    echo "Testing perf rb pages: $pages"
    state="start"

    while true; do
        echo "  Trying $procs parallel process(es)..."

        # Run bpftrace with the dynamically generated workload and capture
        # stderr to detect lost events. We don't post-process — the
        # post-processor isn't on the critical path for the kernel→userspace
        # capture-rate question this test asks.
        bt_stderr=$(mktemp)
        BPFTRACE_PERF_RB_PAGES="$pages" \
        BPFTRACE_STRLEN=64 \
            sudo -E bpftrace -B none -q \
                -c "./run-test.sh $procs" \
                "${BT_DIR}/trace_deps.bt" \
                >/dev/null 2>"$bt_stderr"

        # bpftrace prints "Lost N events" to stderr when its perf buffer
        # overflows. Absence of that string ⇒ zero drops.
        lost=$(grep -oE "Lost [0-9]+ events" "$bt_stderr" | grep -oE "[0-9]+" | head -n1)
        rm -f "$bt_stderr"
        : "${lost:=0}"

        if [ "$lost" -eq 0 ]; then
            if [ "$state" = "searching_down" ]; then
                echo "    Boundary found! Max processes: $procs"
                echo "$pages,$procs" >> "$RESULTS_CSV"
                break
            fi
            state="searching_up"
            procs=$((procs + 1))
            if [ "$procs" -gt 16 ]; then
                echo "    Reached 16 processes without dropping. Capping."
                echo "$pages,16" >> "$RESULTS_CSV"
                procs=16
                break
            fi
        else
            if [ "$state" = "searching_up" ]; then
                max_procs=$((procs - 1))
                echo "    Boundary found! Max processes: $max_procs (lost $lost events at $procs)"
                echo "$pages,$max_procs" >> "$RESULTS_CSV"
                procs=$max_procs
                break
            fi
            state="searching_down"
            procs=$((procs - 1))
            if [ "$procs" -lt 1 ]; then
                echo "    Boundary found! Max processes: 0 (lost $lost events with 1 process)"
                echo "$pages,0" >> "$RESULTS_CSV"
                procs=1
                break
            fi
        fi
    done
done

echo "========================================"
echo "bpftrace throughput benchmarking complete!"
echo "Results saved to: $RESULTS_CSV"
python3 plot.py "$RESULTS_CSV" "$PLOT_PNG" "PerfRbPages" \
    "bpftrace Throughput Capacity Boundary by Per-CPU Perf-Buffer Size"
echo "bpftrace throughput plot generated at $PLOT_PNG"
