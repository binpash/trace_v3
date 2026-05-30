#!/bin/bash
set -e
trap 'echo; echo "Interrupted. Exiting..."; exit 130' INT

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/throughput"

cc -O3 -o test-throughput test-throughput.c

TRACE="${TRACE:-trace_v3}"

mkdir -p output
RESULTS_CSV="output/results.csv"
PLOT_PNG="output/throughput_boundary.png"

echo "RingbufSize,Procs,EventsPerSec,Missed,Phase" > "$RESULTS_CSV"

SIZES=("128K" "256K" "512K" "1M" "2M" "4M" "8M")
MAX_PROCS=$(( $(nproc) * 2 ))
NUM_SWEEPS="${NUM_SWEEPS:-5}"
echo "Max parallel processes: $MAX_PROCS (2x $(nproc) CPUs)"
echo "Sweeps per boundary: $NUM_SWEEPS"

# Run trace with given procs; sets globals: missed, eps
run_once() {
    local size="$1"
    local procs="$2"
    local phase="$3"

    rm -f output/missed.txt output/throughput_tmp.txt
    sudo -E "$TRACE" \
        --ringbuf-size "$size" \
        --missed-file output/missed.txt \
        --throughput-file output/throughput_tmp.txt \
        --throughput-interval 0.025 \
        -- ./run-test.sh "$procs" > /dev/null 2>&1 || true

    # If the tracer crashed (no missed.txt written), treat as total miss
    if [ ! -f output/missed.txt ]; then
        missed=1
    else
        missed=$(grep -o '[0-9]\+' output/missed.txt | head -n1 || echo 0)
        if [ -z "$missed" ]; then missed=0; fi
    fi

    eps=$(awk '/^\[/{for(i=1;i<=NF;i++) if ($i=="events/s") print $(i-1)}' output/throughput_tmp.txt | sort -n | tail -1)
    if [ -z "$eps" ]; then eps=0; fi

    echo "$size,$procs,$eps,$missed,$phase" >> "$RESULTS_CSV"

    if [ "$missed" -eq 0 ]; then
        echo "    [$phase] procs=$procs: OK ($eps events/s)"
    else
        echo "    [$phase] procs=$procs: MISSED $missed events ($eps events/s)"
    fi
}

for size in "${SIZES[@]}"; do
    echo ""
    echo "Testing ringbuffer size: $size"

    # Binary search invariant:
    #   lo = highest confirmed no-miss (0 = none confirmed yet)
    #   hi = lowest confirmed miss (MAX_PROCS+1 = none confirmed yet)
    lo=0
    hi=$(( MAX_PROCS + 1 ))

    while [ $(( hi - lo )) -gt 4 ]; do
        mid=$(( (lo + hi) / 2 ))
        run_once "$size" "$mid" "binary"
        if [ "$missed" -eq 0 ]; then
            lo=$mid
        else
            hi=$mid
        fi
    done

    # Sweep the boundary range including lo and hi endpoints
    sweep_lo=$lo
    sweep_hi=$hi
    [ "$sweep_lo" -lt 1 ] && sweep_lo=1
    [ "$sweep_hi" -gt "$MAX_PROCS" ] && sweep_hi=$MAX_PROCS

    echo "  Sweeping boundary: $sweep_lo to $sweep_hi ($NUM_SWEEPS times)"
    for sweep in $(seq 1 "$NUM_SWEEPS"); do
        for p in $(seq "$sweep_lo" "$sweep_hi"); do
            run_once "$size" "$p" "sweep"
        done
    done
done

echo ""
echo "========================================"
echo "Throughput benchmarking complete!"
echo "Results saved to: $RESULTS_CSV"
echo "Generating plot..."
python3 plot.py
echo "Throughput plot generated at tests/throughput/$PLOT_PNG"
