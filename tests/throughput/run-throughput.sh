#!/bin/bash
set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
cd "${PROJ_ROOT}/tests/throughput"

TRACE="${TRACE:-trace_v3}"

mkdir -p output
RESULTS_CSV="output/results.csv"
PLOT_PNG="output/throughput_boundary.png"

echo "RingbufSize,MaxProcs" > "$RESULTS_CSV"

# Test a few different power-of-2 ringbuf sizes
SIZES=("1M" "2M" "4M" "8M")

for size in "${SIZES[@]}"; do
    echo "Testing ringbuffer size: $size"
    procs=1
    while true; do
        echo "  Trying $procs parallel process(es)..."

        rm -f output/missed.txt
        # Run trace_v3 with the dynamically generated throughput workload
        sudo -E "$TRACE" --ringbuf-size "$size" --missed-file output/missed.txt -- ./run-test.sh "$procs" > /dev/null 2>&1

        # Parse the missed event count from the output file
        missed=$(grep -o '[0-9]\+' output/missed.txt | head -n1 || echo 0)
        if [ -z "$missed" ]; then
            missed=0
        fi

        if [ "$missed" -eq 0 ]; then
            # No missed events, try with one more parallel process to increase pressure
            procs=$((procs + 1))
        else
            # We missed events! The boundary is the previous process count.
            max_procs=$((procs - 1))
            echo "    Boundary found! Max processes: $max_procs (missed $missed events with $procs processes)"
            echo "$size,$max_procs" >> "$RESULTS_CSV"
            break
        fi

        # Safeguard to prevent runaway tests
        if [ "$procs" -gt 16 ]; then
            echo "    Reached 16 processes without missing events. Moving on."
            echo "$size,16" >> "$RESULTS_CSV"
            break
        fi
    done
done

echo "========================================"
echo "Throughput benchmarking complete!"
echo "Results saved to: $RESULTS_CSV"
echo "Generating plot..."
echo "Running: python3 tests/throughput/plot.py"
python3 plot.py
echo "Throughput plot generated at tests/throughput/$PLOT_PNG"
