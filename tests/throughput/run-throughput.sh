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

procs=1
for size in "${SIZES[@]}"; do
    echo "Testing ringbuffer size: $size"
    state="start"

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
            if [ "$state" = "searching_down" ]; then
                # We were decrementing because of failures, and we finally found a success!
                # This successful process count is the boundary.
                echo "    Boundary found! Max processes: $procs"
                echo "$size,$procs" >> "$RESULTS_CSV"
                break
            fi

            # We are succeeding, let's push the limits upwards
            state="searching_up"
            procs=$((procs + 1))

            if [ "$procs" -gt 16 ]; then
                echo "    Reached 16 processes without missing events. Moving on."
                echo "$size,16" >> "$RESULTS_CSV"
                procs=16
                break
            fi
        else
            if [ "$state" = "searching_up" ]; then
                # We were incrementing and succeeding, but now we failed.
                # The boundary is the previous successful process count.
                max_procs=$((procs - 1))
                echo "    Boundary found! Max processes: $max_procs (missed $missed events with $procs processes)"
                echo "$size,$max_procs" >> "$RESULTS_CSV"
                procs=$max_procs # Restore to the successful count for the next ringbuffer size
                break
            fi

            # We are failing, let's reduce the pressure
            state="searching_down"
            procs=$((procs - 1))

            if [ "$procs" -lt 1 ]; then
                echo "    Boundary found! Max processes: 0 (missed $missed events with 1 process)"
                echo "$size,0" >> "$RESULTS_CSV"
                procs=1
                break
            fi
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
