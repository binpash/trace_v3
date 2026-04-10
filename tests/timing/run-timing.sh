#!/bin/sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set environment variables for benchmark.sh
export RUNS_BASELINE=100
export RUNS_TOOL=10
export WARMUPS=3

# Create a shared temporary directory for both phases
export TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

run_bench() {
    local name="$1"
    local cmd="$2"

    echo "========================================"
    echo "Starting benchmark: $name (Phase: $PHASE)"
    echo "Command: $cmd"
    echo "========================================"

    "$SCRIPT_DIR/benchmark.sh" "$name" "$cmd"

    echo "Completed $name"
    echo
}

run_all_benches() {
    export PHASE="$1"
    echo "========================================"
    echo "Running all benchmarks for phase: $PHASE"
    echo "========================================"

    # 1. Finding files (Heavy getdents64 and stat calls)
    run_bench "find" "find /usr/include -type f > /dev/null 2>&1"

    # 2. Recursive listing (Heavy file metadata retrieval)
    run_bench "ls" "ls -lR /usr/include > /dev/null 2>&1"

    # 3. Disk usage calculation (Directory traversal and stat)
    run_bench "du" "du -sh /usr/lib > /dev/null 2>&1"

    # 4. Grepping through files (Heavy openat, read, close)
    run_bench "grep" "grep -r 'typedef' /usr/include > /dev/null 2>&1"

    # 5. Archiving files (Heavy I/O operations)
    run_bench "tar" "tar -cf /tmp/bench_test.tar /usr/include && rm /tmp/bench_test.tar"

    # 6. Git clone (Network and heavy file creation/writing)
    run_bench "git_clone" "git clone --depth 1 https://github.com/git/git.git /tmp/git_bench >/dev/null 2>&1 && rm -rf /tmp/git_bench"
}

# Run all tests without BPF first
echo "Uninstalling trace_v3 BPF programs..."
"$TRACE" uninstall || true
echo "trace_v3 BPF programs uninstalled"

run_all_benches "no-bpf"

# Run all tests with BPF next
echo "Installing trace_v3 BPF programs..."
trace_v3 install
echo "trace_v3 BPF programs installed"

run_all_benches "bpf"

echo "========================================"
echo "All benchmarks finished!"
echo "Check tests/timing/benchmark.csv and tests/timing/benchmark.json for results."
echo "You can plot the results using: python3 tests/timing/plot_results.py"
