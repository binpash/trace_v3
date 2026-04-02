
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set environment variables for benchmark.sh
export RUNS=10
export WARMUPS=3

run_bench() {
    local name="$1"
    local cmd="$2"

    echo "========================================"
    echo "Starting benchmark: $name"
    echo "Command: $cmd"
    echo "========================================"

    # Pipe 'y' to bypass the confirmation prompt in benchmark.sh
    echo 'y' | "$SCRIPT_DIR/benchmark.sh" "$name" "$cmd"

    echo "Completed $name"
    echo
}

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

echo "========================================"
echo "All benchmarks finished!"
echo "Check tests/timing/benchmark.csv and tests/timing/benchmark.json for results."
echo "You can plot the results using: python3 tests/timing/plot_results.py"
