#!/bin/sh
# Generic benchmarking script for fstrace - POSIX sh compliant
# Usage: ./benchmark.sh <test_name> "<command>"
# Example: ./benchmark.sh find "find / >/dev/null 2>&1"

set -e

PROJ_ROOT="${PROJ_ROOT:-$(git rev-parse --show-toplevel)}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCHMARK_DIR="${SCRIPT_DIR}"
OUTPUT_DIR="${BENCHMARK_DIR}/output"
mkdir -p "${OUTPUT_DIR}"
grep -q "^output/$" "${PROJ_ROOT}/tests/.gitignore" 2>/dev/null || echo "output/" >> "${PROJ_ROOT}/tests/.gitignore"

# Separate run configurations
RUNS_BASELINE="${RUNS_BASELINE:-100}"
RUNS_TOOL="${RUNS_TOOL:-10}"
WARMUPS="${WARMUPS:-3}"

JSON_OUTPUT="${OUTPUT_DIR}/benchmark.json"
CSV_OUTPUT="${OUTPUT_DIR}/benchmark.csv"

# Strace flags: -y (fd paths), -f (follow forks), --seccomp-bpf (efficient), -e (event filters)
STRACE_CMD="strace -q -y -f --seccomp-bpf -e %file,fork,clone,fcntl"

TRACE_V3_CMD="fstrace --dep-file /dev/null --trace-file /dev/null --missed-file /dev/null"

# Colors
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    BLUE=''
    YELLOW=''
    RED=''
    NC=''
fi

print_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

print_section() {
    printf "\n${BLUE}=== %s ===${NC}\n" "$1"
}

print_usage() {
    printf "Usage: %s <test_name> <command>\n\n" "$(basename "$0")"
    printf "Examples:\n"
    printf "  %s find \"find / >/dev/null 2>&1\"\n" "$(basename "$0")"
    printf "  %s git_clone \"git clone https://github.com/git/git.git /tmp/git >/dev/null 2>&1 && rm -rf /tmp/git\"\n" "$(basename "$0")"
    printf "  %s ls \"ls -R / >/dev/null 2>&1\"\n" "$(basename "$0")"
    printf "\nOptions via Environment Variables:\n"
    printf "  RUNS_BASELINE=100 Number of times to run the baselines (default: 100)\n"
    printf "  RUNS_TOOL=10      Number of times to run strace/fstrace (default: 10)\n"
    printf "  WARMUPS=3         Number of warmup runs (default: 3)\n"
    printf "  PHASE             Set to 'no-bpf' or 'bpf' to only run that portion\n"
}

check_dependencies() {
    print_section "Checking dependencies"

    for cmd in hyperfine fstrace strace python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            print_error "$cmd not found"
            exit 1
        fi
        print_success "$cmd found"
    done
}

setup_temp_dir() {
    if [ -z "$TEMP_DIR" ]; then
        TEMP_DIR=$(mktemp -d)
        export TEMP_DIR
        trap "rm -rf ${TEMP_DIR}" EXIT
    fi
    print_success "Temporary directory: ${TEMP_DIR}"
}

benchmark_test() {
    local test_name="$1"
    local command="$2"

    print_section "Benchmarking: ${test_name}"

    if [ -z "$PHASE" ] || [ "$PHASE" = "no-bpf" ]; then
        print_info "Running baseline without overhead (${RUNS_BASELINE} runs)..."
        hyperfine --min-runs "${RUNS_BASELINE}" --warmup "${WARMUPS}" --ignore-failure \
            --export-json "${TEMP_DIR}/${test_name}_baseline.json" \
            "${command}"

        print_info "Running baseline vs strace (${RUNS_TOOL} runs)..."
        hyperfine --min-runs "${RUNS_TOOL}" --warmup "${WARMUPS}" --ignore-failure \
            --export-json "${TEMP_DIR}/${test_name}_strace.json" \
            "${STRACE_CMD} ${command}"
    fi

    if [ -z "$PHASE" ] || [ "$PHASE" = "bpf" ]; then
        print_info "Running baseline with BPF program overhead (${RUNS_BASELINE} runs)..."
        hyperfine --min-runs "${RUNS_BASELINE}" --warmup "${WARMUPS}" --ignore-failure \
            --export-json "${TEMP_DIR}/${test_name}_baseline_bpf.json" \
            "${command}"

        print_info "Running fstrace (${RUNS_TOOL} runs)..."
        hyperfine --min-runs "${RUNS_TOOL}" --warmup "${WARMUPS}" --ignore-failure \
            --export-json "${TEMP_DIR}/${test_name}_fstrace.json" \
            "${TRACE_V3_CMD} ${command}"
    fi
}

merge_results() {
    local test_name="$1"

    print_section "Merging results for ${test_name}"

    python3 "${BENCHMARK_DIR}/merge_results.py" \
        "${TEMP_DIR}" \
        "${JSON_OUTPUT}" \
        "${CSV_OUTPUT}" \
        "${test_name}" \
        "${RUNS_BASELINE}" \
        "${WARMUPS}"
}

main() {
    # Parse command line arguments
    if [ $# -lt 2 ]; then
        print_usage
        exit 1
    fi

    TEST_NAME="$1"
    COMMAND="$2"

    print_info "Starting benchmark for: ${TEST_NAME}"
    print_info "Command: ${COMMAND}"
    check_dependencies
    setup_temp_dir

    printf "\n${YELLOW}Running benchmark (Baselines: ${RUNS_BASELINE} runs, Tools: ${RUNS_TOOL} runs, Warmups: ${WARMUPS})${NC}\n"

    # Only prompt if not running a specific phase (assumes automated run if PHASE is set)
    if [ -z "$PHASE" ]; then
        printf "${YELLOW}Continue? (y/n): ${NC}"
        read -r ans

        case "$ans" in
            y|Y) ;;
            *) print_error "Cancelled"; exit 0 ;;
        esac
    fi

    benchmark_test "${TEST_NAME}" "${COMMAND}"
    merge_results "${TEST_NAME}"

    print_section "Summary"
    print_success "JSON: ${JSON_OUTPUT}"
    print_success "CSV: ${CSV_OUTPUT}"
    print_info "To plot: python3 ${BENCHMARK_DIR}/plot_results.py"
}

main "$@"
