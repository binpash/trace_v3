
set -e

# --- Colors ---
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    GREEN=''
    BLUE=''
    YELLOW=''
    RED=''
    CYAN=''
    NC=''
fi

# --- Helper Functions ---
print_header() {
    printf "\n${BLUE}================================================${NC}\n"
    printf "${BLUE} %s ${NC}\n" "$1"
    printf "${BLUE}================================================${NC}\n"
}

print_info() {
    printf "${CYAN}[INFO]${NC} %s\n" "$1"
}

print_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

# --- Initialization ---
export PROJ_ROOT="$(git rev-parse --show-toplevel)"

# Ensure trace_v3 is available in PATH
if ! command -v trace_v3 >/dev/null 2>&1; then
    print_error "trace_v3 could not be found in PATH."
    print_info "Attempting to build and install with Cargo..."
    (cd "$PROJ_ROOT" && cargo install --path .)
fi

export TRACE=$(command -v trace_v3)

# --- Setup eBPF Programs ---
print_header "SETUP"
print_info "Ensuring trace_v3 eBPF programs are installed..."

# Uninstall first to ensure clean state, mirroring benchmark script behavior
sudo rm -rf /sys/fs/bpf/trace_v3 || true

if "$TRACE" install; then
    print_success "trace_v3 eBPF programs installed successfully."
else
    print_error "Failed to install trace_v3 eBPF programs. Make sure you have the necessary privileges."
    exit 1
fi

# --- Test Runner Function ---
run_tests_in_dir() {
    local dir="$1"
    local name="$2"

    print_header "${name} TESTS"

    if [ ! -d "$dir" ]; then
        print_info "Directory $dir not found. Skipping."
        return
    fi

    for test in "$dir"/test-*.sh; do
        # Check if the glob didn't match anything
        [ -e "$test" ] || continue

        test_name=$(basename "$test")
        print_info "Running $test_name..."

        set +e
        "$test" 1>"${test}.out" 2>"${test}.err"
        exit_code=$?
        set -e

        if [ $exit_code -eq 0 ]; then
            print_success "$test_name passed!"
        else
            print_error "$test_name failed with exit code $exit_code!"
        fi

        # Display output streams with slight formatting
        if [ -s "${test}.out" ]; then
            printf "${YELLOW}==== STDOUT (${test_name}) ====${NC}\n"
            cat "${test}.out"
        fi

        if [ -s "${test}.err" ]; then
            printf "${RED}==== STDERR (${test_name}) ====${NC}\n"
            cat "${test}.err"
        fi

        # Exit early if test fails, optional but generally good practice
        if [ $exit_code -ne 0 ]; then
            exit $exit_code
        fi
    done
}

# --- Execution ---

run_tests_in_dir "${PROJ_ROOT}/tests/short" "SHORT"
run_tests_in_dir "${PROJ_ROOT}/tests/long" "LONG"

print_header "CORRECTNESS TESTS"
if "${PROJ_ROOT}/tests/correctness/run-harness.sh"; then
    print_success "Correctness tests passed!"
else
    print_error "Correctness tests failed!"
fi

print_header "TIMING TESTS"
if "${PROJ_ROOT}/tests/timing/run-timing.sh"; then
    print_success "Timing tests completed successfully!"
else
    print_error "Timing tests failed!"
    exit 1
fi

print_header "THROUGHPUT TESTS"
if "${PROJ_ROOT}/tests/throughput/run-throughput.sh"; then
    print_success "Throughput tests completed successfully!"
else
    print_error "Throughput tests failed!"
    exit 1
fi

print_header "ALL TESTS FINISHED SUCCESSFULLY"
