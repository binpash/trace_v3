#!/usr/bin/env python3
"""Merge benchmark results and convert to CSV"""

import csv
import json
import math
import os
import sys
from datetime import datetime


def extract_benchmark(json_path, result_index=0):
    """Extract timing data from hyperfine JSON output at specified result index"""
    try:
        with open(json_path) as f:
            data = json.load(f)
        if data.get("results") and len(data["results"]) > result_index:
            r = data["results"][result_index]
            times = r.get("times", [])
            if times:
                geom_mean = math.exp(sum(math.log(t) for t in times) / len(times))
            else:
                geom_mean = r.get("mean")

            return {
                "mean": geom_mean,
                "stddev": r.get("stddev"),
                "median": r.get("median"),
                "min": r.get("min"),
                "max": r.get("max"),
            }
    except Exception as e:
        print(f"Warning: Failed to read {json_path}: {e}", file=sys.stderr)
    return None


def merge_results(temp_dir, json_output, csv_output, test_name, runs, warmups):
    """Merge all benchmark results into single JSON and CSV files"""

    results = {
        "benchmarks": {},
        "metadata": {
            "date": datetime.now().isoformat(),
            "runs": runs,
            "warmups": warmups,
            "strace_flags": "-q -y -f --seccomp-bpf -e %file,fork,clone,fcntl",
        },
    }

    # Initialize test in benchmarks if not present
    if test_name not in results["benchmarks"]:
        results["benchmarks"][test_name] = {}

    # Load existing results if file exists
    if os.path.exists(json_output):
        try:
            with open(json_output) as f:
                existing = json.load(f)
            # Merge existing results
            if "benchmarks" in existing:
                results["benchmarks"] = existing.get("benchmarks", {})
                if test_name not in results["benchmarks"]:
                    results["benchmarks"][test_name] = {}
            # Preserve existing metadata but update timestamp
            if "metadata" in existing:
                results["metadata"] = existing["metadata"]
                results["metadata"]["date"] = datetime.now().isoformat()
        except Exception as e:
            print(f"Warning: Could not load existing results: {e}", file=sys.stderr)

    # Extract results from strace benchmark (BPF not installed)
    strace_json = os.path.join(temp_dir, f"{test_name}_strace.json")
    results["benchmarks"][test_name]["baseline"] = extract_benchmark(strace_json, 0)
    results["benchmarks"][test_name]["strace"] = extract_benchmark(strace_json, 1)

    # Extract results from trace_v3 benchmark (BPF installed)
    trace_v3_json = os.path.join(temp_dir, f"{test_name}_trace_v3.json")
    results["benchmarks"][test_name]["baseline_bpf"] = extract_benchmark(
        trace_v3_json, 0
    )
    results["benchmarks"][test_name]["trace_v3"] = extract_benchmark(trace_v3_json, 1)

    # Write merged results to JSON
    with open(json_output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results merged to {json_output}")

    # Convert to CSV
    rows = [
        [
            "Test",
            "Scenario",
            "Geometric Mean (s)",
            "StdDev (s)",
            "Median (s)",
            "Min (s)",
            "Max (s)",
        ]
    ]
    for test_key, scenarios in results["benchmarks"].items():
        for scenario, data in scenarios.items():
            if data:
                rows.append(
                    [
                        test_key,
                        scenario,
                        f"{data['mean']:.6f}",
                        f"{data['stddev']:.6f}",
                        f"{data['median']:.6f}",
                        f"{data['min']:.6f}",
                        f"{data['max']:.6f}",
                    ]
                )

    with open(csv_output, "w", newline="") as f:
        csv.writer(f).writerows(rows)

    print(f"Results converted to {csv_output}")


if __name__ == "__main__":
    if len(sys.argv) != 7:
        print(
            "Usage: merge_results.py <temp_dir> <json_output> <csv_output> <test_name> <runs> <warmups>"
        )
        sys.exit(1)

    temp_dir = sys.argv[1]
    json_output = sys.argv[2]
    csv_output = sys.argv[3]
    test_name = sys.argv[4]
    runs = int(sys.argv[5])
    warmups = int(sys.argv[6])

    merge_results(temp_dir, json_output, csv_output, test_name, runs, warmups)
