#!/usr/bin/env python3
"""Plot benchmarking results for trace_v3"""

import json
import os
import sys

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("Error: Install matplotlib and numpy with: pip install matplotlib numpy")
    sys.exit(1)


def load_results(json_file):
    if not os.path.exists(json_file):
        print(f"Error: {json_file} not found")
        sys.exit(1)
    with open(json_file) as f:
        return json.load(f)


def plot_bars(results, test_name, output_dir):
    """Generate a bar chart for a single test"""
    if test_name not in results["benchmarks"]:
        return

    data = results["benchmarks"][test_name]

    # Four scenarios: baseline, strace, baseline_bpf, trace_v3
    scenarios = ["baseline", "strace", "baseline_bpf", "trace_v3"]
    means = [data[s]["mean"] if data.get(s) else 0 for s in scenarios]
    stddevs = [data[s]["stddev"] if data.get(s) else 0 for s in scenarios]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(scenarios))
    colors = ["#2ecc71", "#e74c3c", "#f39c12", "#3498db"]
    bars = ax.bar(x, means, 0.6, yerr=stddevs, capsize=5, color=colors, alpha=0.8)

    ax.set_ylabel("Time (seconds)", fontsize=12)
    ax.set_title(
        f"Benchmark: {test_name.replace('_', ' ').title()}",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_xticks(x)

    # Better labels for readability
    labels = [
        "Baseline\n(no BPF)",
        "Strace\n(no BPF)",
        "Baseline\n(BPF installed)",
        "trace_v3\n(BPF installed)",
    ]
    ax.set_xticklabels(labels, fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")

    for bar, mean, std in zip(bars, means, stddevs):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{mean:.2f}s\n±{std:.2f}s",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    # Calculate and display overheads
    if means[0] > 0:
        strace_oh = (means[1] - means[0]) / means[0] * 100 if means[1] > 0 else 0
        bpf_oh = (means[2] - means[0]) / means[0] * 100 if means[2] > 0 else 0
        trace_v3_oh = (means[3] - means[2]) / means[3] * 100 if means[3] > 0 else 0

        overhead_text = f"strace overhead: {strace_oh:+.1f}%\nBPF overhead: {bpf_oh:+.1f}%\ntrace_v3 overhead: {trace_v3_oh:+.1f}%"
        ax.text(
            0.98,
            0.97,
            overhead_text,
            transform=ax.transAxes,
            fontsize=9,
            va="top",
            ha="right",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
        )

    plt.tight_layout()
    out = os.path.join(output_dir, f"benchmark_{test_name}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Saved: {out}")
    plt.close()


def plot_strace_vs_trace_v3_scatter(results, output_dir):
    """Generate scatter plot comparing strace times vs trace_v3 times"""

    tests = []
    strace_times = []
    trace_v3_times = []

    for test_name, data in results["benchmarks"].items():
        strace_data = data.get("strace")
        trace_v3_data = data.get("trace_v3")

        if (
            strace_data
            and strace_data.get("mean")
            and trace_v3_data
            and trace_v3_data.get("mean")
        ):
            tests.append(test_name)
            strace_times.append(strace_data["mean"])
            trace_v3_times.append(trace_v3_data["mean"])

    if not tests:
        print("Warning: No strace/trace_v3 data found for scatter plot")
        return

    fig, ax = plt.subplots(figsize=(10, 10))

    # Plot data points
    ax.scatter(
        strace_times,
        trace_v3_times,
        s=100,
        alpha=0.6,
        color="#3498db",
        edgecolors="black",
        linewidth=1.5,
    )

    # Add labels for each point
    for test, strace, trace_v3 in zip(tests, strace_times, trace_v3_times):
        speedup = strace / trace_v3
        ax.annotate(
            f"{test} ({speedup:.1f}x)",
            (strace, trace_v3),
            xytext=(5, 5),
            textcoords="offset points",
            fontsize=9,
        )

    # Set log scale
    ax.set_xscale("log")
    ax.set_yscale("log")

    # Add diagonal line (equal performance)
    min_val = min(min(strace_times), min(trace_v3_times)) / 2
    max_val = max(max(strace_times), max(trace_v3_times)) * 2
    ax.plot(
        [min_val, max_val],
        [min_val, max_val],
        "r--",
        linewidth=2,
        label="Equal time (strace = trace_v3)",
        alpha=0.7,
    )

    # Add logarithmic speedup lines
    max_speedup = max(s / t for s, t in zip(strace_times, trace_v3_times))

    speedup_levels = []
    level = 2
    while level <= max(16, max_speedup * 2):
        speedup_levels.append(level)
        level *= 2

    for speedup in speedup_levels:
        ax.plot(
            [min_val, max_val],
            [min_val / speedup, max_val / speedup],
            "--",
            linewidth=1,
            color="gray",
            alpha=0.6,
            label=f"{speedup}x speedup",
        )
        ax.text(
            max_val,
            max_val / speedup,
            f"{speedup}x",
            fontsize=9,
            color="gray",
            va="bottom",
            ha="right",
        )

    ax.set_xlim([min_val, max_val])
    ax.set_ylim([min_val, max_val])

    # Shade regions
    ax.fill_between(
        [min_val, max_val],
        [min_val, max_val],
        max_val,
        alpha=0.1,
        color="red",
        label="strace faster",
    )
    ax.fill_between(
        [min_val, max_val],
        [min_val, max_val],
        min_val,
        alpha=0.1,
        color="green",
        label="trace_v3 faster",
    )

    ax.set_xlabel("Strace Time (seconds)", fontsize=12)
    ax.set_ylabel("trace_v3 Time (seconds)", fontsize=12)
    ax.set_title(
        "Strace vs trace_v3 Performance Comparison (Log Scale)",
        fontsize=14,
        fontweight="bold",
    )
    ax.grid(True, alpha=0.3, linestyle="--", which="both")
    ax.legend(fontsize=10, loc="upper left")

    plt.tight_layout()
    out = os.path.join(output_dir, "scatter_strace_vs_trace_v3.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Saved: {out}")
    plt.close()


def plot_bpf_overhead(results, output_dir):
    """Grouped bar chart: baseline vs baseline_bpf, normalized so baseline=1.0"""

    tests = []
    scale_factors = []
    bpf_heights = []
    baseline_errs = []  # [[lower_errs], [upper_errs]]
    bpf_errs = []

    for test_name, data in results["benchmarks"].items():
        baseline = data.get("baseline")
        baseline_bpf = data.get("baseline_bpf")

        if (
            baseline
            and baseline.get("mean")
            and baseline.get("min")
            and baseline.get("max")
            and baseline_bpf
            and baseline_bpf.get("mean")
            and baseline_bpf.get("min")
            and baseline_bpf.get("max")
        ):
            scale = 1.0 / baseline["mean"]
            tests.append(test_name)
            scale_factors.append(scale)
            bpf_heights.append(baseline_bpf["mean"] * scale)
            baseline_errs.append(
                [baseline["mean"] * scale - baseline["min"] * scale,
                 baseline["max"] * scale - baseline["mean"] * scale]
            )
            bpf_errs.append(
                [baseline_bpf["mean"] * scale - baseline_bpf["min"] * scale,
                 baseline_bpf["max"] * scale - baseline_bpf["mean"] * scale]
            )

    if not tests:
        print("Warning: No baseline data found for BPF overhead plot")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    n = len(tests)
    x = np.arange(n)
    width = 0.35

    baseline_lower = [e[0] for e in baseline_errs]
    baseline_upper = [e[1] for e in baseline_errs]
    bpf_lower = [e[0] for e in bpf_errs]
    bpf_upper = [e[1] for e in bpf_errs]

    ax.bar(
        x - width / 2, [1.0] * n, width,
        yerr=[baseline_lower, baseline_upper],
        capsize=5, color="#2ecc71", alpha=0.8, edgecolor="black", linewidth=1,
        label="Baseline (no BPF)",
    )
    ax.bar(
        x + width / 2, bpf_heights, width,
        yerr=[bpf_lower, bpf_upper],
        capsize=5, color="#f39c12", alpha=0.8, edgecolor="black", linewidth=1,
        label="Baseline (BPF installed)",
    )

    # Annotate overhead % above each bpf bar
    for i, h in enumerate(bpf_heights):
        overhead_pct = (h - 1.0) * 100
        ax.text(
            x[i] + width / 2,
            h + bpf_upper[i] + 0.01,
            f"{overhead_pct:+.1f}%",
            ha="center", va="bottom", fontsize=9,
        )

    ax.set_ylabel("Normalized time (baseline = 1.0)", fontsize=12)
    ax.set_title("BPF Program Installation Overhead", fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(tests, rotation=45, ha="right")
    ax.axhline(y=1.0, color="black", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")

    plt.tight_layout()
    out = os.path.join(output_dir, "bpf_overhead.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Saved: {out}")
    plt.close()


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "output")
    json_file = os.path.join(output_dir, "benchmark.json")
    results = load_results(json_file)

    print("Generating plots...")

    # Generate bar charts for each test
    for test in results["benchmarks"].keys():
        plot_bars(results, test, output_dir)

    # Generate scatter plot comparing strace vs trace_v3
    plot_strace_vs_trace_v3_scatter(results, output_dir)

    # Generate BPF overhead plot
    plot_bpf_overhead(results, output_dir)

    print("\n" + "=" * 80)
    print("Benchmark Summary:")
    print("=" * 80)
    for test, scenarios in results["benchmarks"].items():
        print(f"\n{test.upper()}:")
        print(
            f"  {'Scenario':<20} {'Geom. Mean (s)':<15} {'StdDev (s)':<12} {'vs Baseline':<12}"
        )
        print("  " + "-" * 76)

        baseline = (
            scenarios.get("baseline", {}).get("mean")
            if scenarios.get("baseline")
            else None
        )

        for scenario in ["baseline", "strace", "baseline_bpf", "trace_v3"]:
            data = scenarios.get(scenario)
            if data and data.get("mean"):
                if baseline and scenario != "baseline":
                    oh = (data["mean"] - baseline) / baseline * 100
                    oh_str = f"{oh:+.1f}%"
                else:
                    oh_str = "baseline"
                print(
                    f"  {scenario:<20} {data['mean']:>6.2f}s       ±{data['stddev']:>6.2f}s       {oh_str:>11}"
                )

    print("\n" + "=" * 80)
    print("Performance Comparison:")
    print("=" * 80)
    print(
        f"\n{'Test':<20} {'Strace (s)':<15} {'trace_v3 (s)':<15} {'Speedup (x)':<12} {'Faster':<10}"
    )
    print("-" * 80)

    for test_name, data in results["benchmarks"].items():
        strace = data.get("strace")
        trace_v3 = data.get("trace_v3")

        if strace and strace.get("mean") and trace_v3 and trace_v3.get("mean"):
            strace_mean = strace["mean"]
            trace_v3_mean = trace_v3["mean"]
            speedup = strace_mean / trace_v3_mean
            faster = "trace_v3" if speedup > 1 else "strace"
            print(
                f"{test_name:<20} {strace_mean:>6.3f}s        {trace_v3_mean:>6.3f}s        {speedup:>6.2f}x       {faster:>10}"
            )


if __name__ == "__main__":
    main()
