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

    # Five scenarios: baseline, strace, bpftrace+post_process, baseline_bpf, trace_v3
    scenarios = ["baseline", "strace", "bpftrace", "baseline_bpf", "trace_v3"]
    means = [data[s]["mean"] if data.get(s) else 0 for s in scenarios]
    stddevs = [data[s]["stddev"] if data.get(s) else 0 for s in scenarios]

    fig, ax = plt.subplots(figsize=(13, 6))
    x = np.arange(len(scenarios))
    colors = ["#2ecc71", "#e74c3c", "#9b59b6", "#f39c12", "#3498db"]
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
        "bpftrace+post\n(no BPF)",
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
        bpftrace_oh = (means[2] - means[0]) / means[0] * 100 if means[2] > 0 else 0
        bpf_oh = (means[3] - means[0]) / means[0] * 100 if means[3] > 0 else 0
        trace_v3_oh = (
            (means[4] - means[3]) / means[4] * 100 if means[4] > 0 and means[3] > 0 else 0
        )

        overhead_text = (
            f"strace overhead: {strace_oh:+.1f}%\n"
            f"bpftrace overhead: {bpftrace_oh:+.1f}%\n"
            f"BPF overhead: {bpf_oh:+.1f}%\n"
            f"trace_v3 overhead: {trace_v3_oh:+.1f}%"
        )
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


def _scatter_vs_trace_v3(results, output_dir, competitor_key, competitor_label):
    """Generic log-log scatter: <competitor> time on x, trace_v3 time on y.

    The diagonal is equal performance; isobars below the diagonal mark Nx
    speedups for trace_v3. We render one PNG per competitor so the
    strace-vs-trace_v3 plot stays the same and a parallel bpftrace plot drops
    in next to it without disturbing the existing visual baseline.
    """
    tests = []
    competitor_times = []
    trace_v3_times = []

    for test_name, data in results["benchmarks"].items():
        c = data.get(competitor_key)
        v = data.get("trace_v3")
        if c and c.get("mean") and v and v.get("mean"):
            tests.append(test_name)
            competitor_times.append(c["mean"])
            trace_v3_times.append(v["mean"])

    if not tests:
        print(f"Warning: No {competitor_key}/trace_v3 data found for scatter plot")
        return

    fig, ax = plt.subplots(figsize=(10, 10))

    ax.scatter(
        competitor_times,
        trace_v3_times,
        s=100,
        alpha=0.6,
        color="#3498db",
        edgecolors="black",
        linewidth=1.5,
    )

    for test, c, v in zip(tests, competitor_times, trace_v3_times):
        speedup = c / v
        ax.annotate(
            f"{test} ({speedup:.1f}x)",
            (c, v),
            xytext=(5, 5),
            textcoords="offset points",
            fontsize=9,
        )

    ax.set_xscale("log")
    ax.set_yscale("log")

    min_val = min(min(competitor_times), min(trace_v3_times)) / 2
    max_val = max(max(competitor_times), max(trace_v3_times)) * 2
    ax.plot(
        [min_val, max_val],
        [min_val, max_val],
        "r--",
        linewidth=2,
        label=f"Equal time ({competitor_label} = trace_v3)",
        alpha=0.7,
    )

    max_speedup = max(c / v for c, v in zip(competitor_times, trace_v3_times))
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

    ax.fill_between(
        [min_val, max_val], [min_val, max_val], max_val,
        alpha=0.1, color="red", label=f"{competitor_label} faster",
    )
    ax.fill_between(
        [min_val, max_val], [min_val, max_val], min_val,
        alpha=0.1, color="green", label="trace_v3 faster",
    )

    ax.set_xlabel(f"{competitor_label} Time (seconds)", fontsize=12)
    ax.set_ylabel("trace_v3 Time (seconds)", fontsize=12)
    ax.set_title(
        f"{competitor_label} vs trace_v3 Performance Comparison (Log Scale)",
        fontsize=14, fontweight="bold",
    )
    ax.grid(True, alpha=0.3, linestyle="--", which="both")
    ax.legend(fontsize=10, loc="upper left")

    plt.tight_layout()
    out = os.path.join(output_dir, f"scatter_{competitor_key}_vs_trace_v3.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Saved: {out}")
    plt.close()


def plot_strace_vs_trace_v3_scatter(results, output_dir):
    _scatter_vs_trace_v3(results, output_dir, "strace", "Strace")


def plot_bpftrace_vs_trace_v3_scatter(results, output_dir):
    _scatter_vs_trace_v3(results, output_dir, "bpftrace", "bpftrace+post")


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

    # Generate scatter plot comparing bpftrace+post vs trace_v3
    plot_bpftrace_vs_trace_v3_scatter(results, output_dir)

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

        for scenario in ["baseline", "strace", "bpftrace", "baseline_bpf", "trace_v3"]:
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
        f"\n{'Test':<20} {'Strace (s)':<13} {'bpftrace (s)':<14} {'trace_v3 (s)':<14} "
        f"{'st/v3 (x)':<10} {'bt/v3 (x)':<10}"
    )
    print("-" * 90)

    for test_name, data in results["benchmarks"].items():
        strace = data.get("strace")
        bpftrace = data.get("bpftrace")
        trace_v3 = data.get("trace_v3")

        if not (trace_v3 and trace_v3.get("mean")):
            continue
        v3_mean = trace_v3["mean"]
        st_mean = strace["mean"] if strace and strace.get("mean") else float("nan")
        bt_mean = bpftrace["mean"] if bpftrace and bpftrace.get("mean") else float("nan")
        st_speedup = st_mean / v3_mean if st_mean == st_mean else float("nan")
        bt_speedup = bt_mean / v3_mean if bt_mean == bt_mean else float("nan")
        print(
            f"{test_name:<20} {st_mean:>7.3f}s     {bt_mean:>7.3f}s      "
            f"{v3_mean:>7.3f}s      {st_speedup:>6.2f}x   {bt_speedup:>6.2f}x"
        )


if __name__ == "__main__":
    main()
