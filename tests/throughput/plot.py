import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D


def fmt_eps(eps):
    if eps >= 1_000_000:
        return f"{eps / 1_000_000:.2f}M events/s"
    elif eps >= 1_000:
        return f"{eps / 1_000:.1f}K events/s"
    return f"{eps:.0f} events/s"


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_csv = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(script_dir, "output", "results.csv")
    )
    output_png = (
        sys.argv[2]
        if len(sys.argv) > 2
        else os.path.join(script_dir, "output", "throughput_boundary.png")
    )

    rows = []
    with open(input_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "size": row["RingbufSize"],
                "procs": int(row["Procs"]),
                "eps": float(row["EventsPerSec"]),
                "missed": int(row["Missed"]),
            })

    seen = set()
    sizes = []
    for r in rows:
        if r["size"] not in seen:
            seen.add(r["size"])
            sizes.append(r["size"])

    boundaries = {}
    for size in sizes:
        ok = [r["procs"] for r in rows if r["size"] == size and r["missed"] == 0]
        boundaries[size] = max(ok) if ok else 0

    col_w = max(len(s) for s in sizes) if sizes else 10
    print(f"\n{'Ringbuf Size':<{col_w}}  {'Max Procs':>10}  {'Max Throughput':>18}")
    print("-" * (col_w + 32))
    for size in sizes:
        boundary = boundaries[size]
        ok_eps = [r["eps"] for r in rows if r["size"] == size and r["missed"] == 0]
        max_eps = max(ok_eps) if ok_eps else 0
        print(f"{size:<{col_w}}  {boundary:>10}  {fmt_eps(max_eps):>18}")
    print()

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(sizes))

    all_procs = [r["procs"] for r in rows]
    boundary_vals = [boundaries[s] for s in sizes]
    y_max = max(max(all_procs) + 2, max(boundary_vals) + 2) if rows else 10

    rng = np.random.default_rng(42)
    for r in rows:
        xi = sizes.index(r["size"])
        jitter = rng.uniform(-0.2, 0.2)
        color = "#2ca02c" if r["missed"] == 0 else "#d62728"
        ax.scatter(
            xi + jitter, r["procs"],
            color=color, marker="o", s=60,
            zorder=3, alpha=0.85, edgecolors="white", linewidths=0.5,
        )

    legend_elements = [
        Line2D([0], [0], marker="o", color="w", markerfacecolor="#2ca02c", markersize=8, label="No misses"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor="#d62728", markersize=8, label="Missed events"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(sizes)
    ax.set_ylim(0, y_max)
    ax.set_xlabel("Ringbuffer Size", fontsize=12)
    ax.set_ylabel("Parallel Processes", fontsize=12)
    ax.set_title("Throughput Capacity Boundary by Ringbuffer Size", fontsize=14)
    ax.grid(True, linestyle="--", alpha=0.7, zorder=0)

    plt.tight_layout()
    plt.savefig(output_png, dpi=300)
    print(f"Plot saved to {output_png}")


if __name__ == "__main__":
    main()
