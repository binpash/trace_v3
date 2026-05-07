import csv
import os
import sys

import matplotlib.pyplot as plt


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
    # Optional override of the X-axis column header so we can reuse this
    # script for both the trace_v3 RingbufSize curve and the bpftrace
    # PerfRbPages curve.
    x_label = sys.argv[3] if len(sys.argv) > 3 else "Ringbuffer Size"
    title = (
        sys.argv[4]
        if len(sys.argv) > 4
        else "Throughput Capacity Boundary by Ringbuffer Size"
    )

    sizes = []
    max_procs = []

    with open(input_csv, "r") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        # Treat the first row as data only if it doesn't look like a header.
        if header and not header[0].lower().startswith(("ringbuf", "perfrb")):
            sizes.append(header[0])
            max_procs.append(int(header[1]))

        for row in reader:
            if len(row) == 2:
                sizes.append(row[0])
                max_procs.append(int(row[1]))

    plt.figure(figsize=(10, 6))
    plt.plot(
        sizes,
        max_procs,
        marker="o",
        linestyle="-",
        color="g",
        linewidth=2,
        markersize=8,
    )

    if max_procs:
        y_max = max(16, max(max_procs) + 2)
        plt.ylim(0, y_max)
        plt.fill_between(sizes, 0, max_procs, color="green", alpha=0.3)
        plt.fill_between(sizes, max_procs, y_max, color="red", alpha=0.3)

    plt.xlabel(x_label, fontsize=12)
    plt.ylabel("Max Parallel Processes (No Missed Events)", fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True, linestyle="--", alpha=0.7)

    plt.tight_layout()
    plt.savefig(output_png, dpi=300)
    print(f"Plot saved successfully to {output_png}")


if __name__ == "__main__":
    main()
