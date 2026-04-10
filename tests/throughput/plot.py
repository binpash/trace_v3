import csv
import sys

import matplotlib.pyplot as plt

def main():
    if len(sys.argv) < 3:
        print("Usage: python plot.py <input.csv> <output.png>")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_png = sys.argv[2]

    sizes = []
    max_procs = []

    with open(input_csv, "r") as f:
        reader = csv.reader(f)
        # Skip header if it exists (assuming header starts with 'ringbuf' or similar)
        header = next(reader, None)
        if header and not header[0].lower().startswith("ringbuf"):
            # If it wasn't a header, process it
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
        color="b",
        linewidth=2,
        markersize=8,
    )

    plt.xlabel("Ringbuffer Size", fontsize=12)
    plt.ylabel("Max Parallel Processes (No Missed Events)", fontsize=12)
    plt.title("Throughput Capacity Boundary by Ringbuffer Size", fontsize=14)
    plt.grid(True, linestyle="--", alpha=0.7)

    plt.tight_layout()
    plt.savefig(output_png, dpi=300)
    print(f"Plot saved successfully to {output_png}")


if __name__ == "__main__":

if __name__ == '__main__':
    main()
