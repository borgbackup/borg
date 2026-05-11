"""
Chunker Comparison Tool for Borg Backup

This script analyzes and compares the statistical properties of different chunking algorithms
used in Borg Backup (BuzHash and BuzHash64). It helps evaluate how data is split into chunks
by each algorithm, which is crucial for deduplication efficiency.

Usage:
    python scripts/chunker_comparison.py [options]

Options:
    -g, --graphical       Enable graphical output (requires matplotlib)
    -o, --output PATH     Output file prefix for saving plots (implies --graphical)
    -d, --directory PATH  Path to directory containing files to analyze (instead of random data)
    -s, --size SIZE       Size of random data in MB (default: 100MB, only used when not using --directory)

Examples:
    # Analyze with 100MB of random data
    python scripts/chunker_comparison.py

    # Analyze with 500MB of random data
    python scripts/chunker_comparison.py --size 500

    # Analyze files in a directory and show graphical output
    python scripts/chunker_comparison.py --directory /path/to/files --graphical

    # Analyze files and save plots to disk
    python scripts/chunker_comparison.py --directory /path/to/files --output results/chunker_analysis
"""

import os
import statistics
import argparse
from io import BytesIO
from collections import defaultdict

from borg.chunkers import Chunker, ChunkerBuzHash64

# Import matplotlib if available
try:
    import matplotlib.pyplot as plt
    import numpy as np

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


def analyze_chunker(chunker_class, name, data, min_exp, max_exp, mask_bits, winsize, seed_or_key, do_encrypt=False):
    """Analyze a chunker's performance on the given data."""
    chunk_sizes = []
    kwargs = dict(do_encrypt=do_encrypt) if name.startswith("BuzHash64") else {}
    chunker = chunker_class(seed_or_key, min_exp, max_exp, mask_bits, winsize, **kwargs)
    with BytesIO(data) as f:
        for chunk in chunker.chunkify(f):
            chunk_sizes.append(chunk.meta["size"])

    if not chunk_sizes:
        print(f"No chunks were produced by {name}")
        return None

    # Calculate statistics
    stats = {
        "name": name,
        "count": len(chunk_sizes),
        "min": min(chunk_sizes) if chunk_sizes else 0,
        "max": max(chunk_sizes) if chunk_sizes else 0,
        "mean": statistics.mean(chunk_sizes) if chunk_sizes else 0,
        "median": statistics.median(chunk_sizes) if chunk_sizes else 0,
        "std_dev": statistics.stdev(chunk_sizes) if len(chunk_sizes) > 1 else 0,
        "min_count": sum(int(size == 2**min_exp) for size in chunk_sizes),
        "max_count": sum(int(size == 2**max_exp) for size in chunk_sizes),
        "sizes": chunk_sizes,
    }

    return stats


def analyze_chunker_on_files(chunker_class, name, file_paths, min_exp, max_exp, mask_bits, winsize, seed=0):
    """Analyze a chunker's performance on multiple files individually."""
    all_chunk_sizes = []
    total_files_processed = 0

    for file_path in file_paths:
        try:
            # Skip empty files
            if os.path.getsize(file_path) == 0:
                continue

            # Process this individual file
            file_chunk_sizes = []
            chunker = chunker_class(seed, min_exp, max_exp, mask_bits, winsize)
            with open(file_path, "rb") as f:
                for chunk in chunker.chunkify(f):
                    file_chunk_sizes.append(chunk.meta["size"])

            # Add chunk sizes to our collection
            all_chunk_sizes.extend(file_chunk_sizes)

            total_files_processed += 1
            print(f"  Processed {file_path}: {len(file_chunk_sizes)} chunks")

        except (IOError, OSError) as e:
            print(f"  Error processing {file_path}: {e}")
            continue

    print(f"Total files processed with {name}: {total_files_processed}")

    if not all_chunk_sizes:
        print(f"No chunks were produced by {name}")
        return None

    # Calculate statistics
    stats = {
        "name": name,
        "count": len(all_chunk_sizes),
        "min": min(all_chunk_sizes) if all_chunk_sizes else 0,
        "max": max(all_chunk_sizes) if all_chunk_sizes else 0,
        "mean": statistics.mean(all_chunk_sizes) if all_chunk_sizes else 0,
        "median": statistics.median(all_chunk_sizes) if all_chunk_sizes else 0,
        "std_dev": statistics.stdev(all_chunk_sizes) if len(all_chunk_sizes) > 1 else 0,
        "min_count": sum(int(size == 2**min_exp) for size in all_chunk_sizes),
        "max_count": sum(int(size == 2**max_exp) for size in all_chunk_sizes),
        "sizes": all_chunk_sizes,
    }

    return stats


def print_stats(stats):
    """Print statistics for a chunker."""
    if stats is None:
        return

    print(f"Chunker: {stats['name']}")
    print(f"  Number of chunks: {stats['count']}")
    print(f"  Min chunk size: {stats['min']} bytes")
    print(f"  Max chunk size: {stats['max']} bytes")
    print(f"  Mean chunk size: {stats['mean']:.2f} bytes")
    print(f"  Median chunk size: {stats['median']:.2f} bytes")
    print(f"  Standard deviation: {stats['std_dev']:.2f} bytes")
    print(f"  Number of chunks at min size: {stats['min_count']} ({stats['min_count']/stats['count']*100:.2f}%)")
    print(f"  Number of chunks at max size: {stats['max_count']} ({stats['max_count']/stats['count']*100:.2f}%)")
    print()


def calculate_bucket(size):
    """Calculate the power-of-2 bucket for a given size."""
    # Calculate log2 manually
    bucket = 1
    while bucket < size:
        bucket *= 2
    return bucket


def plot_chunk_size_histogram(buzhash_stats, buzhash64_stats, output_file=None):
    """Plot histogram of chunk sizes for both chunkers."""
    if not MATPLOTLIB_AVAILABLE:
        print("Matplotlib is not available. Skipping histogram plot.")
        return

    plt.figure(figsize=(12, 6))

    # Create histograms with logarithmic bins
    min_size = min(min(buzhash_stats["sizes"]), min(buzhash64_stats["sizes"]))
    max_size = max(max(buzhash_stats["sizes"]), max(buzhash64_stats["sizes"]))

    # Create logarithmic bins
    bins = [2**i for i in range(int(np.log2(min_size)), int(np.log2(max_size)) + 2)]

    plt.hist(buzhash_stats["sizes"], bins=bins, alpha=0.5, label=buzhash_stats["name"])
    plt.hist(buzhash64_stats["sizes"], bins=bins, alpha=0.5, label=buzhash64_stats["name"])

    plt.xscale("log", base=2)
    plt.xlabel("Chunk Size (bytes)")
    plt.ylabel("Frequency")
    plt.title("Chunk Size Distribution")
    plt.grid(True, which="both", ls="--", alpha=0.5)
    plt.legend()

    if output_file:
        plt.savefig(f"{output_file}_histogram.png")
    else:
        plt.show()
    plt.close()


def plot_metrics_comparison(buzhash_stats, buzhash64_stats, output_file=None):
    """Plot comparison of key metrics between the two chunkers."""
    if not MATPLOTLIB_AVAILABLE:
        print("Matplotlib is not available. Skipping metrics comparison plot.")
        return

    metrics = ["count", "mean", "median", "std_dev"]
    buzhash_values = [buzhash_stats[m] for m in metrics]
    buzhash64_values = [buzhash64_stats[m] for m in metrics]

    # Normalize values for better visualization
    normalized_values = []
    for i, metric in enumerate(metrics):
        max_val = max(buzhash_values[i], buzhash64_values[i])
        normalized_values.append((buzhash_values[i] / max_val, buzhash64_values[i] / max_val))

    plt.figure(figsize=(10, 6))

    x = np.arange(len(metrics))
    width = 0.35

    plt.bar(x - width / 2, [v[0] for v in normalized_values], width, label=buzhash_stats["name"])
    plt.bar(x + width / 2, [v[1] for v in normalized_values], width, label=buzhash64_stats["name"])

    # Add actual values as text
    for i, metric in enumerate(metrics):
        plt.text(
            i - width / 2,
            normalized_values[i][0] + 0.05,
            f"{buzhash_values[i]:.1f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )
        plt.text(
            i + width / 2,
            normalized_values[i][1] + 0.05,
            f"{buzhash64_values[i]:.1f}",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.xlabel("Metric")
    plt.ylabel("Normalized Value")
    plt.title("Comparison of Key Metrics")
    plt.xticks(x, metrics)
    plt.legend()
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)

    if output_file:
        plt.savefig(f"{output_file}_metrics.png")
    else:
        plt.show()
    plt.close()


def plot_bucket_distribution(buzhash_dist, buzhash64_dist, buzhash_stats, buzhash64_stats, output_file=None):
    """Plot the power-of-2 bucket distribution."""
    if not MATPLOTLIB_AVAILABLE:
        print("Matplotlib is not available. Skipping bucket distribution plot.")
        return

    all_buckets = sorted(set(list(buzhash_dist.keys()) + list(buzhash64_dist.keys())))

    bh_pcts = [
        buzhash_dist[bucket] / buzhash_stats["count"] * 100 if buzhash_stats["count"] > 0 else 0
        for bucket in all_buckets
    ]
    bh64_pcts = [
        buzhash64_dist[bucket] / buzhash64_stats["count"] * 100 if buzhash64_stats["count"] > 0 else 0
        for bucket in all_buckets
    ]

    plt.figure(figsize=(12, 6))

    x = np.arange(len(all_buckets))
    width = 0.35

    plt.bar(x - width / 2, bh_pcts, width, label=buzhash_stats["name"])
    plt.bar(x + width / 2, bh64_pcts, width, label=buzhash64_stats["name"])

    plt.xlabel("Chunk Size Bucket (bytes)")
    plt.ylabel("Percentage of Chunks")
    plt.title("Chunk Size Distribution by Power-of-2 Buckets")
    plt.xticks(x, [f"{b:,}" for b in all_buckets], rotation=45)
    plt.legend()
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)

    if output_file:
        plt.savefig(f"{output_file}_buckets.png")
    else:
        plt.show()
    plt.close()


def read_files_from_directory(directory_path):
    """
    Recursively find files from a directory.

    Args:
        directory_path: Path to the directory to read files from

    Returns:
        list: List of file paths to be processed individually
    """
    print(f"Finding files in directory: {directory_path}")
    file_paths = []
    total_size = 0

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Skip symbolic links, device files, etc.
                if not os.path.isfile(file_path) or os.path.islink(file_path):
                    continue

                file_size = os.path.getsize(file_path)
                # Skip empty files
                if file_size == 0:
                    continue

                # Add file path to our list
                file_paths.append(file_path)
                total_size += file_size
                print(f"  Found {file_path} ({file_size/1024:.1f}KB)")

            except (IOError, OSError) as e:
                print(f"  Error accessing {file_path}: {e}")
                continue

    print(f"Total found: {len(file_paths)} files, {total_size/1024/1024:.1f}MB from directory {directory_path}")
    return file_paths


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Analyze and compare Borg chunkers")
    parser.add_argument("-g", "--graphical", action="store_true", help="Enable graphical output (requires matplotlib)")
    parser.add_argument(
        "-o", "--output", type=str, default=None, help="Output file prefix for saving plots (implies --graphical)"
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=str,
        default=None,
        help="Path to directory containing files to analyze (instead of random data)",
    )
    parser.add_argument(
        "-s",
        "--size",
        type=int,
        default=100,
        help="Size of random data in MB (default: 100MB, only used when not using --directory)",
    )
    args = parser.parse_args()

    # Check if graphical output is requested but matplotlib is not available
    if (args.graphical or args.output) and not MATPLOTLIB_AVAILABLE:
        print("Warning: Graphical output requested but matplotlib is not available.")
        print("Install matplotlib to enable graphical output.")
        args.graphical = False

    # Configuration parameters
    min_exp = 19  # Minimum chunk size = 2^min_exp
    max_exp = 23  # Maximum chunk size = 2^max_exp
    mask_bits = 21  # Target chunk size = 2^mask_bits
    winsize = 4095  # Rolling hash window size, must be uneven!

    print("=" * 80)
    print("BORG CHUNKER STATISTICAL ANALYSIS")
    print("=" * 80)
    print("Parameters:")
    print(f"  minexp={min_exp} (min chunk size: {2**min_exp} bytes)")
    print(f"  maxexp={max_exp} (max chunk size: {2**max_exp} bytes)")
    print(f"  maskbits={mask_bits} (target avg chunk size: ~{2**mask_bits} bytes)")
    print(f"  winsize={winsize}")
    print("-" * 80)

    # Get data for analysis - either from files or generate random data
    data_size = args.size * 1024 * 1024  # Convert MB to bytes

    if args.directory:
        # Get list of files from the specified directory
        file_paths = read_files_from_directory(args.directory)
        if not file_paths:
            print("Error: No files could be found in the specified directory.")
            return

        # Analyze both chunkers on individual files
        print("Analyzing chunkers on individual files...")
        buzhash_stats = analyze_chunker_on_files(Chunker, "BuzHash", file_paths, min_exp, max_exp, mask_bits, winsize)
        buzhash64_stats = analyze_chunker_on_files(
            ChunkerBuzHash64, "BuzHash64", file_paths, min_exp, max_exp, mask_bits, winsize
        )
    else:
        # Generate random data
        print(f"Generating {data_size/1024/1024:.1f}MB of random data...")
        data = os.urandom(data_size)

        # Analyze both chunkers on random data
        print("Analyzing chunkers...")
        seed = 0
        buzhash_stats = analyze_chunker(
            Chunker, "BuzHash", data, min_exp, max_exp, mask_bits, winsize, seed_or_key=seed
        )
        key = b"0123456789abcdef0123456789abcdef"
        encrypt = True
        name = "BuzHash64e" if encrypt else "BuzHash64"
        buzhash64_stats = analyze_chunker(
            ChunkerBuzHash64, name, data, min_exp, max_exp, mask_bits, winsize, seed_or_key=key, do_encrypt=encrypt
        )

    # Print statistics
    print("\nChunker Statistics:")
    print_stats(buzhash_stats)
    print_stats(buzhash64_stats)

    # Compare the chunkers
    if buzhash_stats and buzhash64_stats:
        print("Comparison:")
        print(f"  BuzHash64/BuzHash chunk count ratio: {buzhash64_stats['count']/buzhash_stats['count']:.2f}")
        print(f"  BuzHash64/BuzHash mean chunk size ratio: {buzhash64_stats['mean']/buzhash_stats['mean']:.2f}")
        print(f"  BuzHash64/BuzHash std dev ratio: {buzhash64_stats['std_dev']/buzhash_stats['std_dev']:.2f}")

        # Calculate chunk size distribution
        buzhash_dist = defaultdict(int)
        buzhash64_dist = defaultdict(int)

        # Group chunk sizes into power-of-2 buckets
        for size in buzhash_stats["sizes"]:
            bucket = calculate_bucket(size)
            buzhash_dist[bucket] += 1

        for size in buzhash64_stats["sizes"]:
            bucket = calculate_bucket(size)
            buzhash64_dist[bucket] += 1

        print("\nChunk Size Distribution (power-of-2 buckets):")
        print("  Size Bucket | BuzHash Count (%) | BuzHash64e Count (%)")
        print("  -----------|-------------------|-------------------")

        all_buckets = sorted(set(list(buzhash_dist.keys()) + list(buzhash64_dist.keys())))
        for bucket in all_buckets:
            bh_count = buzhash_dist[bucket]
            bh64_count = buzhash64_dist[bucket]
            bh_pct = bh_count / buzhash_stats["count"] * 100 if buzhash_stats["count"] > 0 else 0
            bh64_pct = bh64_count / buzhash64_stats["count"] * 100 if buzhash64_stats["count"] > 0 else 0
            print(f"  {bucket:10d} | {bh_count:5d} ({bh_pct:5.1f}%) | {bh64_count:5d} ({bh64_pct:5.1f}%)")

    # Add a summary of the findings
    if buzhash_stats and buzhash64_stats:
        # Generate graphical output if requested
        if args.graphical or args.output:
            print("\nGenerating graphical output...")
            plot_chunk_size_histogram(buzhash_stats, buzhash64_stats, args.output)
            plot_metrics_comparison(buzhash_stats, buzhash64_stats, args.output)
            plot_bucket_distribution(buzhash_dist, buzhash64_dist, buzhash_stats, buzhash64_stats, args.output)
            if args.output:
                print(f"Plots saved with prefix: {args.output}")


if __name__ == "__main__":
    main()
