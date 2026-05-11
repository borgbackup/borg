#!/bin/sh
# Generate a single-file binary of borgbackup using Nuitka.

set -eu

OUTPUT_DIR="dist/binary"
OUTPUT_FILENAME="borg-nuitka.exe"  # .exe does NOT mean windows here
SRC_DIR="src/borg"

echo "Building single-file binary of borgbackup..."

# Run Nuitka compilation
# We use --assume-yes-for-downloads to avoid interactive prompts in automated runs.
# We set PYTHONPATH=src to ensure the local version of borg is used.
mkdir -p $OUTPUT_DIR
PYTHONPATH=src python -m nuitka \
    --mode=onefile \
    --assume-yes-for-downloads \
    --include-package=borg \
    --include-package=borghash \
    --include-package=borgstore \
    --output-dir="$OUTPUT_DIR" \
    --output-filename="$OUTPUT_FILENAME" \
    "$SRC_DIR"

echo "Single-file binary generated at:"
echo "$OUTPUT_DIR/$OUTPUT_FILENAME"
