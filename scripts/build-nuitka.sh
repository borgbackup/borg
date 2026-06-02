#!/bin/bash
# Generate a single-file binary of borgbackup using Nuitka.

set -euo pipefail

OUTPUT_DIR="build"
OUTPUT_FILENAME="borg-nuitka.exe"  # .exe does NOT mean windows here
SRC_DIR="src/borg"

echo "============================================"
echo "Found Nuitka $(python -m nuitka --version | head -n 1)."
echo "Building single-file binary of borgbackup..."
echo "============================================"

# Run Nuitka compilation
# We use --assume-yes-for-downloads to avoid interactive prompts in automated runs.
# We set PYTHONPATH=src to ensure the local version of borg is used.
# We include cffi and _cffi_backend to avoid runtime ModuleNotFoundError in argon2-cffi.
PYTHONPATH=src python -m nuitka \
    --standalone \
    --onefile \
    --assume-yes-for-downloads \
    --include-package=borg \
    --include-package=borghash \
    --include-package=borgstore \
    --include-package=cffi \
    --include-module=_cffi_backend \
    --output-dir="$OUTPUT_DIR" \
    --output-filename="$OUTPUT_FILENAME" \
    "$SRC_DIR"

echo "============================================="
echo "Build completed successfully!"
echo "Single-file binary generated at:"
echo "  $OUTPUT_DIR/$OUTPUT_FILENAME"
echo "============================================="
