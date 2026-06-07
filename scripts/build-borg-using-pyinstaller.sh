#!/bin/sh
# Generate a single-file binary of borgbackup using PyInstaller.

set -eu

OUTPUT_DIR="dist/binary"
SPEC_FILE="scripts/borg.exe.spec"

echo "Building single-file binary of borgbackup using PyInstaller..."

# Run PyInstaller compilation
# We use -y/--noconfirm to overwrite the output directory without asking.
# We use --clean to clean PyInstaller cache and temporary files before building.
mkdir -p $OUTPUT_DIR
pyinstaller \
    -y \
    --clean \
    --distpath="$OUTPUT_DIR" \
    "$SPEC_FILE"

echo "Single-file binary generated at:"
echo "$OUTPUT_DIR/borg.exe"
