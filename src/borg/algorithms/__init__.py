"""
borg.algorithms
===============

This package is intended for hash and checksum functions.

Ideally these would be sourced from existing libraries,
but:

- are frequently not available yet (lz4, zstd),
- are available but in poor form (crc32), or
- don't really make sense as a library (xxHash).
"""
