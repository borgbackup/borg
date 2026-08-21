#!/usr/bin/env python3
"""
Generate a borg input map (borg create --map) from LVM thin pool metadata, see #4363.

This converts XML produced by the thin-provisioning-tools (thin_dump / thin_delta,
version >= 0.7.4 required - older thin_delta versions had bugs) into the map format
expected by ``borg create --map``, so borg only reads the parts of a thin LV snapshot
that actually contain (changed) data.

full mode - initial (or periodic full-read) backup of a thin LV snapshot:

    lvcreate -s -n snap1 vg/lv                # snapshot to back up (keep it for delta mode!)
    lvchange -ay -Ky vg/snap1
    dmsetup message vg-pool-tpool 0 reserve_metadata_snap
    thin_dump -m --dev-id $(lvs --noheadings -o thin_id vg/snap1) /dev/mapper/vg-pool_tmeta \
        | lvm-thin-map.py full --device /dev/vg/snap1 > snap1.map
    dmsetup message vg-pool-tpool 0 release_metadata_snap
    borg create --read-special --chunker-params fixed,4194304 \
        --map snap1.map lv-backup /dev/vg/snap1

    Unallocated ranges read as zeros, so borg stores them as holes without reading them.

delta mode - incremental backup against the previous snapshot's archive:

    lvcreate -s -n snap2 vg/lv
    lvchange -ay -Ky vg/snap2
    dmsetup message vg-pool-tpool 0 reserve_metadata_snap
    thin_delta -m --snap1 $(lvs --noheadings -o thin_id vg/snap1) \
               --snap2 $(lvs --noheadings -o thin_id vg/snap2) /dev/mapper/vg-pool_tmeta \
        | lvm-thin-map.py delta --device /dev/vg/snap2 > snap2.map
    dmsetup message vg-pool-tpool 0 release_metadata_snap
    borg create --read-special --chunker-params fixed,4194304 \
        --map snap2.map --reuse-from lv-backup lv-backup /dev/vg/snap2
    lvremove vg/snap1                         # snap2 is the reference for the next delta

    Ranges that are identical in both snapshots become "same" ranges: borg reuses the
    chunks of the --reuse-from reference archive for them, without reading the device.

Notes:

- The reference snapshot (--snap1) must be the snapshot that was backed up into the
  --reuse-from archive - THIS IS NOT CHECKED and cannot be. A wrong pairing silently
  produces an archive that does not match the device.
- Remember to release_metadata_snap; a leftover metadata snapshot blocks future reserves.
- The pool's chunk size (data_block_size) defines the map granularity. borg's fixed
  chunker block size does not need to match it; ranges are given in exact bytes.
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

DELTA_STATES = {
    "same": "same",  # unchanged between the two snapshots -> reuse reference chunks
    "different": "data",  # changed -> read
    "right_only": "data",  # newly allocated -> read
    "left_only": "zero",  # deallocated (discarded) -> reads as zeros now
}
SECTOR = 512


def die(msg):
    print(f"lvm-thin-map: error: {msg}", file=sys.stderr)
    sys.exit(2)


def device_size(args):
    if args.size is not None:
        return args.size
    fd = os.open(args.device, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def parse_ranges(xml_file, mode, meta):
    """Yield (start_block, length_blocks, state) from thin_dump / thin_delta XML; fill *meta* in place."""
    inside_device = False
    context = ET.iterparse(xml_file, events=("start", "end"))
    for event, elem in context:
        if event == "start":
            if elem.tag == "superblock":
                meta["data_block_size"] = int(elem.get("data_block_size")) * SECTOR
            elif elem.tag == "diff":
                meta["left"], meta["right"] = elem.get("left"), elem.get("right")
            elif elem.tag == "device":
                if "dev_id" in meta:
                    die("XML contains more than one <device>, re-run thin_dump with --dev-id")
                meta["dev_id"] = elem.get("dev_id")
                inside_device = True
            elif elem.tag == "range":
                die("nested <range> elements found - run thin_delta without --verbose")
            continue
        # end events
        if elem.tag == "device":
            inside_device = False
        elif mode == "delta" and elem.tag in DELTA_STATES:
            yield int(elem.get("begin")), int(elem.get("length")), DELTA_STATES[elem.tag]
        elif mode == "full" and elem.tag in ("single_mapping", "range_mapping"):
            if not inside_device:
                die(f"<{elem.tag}> outside of a <device> element - unsupported thin_dump output")
            if elem.tag == "single_mapping":
                yield int(elem.get("origin_block")), 1, "data"
            else:
                yield int(elem.get("origin_begin")), int(elem.get("length")), "data"
        elem.clear()


def main():
    parser = argparse.ArgumentParser(
        description="convert thin_dump/thin_delta XML into a borg input map (borg create --map)"
    )
    parser.add_argument("mode", choices=("full", "delta"), help="full: thin_dump XML, delta: thin_delta XML")
    parser.add_argument("xml", nargs="?", default="-", help="XML input file (default: stdin)")
    size_group = parser.add_mutually_exclusive_group(required=True)
    size_group.add_argument("--device", help="get the map's total size from this block device")
    size_group.add_argument("--size", type=int, help="give the map's total size in bytes")
    args = parser.parse_intermixed_args()

    size = device_size(args)
    xml_file = sys.stdin.buffer if args.xml == "-" else args.xml

    out = []  # coalesced [start, end, state] ranges, in bytes
    offset = 0  # next expected byte offset
    meta = {}

    def emit(start, end, state):
        nonlocal offset
        if start < offset:
            die(f"XML ranges overlap or are not sorted (at byte offset {start})")
        if start > offset:
            emit_range(offset, start, "zero")  # gap: unallocated in all snapshots, reads as zeros
        emit_range(start, end, state)
        offset = end

    def emit_range(start, end, state):
        if out and out[-1][2] == state and out[-1][1] == start:
            out[-1][1] = end
        else:
            out.append([start, end, state])

    for begin, length, state in parse_ranges(xml_file, args.mode, meta):
        block_size = meta["data_block_size"]
        emit(begin * block_size, (begin + length) * block_size, state)

    if "data_block_size" not in meta:
        die("no <superblock> found in the XML input")
    if offset > size:
        die(f"XML mappings end at {offset}, beyond the given size {size} - wrong device or size?")
    if offset < size:
        emit_range(offset, size, "zero")

    print(f"# borg input map generated by lvm-thin-map.py ({args.mode} mode)")
    print(f"# size: {size} bytes, thin pool chunk size: {meta['data_block_size']} bytes")
    if args.mode == "delta":
        print(f"# thin_delta left (reference) dev_id: {meta.get('left')}, right dev_id: {meta.get('right')}")
    else:
        print(f"# thin_dump dev_id: {meta.get('dev_id')}")
    for start, end, state in out:
        print(f"{start} {end - start} {state}")


if __name__ == "__main__":
    main()
