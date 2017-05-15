#!/usr/bin/env python3
import marshal
import sys

import msgpack

if len(sys.argv) not in (2, 3):
    print('Synopsis:', sys.argv[0], '<msgpack input>', '[marshal output]', file=sys.stderr)
    sys.exit(1)

if len(sys.argv) == 2:
    outfile = sys.stdout
else:
    outfile = open(sys.argv[2], 'wb')

with outfile:
    with open(sys.argv[1], 'rb') as infile:
        marshal.dump(msgpack.unpack(infile, use_list=False, encoding='utf-8'), outfile)
