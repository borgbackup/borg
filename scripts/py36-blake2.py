
"""
This script checks compatibility of crypto.blake2b_256 against hashlib.blake2b in CPython 3.6.
"""

import hashlib
import sys


def test_b2(b2_input, b2_output):
    digest = hashlib.blake2b(b2_input, digest_size=32).digest()
    identical = b2_output == digest

    print('Input:     ', b2_input.hex())
    print('Expected:  ', b2_output.hex())
    print('Calculated:', digest.hex())
    print('Identical: ', identical)
    print()
    if not identical:
        sys.exit(1)


test_b2(
    bytes.fromhex('037fb9b75b20d623f1d5a568050fccde4a1b7c5f5047432925e941a17c7a2d0d7061796c6f6164'),
    bytes.fromhex('a22d4fc81bb61c3846c334a09eaf28d22dd7df08c9a7a41e713ef28d80eebd45')
)

test_b2(
    b'abc',
    bytes.fromhex('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
)

test_b2(
    bytes.fromhex('e944973af2256d4d670c12dd75304c319f58f4e40df6fb18ef996cb47e063676') + b'1234567890' * 100,
    bytes.fromhex('97ede832378531dd0f4c668685d166e797da27b47d8cd441e885b60abd5e0cb2'),
)
