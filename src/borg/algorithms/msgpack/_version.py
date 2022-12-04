# This is a bundled msgpack 0.5.6 with local modifications.
# Changes:
# +borg1: drop support for old buffer protocol to be compatible with py310
#         (backport of commit 9ae43709e42092c7f6a4e990d696d9005fa1623d)
# +borg2: Usef __BYTE_ORDER__ instead of __BYTE_ORDER (#513)
#         (backport of commit 9d45926a596028e39ec59dd909a56eb5e9e8fee7)
#         Fix build error caused by ntohs, ntohl (#514)
#         (backport of commit edca770071fc702e0b4c33f87fb0fa3682b486b4)
version = (0, 5, 6, '+borg2')

