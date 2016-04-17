# this set must be kept complete, otherwise the RobustUnpacker might malfunction:
ITEM_KEYS = set([b'path', b'source', b'rdev', b'chunks', b'hardlink_master',
                 b'mode', b'user', b'group', b'uid', b'gid', b'mtime', b'atime', b'ctime',
                 b'xattrs', b'bsdflags', b'acl_nfs4', b'acl_access', b'acl_default', b'acl_extended', ])

ARCHIVE_TEXT_KEYS = (b'name', b'comment', b'hostname', b'username', b'time', b'time_end')
ITEM_TEXT_KEYS = (b'path', b'source', b'user', b'group')

# default umask, overriden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077

CACHE_TAG_NAME = 'CACHEDIR.TAG'
CACHE_TAG_CONTENTS = b'Signature: 8a477f597d28d172789f06886806bc55'

DEFAULT_MAX_SEGMENT_SIZE = 5 * 1024 * 1024
DEFAULT_SEGMENTS_PER_DIR = 10000

CHUNK_MIN_EXP = 19  # 2**19 == 512kiB
CHUNK_MAX_EXP = 23  # 2**23 == 8MiB
HASH_WINDOW_SIZE = 0xfff  # 4095B
HASH_MASK_BITS = 21  # results in ~2MiB chunks statistically

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (12, 16, 14, HASH_WINDOW_SIZE)

# return codes returned by borg command
# when borg is killed by signal N, rc = 128 + N
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation

DASHES = '-' * 78

PBKDF2_ITERATIONS = 100000
