# this set must be kept complete, otherwise the RobustUnpacker might malfunction:
ITEM_KEYS = frozenset(['path', 'source', 'rdev', 'chunks', 'chunks_healthy', 'hardlink_master',
                       'mode', 'user', 'group', 'uid', 'gid', 'mtime', 'atime', 'ctime',
                       'xattrs', 'bsdflags', 'acl_nfs4', 'acl_access', 'acl_default', 'acl_extended',
                       'part'])

# this is the set of keys that are always present in items:
REQUIRED_ITEM_KEYS = frozenset(['path', 'mtime', ])

# this set must be kept complete, otherwise rebuild_manifest might malfunction:
ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'hostname', 'username', 'time', 'time_end',
                          'comment', 'chunker_params',
                          'recreate_cmdline', 'recreate_source_id', 'recreate_args'])

# this is the set of keys that are always present in archives:
REQUIRED_ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'time', ])

# default umask, overriden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077

CACHE_TAG_NAME = 'CACHEDIR.TAG'
CACHE_TAG_CONTENTS = b'Signature: 8a477f597d28d172789f06886806bc55'

# A large, but not unreasonably large segment size. Always less than 2 GiB (for legacy file systems). We choose
# 500 MiB which means that no indirection from the inode is needed for typical Linux file systems.
# Note that this is a soft-limit and can be exceeded (worst case) by a full maximum chunk size and some metadata
# bytes. That's why it's 500 MiB instead of 512 MiB.
DEFAULT_MAX_SEGMENT_SIZE = 500 * 1024 * 1024

# A few hundred files per directory to go easy on filesystems which don't like too many files per dir (NTFS)
DEFAULT_SEGMENTS_PER_DIR = 500

CHUNK_MIN_EXP = 19  # 2**19 == 512kiB
CHUNK_MAX_EXP = 23  # 2**23 == 8MiB
HASH_WINDOW_SIZE = 0xfff  # 4095B
HASH_MASK_BITS = 21  # results in ~2MiB chunks statistically

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (15, 19, 17, HASH_WINDOW_SIZE)

# return codes returned by borg command
# when borg is killed by signal N, rc = 128 + N
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation

DASHES = '-' * 78

PBKDF2_ITERATIONS = 100000


REPOSITORY_README = """This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
"""

CACHE_README = """This is a Borg Backup cache.
See https://borgbackup.readthedocs.io/
"""
