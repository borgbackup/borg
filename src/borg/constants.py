# This set must be kept complete; otherwise the RobustUnpacker might malfunction:
ITEM_KEYS = frozenset(['path', 'source', 'rdev', 'chunks', 'chunks_healthy', 'hardlink_master',
                       'mode', 'user', 'group', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'birthtime', 'size',
                       'xattrs', 'bsdflags', 'acl_nfs4', 'acl_access', 'acl_default', 'acl_extended',
                       'part'])

# This is the set of keys that are always present in items:
REQUIRED_ITEM_KEYS = frozenset(['path', 'mtime', ])

# This set must be kept complete; otherwise rebuild_manifest might malfunction:
ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'hostname', 'username', 'time', 'time_end',
                          'comment', 'chunker_params',
                          'recreate_cmdline',
                          'recreate_source_id', 'recreate_args', 'recreate_partial_chunks',  # used in 1.1.0b1 .. b2
                          'size', 'csize', 'nfiles', 'size_parts', 'csize_parts', 'nfiles_parts', ])

# This is the set of keys that are always present in archives:
REQUIRED_ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'time', ])

# Default umask, overridden by --umask; defaults to read/write only for owner
UMASK_DEFAULT = 0o077

# Default file mode to store stdin data; defaults to read/write for owner and group.
# Forcing to 0o100XXX later.
STDIN_MODE_DEFAULT = 0o660

CACHE_TAG_NAME = 'CACHEDIR.TAG'
CACHE_TAG_CONTENTS = b'Signature: 8a477f597d28d172789f06886806bc55'

# A large, but not unreasonably large segment size. Always less than 2 GiB (for legacy file systems). We choose
# 500 MiB which means that no indirection from the inode is needed for typical Linux file systems.
# Note that this is a soft-limit and can be exceeded (worst case) by a full maximum chunk size and some metadata
# bytes. That's why it's 500 MiB instead of 512 MiB.
DEFAULT_MAX_SEGMENT_SIZE = 500 * 1024 * 1024

# 20 MiB minus 41 bytes for a Repository header (because the "size" field in the Repository includes
# the header, and the total size is set to 20 MiB).
MAX_DATA_SIZE = 20971479

# MAX_OBJECT_SIZE = <20 MiB (MAX_DATA_SIZE) + 41 bytes for a Repository PUT header, which consists of
# a 1 byte tag ID, 4 byte CRC, 4 byte size and 32 bytes for the ID.
MAX_OBJECT_SIZE = MAX_DATA_SIZE + 41  # see LoggedIO.put_header_fmt.size assertion in repository module
assert MAX_OBJECT_SIZE == 20 * 1024 * 1024

# repo config max_segment_size value must be below this limit to stay within uint32 offsets:
MAX_SEGMENT_SIZE_LIMIT = 2 ** 32 - MAX_OBJECT_SIZE

# have one all-zero bytes object
# we use it at all places where we need to detect or create all-zero buffers
zeros = bytes(MAX_DATA_SIZE)

# borg.remote read() buffer size
BUFSIZE = 10 * 1024 * 1024

# To use a safe, limited unpacker, we need to set an upper limit for the archive count in the manifest.
# This does not mean that you can always reach that number, because it also needs to be less than
# MAX_DATA_SIZE, otherwise it will trigger the check for that.
MAX_ARCHIVES = 400000

# repo.list()/.scan() result count limit used by the Borg client
LIST_SCAN_LIMIT = 100000

DEFAULT_SEGMENTS_PER_DIR = 1000

# Some bounds on segment / segment_dir indexes
MIN_SEGMENT_INDEX = 0
MAX_SEGMENT_INDEX = 2**32 - 1
MIN_SEGMENT_DIR_INDEX = 0
MAX_SEGMENT_DIR_INDEX = 2**32 - 1

FD_MAX_AGE = 4 * 60  # 4 minutes

CHUNK_MIN_EXP = 19  # 2**19 == 512 KiB
CHUNK_MAX_EXP = 23  # 2**23 == 8 MiB
HASH_WINDOW_SIZE = 0xfff  # 4095 B
HASH_MASK_BITS = 21  # Results in ~2 MiB chunks statistically

# chunker algorithms
CH_BUZHASH = 'buzhash'
CH_FIXED = 'fixed'

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CH_BUZHASH, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (CH_BUZHASH, 15, 19, 17, HASH_WINDOW_SIZE)

# normal on-disk data, allocated (but not written, all zeros), not allocated hole (all zeros)
CH_DATA, CH_ALLOC, CH_HOLE = 0, 1, 2

# Operating mode of the files cache (for fast skipping of unchanged files)
FILES_CACHE_MODE_UI_DEFAULT = 'ctime,size,inode'  # default for "borg create" command (CLI UI)
FILES_CACHE_MODE_DISABLED = 'd'  # Most Borg commands do not use the files cache at all (disable).

# return codes returned by borg command
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues (generic warning)
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation (generic error)
EXIT_ERROR_BASE = 3  # specific error codes are 3..99 (enabled by BORG_EXIT_CODES=modern)
EXIT_WARNING_BASE = 100  # specific warning codes are 100..127 (enabled by BORG_EXIT_CODES=modern)
EXIT_SIGNAL_BASE = 128  # terminated due to signal, rc = 128 + sig_no

# Never use datetime.isoformat(); it is problematic. Always use one of these:
# datetime.strftime(ISO_FORMAT)  # Output always includes .microseconds
# datetime.strftime(ISO_FORMAT_NO_USECS)  # Output never includes microseconds
ISO_FORMAT_NO_USECS = '%Y-%m-%dT%H:%M:%S'
ISO_FORMAT = ISO_FORMAT_NO_USECS + '.%f'

DASHES = '-' * 78

PBKDF2_ITERATIONS = 100000


REPOSITORY_README = """This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
"""

CACHE_README = """This is a Borg Backup cache.
See https://borgbackup.readthedocs.io/
"""
