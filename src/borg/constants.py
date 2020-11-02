# this set must be kept complete, otherwise the RobustUnpacker might malfunction:
ITEM_KEYS = frozenset(['path', 'source', 'rdev', 'chunks', 'chunks_healthy', 'hardlink_master',
                       'mode', 'user', 'group', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'birthtime', 'size',
                       'xattrs', 'bsdflags', 'acl_nfs4', 'acl_access', 'acl_default', 'acl_extended',
                       'part'])

# this is the set of keys that are always present in items:
REQUIRED_ITEM_KEYS = frozenset(['path', 'mtime', ])

# this set must be kept complete, otherwise rebuild_manifest might malfunction:
ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'hostname', 'username', 'time', 'time_end',
                          'comment', 'chunker_params',
                          'recreate_cmdline',
                          'recreate_source_id', 'recreate_args', 'recreate_partial_chunks',  # used in 1.1.0b1 .. b2
                          ])

# this is the set of keys that are always present in archives:
REQUIRED_ARCHIVE_KEYS = frozenset(['version', 'name', 'items', 'cmdline', 'time', ])

# default umask, overridden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077

# default file mode to store stdin data, defaults to read/write for owner and group
# forcing to 0o100XXX later
STDIN_MODE_DEFAULT = 0o660

CACHE_TAG_NAME = 'CACHEDIR.TAG'
CACHE_TAG_CONTENTS = b'Signature: 8a477f597d28d172789f06886806bc55'

# A large, but not unreasonably large segment size. Always less than 2 GiB (for legacy file systems). We choose
# 500 MiB which means that no indirection from the inode is needed for typical Linux file systems.
# Note that this is a soft-limit and can be exceeded (worst case) by a full maximum chunk size and some metadata
# bytes. That's why it's 500 MiB instead of 512 MiB.
DEFAULT_MAX_SEGMENT_SIZE = 500 * 1024 * 1024

# 20 MiB minus 41 bytes for a Repository header (because the "size" field in the Repository includes
# the header, and the total size was set to 20 MiB).
MAX_DATA_SIZE = 20971479

# MAX_OBJECT_SIZE = <20 MiB (MAX_DATA_SIZE) + 41 bytes for a Repository PUT header, which consists of
# a 1 byte tag ID, 4 byte CRC, 4 byte size and 32 bytes for the ID.
MAX_OBJECT_SIZE = MAX_DATA_SIZE + 41  # see LoggedIO.put_header_fmt.size assertion in repository module
assert MAX_OBJECT_SIZE == 20 * 1024 * 1024

# repo config max_segment_size value must be below this limit to stay within uint32 offsets:
MAX_SEGMENT_SIZE_LIMIT = 2 ** 32 - MAX_OBJECT_SIZE

# borg.remote read() buffer size
BUFSIZE = 10 * 1024 * 1024

# to use a safe, limited unpacker, we need to set a upper limit to the archive count in the manifest.
# this does not mean that you can always really reach that number, because it also needs to be less than
# MAX_DATA_SIZE or it will trigger the check for that.
MAX_ARCHIVES = 400000

# repo.list() / .scan() result count limit the borg client uses
LIST_SCAN_LIMIT = 100000

DEFAULT_SEGMENTS_PER_DIR = 1000

FD_MAX_AGE = 4 * 60  # 4 minutes

CHUNK_MIN_EXP = 19  # 2**19 == 512kiB
CHUNK_MAX_EXP = 23  # 2**23 == 8MiB
HASH_WINDOW_SIZE = 0xfff  # 4095B
HASH_MASK_BITS = 21  # results in ~2MiB chunks statistically

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (15, 19, 17, HASH_WINDOW_SIZE)

# operating mode of the files cache (for fast skipping of unchanged files)
DEFAULT_FILES_CACHE_MODE_UI = 'ctime,size,inode'
DEFAULT_FILES_CACHE_MODE = 'cis'  # == CacheMode(DEFAULT_FILES_CACHE_MODE_UI)

# return codes returned by borg command
# when borg is killed by signal N, rc = 128 + N
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation
EXIT_SIGNAL_BASE = 128  # terminated due to signal, rc = 128 + sig_no

# never use datetime.isoformat(), it is evil. always use one of these:
# datetime.strftime(ISO_FORMAT)  # output always includes .microseconds
# datetime.strftime(ISO_FORMAT_NO_USECS)  # output never includes microseconds
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
