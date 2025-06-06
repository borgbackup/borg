# this set must be kept complete, otherwise the RobustUnpacker might malfunction:
# fmt: off
ITEM_KEYS = frozenset(['path', 'source', 'target', 'rdev', 'chunks', 'chunks_healthy', 'hardlink_master', 'hlid',
                       'mode', 'user', 'group', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'birthtime', 'size', 'inode',
                       'xattrs', 'bsdflags', 'acl_nfs4', 'acl_access', 'acl_default', 'acl_extended',
                       'part'])
# fmt: on

# this is the set of keys that are always present in items:
REQUIRED_ITEM_KEYS = frozenset(["path", "mtime"])

# this set must be kept complete, otherwise rebuild_manifest might malfunction:
# fmt: off
ARCHIVE_KEYS = frozenset(['version', 'name', 'hostname', 'username', 'time', 'time_end',
                          'tags',  # v2+ archives
                          'items',  # legacy v1 archives
                          'item_ptrs',  # v2+ archives
                          'comment', 'chunker_params',
                          'command_line', 'recreate_command_line',  # v2+ archives
                          'cmdline', 'recreate_cmdline',  # legacy
                          'recreate_source_id', 'recreate_args', 'recreate_partial_chunks',  # used in 1.1.0b1 .. b2
                          'size', 'nfiles',
                          'size_parts', 'nfiles_parts',  # legacy v1 archives
                          ])
# fmt: on

# this is the set of keys that are always present in archives:
REQUIRED_ARCHIVE_KEYS = frozenset(["version", "name", "item_ptrs", "command_line", "time"])

# default umask, overridden by --umask, defaults to read/write only for owner
UMASK_DEFAULT = 0o077

# default file mode to store stdin data, defaults to read/write for owner and group
# forcing to 0o100XXX later
STDIN_MODE_DEFAULT = 0o660

# RepoObj types
ROBJ_MANIFEST = "M"  # Manifest (directory of archives, other metadata) object
ROBJ_ARCHIVE_META = "A"  # main archive metadata object
ROBJ_ARCHIVE_CHUNKIDS = "C"  # objects with a list of archive metadata stream chunkids
ROBJ_ARCHIVE_STREAM = "S"  # archive metadata stream chunk (containing items)
ROBJ_FILE_STREAM = "F"  # file content stream chunk (containing user data)
ROBJ_DONTCARE = "*"  # used to parse without type assertion (= accept any type)

# in borg < 1.3, this has been defined like this:
# 20 MiB minus 41 bytes for a PUT header (because the "size" field in the Repository includes
# the header, and the total size was set to precisely 20 MiB for borg < 1.3).
MAX_DATA_SIZE = 20971479

# MAX_OBJECT_SIZE = MAX_DATA_SIZE + len(PUT2 header)
# note: for borg >= 1.3, this makes the MAX_OBJECT_SIZE grow slightly over the precise 20MiB used by
# borg < 1.3, but this is not expected to cause any issues.
MAX_OBJECT_SIZE = MAX_DATA_SIZE + 41 + 8  # see assertion at end of repository module

# How many segment files borg puts into a single directory by default.
DEFAULT_SEGMENTS_PER_DIR = 1000

# A large, but not unreasonably large segment size. Always less than 2 GiB (for legacy file systems). We choose
# 500 MiB which means that no indirection from the inode is needed for typical Linux file systems.
# Note that this is a soft-limit and can be exceeded (worst case) by a full maximum chunk size and some metadata
# bytes. That's why it's 500 MiB instead of 512 MiB.
DEFAULT_MAX_SEGMENT_SIZE = 500 * 1024 * 1024

# repo config max_segment_size value must be below this limit to stay within uint32 offsets:
MAX_SEGMENT_SIZE_LIMIT = 2**32 - MAX_OBJECT_SIZE

# how many metadata stream chunk ids do we store into a "pointer chunk" of the ArchiveItem.item_ptrs list?
IDS_PER_CHUNK = MAX_DATA_SIZE // 40

# have one all-zero bytes object
# we use it at all places where we need to detect or create all-zero buffers
zeros = bytes(MAX_DATA_SIZE)

# borg.remote read() buffer size
BUFSIZE = 10 * 1024 * 1024

# to use a safe, limited unpacker, we need to set a upper limit to the archive count in the manifest.
# this does not mean that you can always really reach that number, because it also needs to be less than
# MAX_DATA_SIZE or it will trigger the check for that.
MAX_ARCHIVES = 400000

# repo.list() result count limit the borg client uses
LIST_SCAN_LIMIT = 100000

FD_MAX_AGE = 4 * 60  # 4 minutes

# Some bounds on segment / segment_dir indexes
MIN_SEGMENT_INDEX = 0
MAX_SEGMENT_INDEX = 2**32 - 1
MIN_SEGMENT_DIR_INDEX = 0
MAX_SEGMENT_DIR_INDEX = 2**32 - 1

# chunker algorithms
CH_BUZHASH = "buzhash"
CH_BUZHASH64 = "buzhash64"
CH_FIXED = "fixed"
CH_FAIL = "fail"

# buzhash chunker params
CHUNK_MIN_EXP = 19  # 2**19 == 512kiB
CHUNK_MAX_EXP = 23  # 2**23 == 8MiB
HASH_WINDOW_SIZE = 0xFFF  # 4095B
HASH_MASK_BITS = 21  # results in ~2MiB chunks statistically

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CH_BUZHASH, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)
CHUNKER64_PARAMS = (CH_BUZHASH64, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (CH_BUZHASH, 15, 19, 17, HASH_WINDOW_SIZE)

# normal on-disk data, allocated (but not written, all zeros), not allocated hole (all zeros)
CH_DATA, CH_ALLOC, CH_HOLE = 0, 1, 2

# operating mode of the files cache (for fast skipping of unchanged files)
FILES_CACHE_MODE_UI_DEFAULT = "ctime,size,inode"  # default for "borg create" command (CLI UI)
FILES_CACHE_MODE_DISABLED = "d"  # most borg commands do not use the files cache at all (disable)

# account for clocks being slightly out-of-sync, timestamps granularity.
# we can't go much higher here (like e.g. to 2s) without causing issues.
TIME_DIFFERS1_NS = 20000000

# similar to above, but for bigger granularity / clock differences
TIME_DIFFERS2_NS = 3000000000

# tar related
SCHILY_XATTR = "SCHILY.xattr."  # xattr key prefix in tar PAX headers

# special tags
# @PROT protects archives against accidential deletion or modification by delete, prune or recreate.
SPECIAL_TAGS = frozenset(["@PROT"])

# return codes returned by borg command
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues (generic warning)
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation (generic error)
EXIT_ERROR_BASE = 3  # specific error codes are 3..99 (enabled by BORG_EXIT_CODES=modern)
EXIT_WARNING_BASE = 100  # specific warning codes are 100..127 (enabled by BORG_EXIT_CODES=modern)
EXIT_SIGNAL_BASE = 128  # terminated due to signal, rc = 128 + sig_no

ISO_FORMAT_NO_USECS = "%Y-%m-%dT%H:%M:%S"
ISO_FORMAT = ISO_FORMAT_NO_USECS + ".%f"

DASHES = "-" * 78

PBKDF2_ITERATIONS = 100000

# https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.2
ARGON2_ARGS = {"time_cost": 3, "memory_cost": 2**16, "parallelism": 4, "type": "id"}
ARGON2_SALT_BYTES = 16

# Maps the CLI argument to our internal identifier for the format
KEY_ALGORITHMS = {
    # encrypt-and-MAC, kdf: PBKDF2(HMAC−SHA256), encryption: AES256-CTR, authentication: HMAC-SHA256
    "pbkdf2": "sha256",
    # encrypt-then-MAC, kdf: argon2, encryption: chacha20, authentication: poly1305
    "argon2": "argon2 chacha20-poly1305",
}


class KeyBlobStorage:
    NO_STORAGE = "no_storage"
    KEYFILE = "keyfile"
    REPO = "repository"


class KeyType:
    # legacy crypto
    # upper 4 bits are ciphersuite, 0 == legacy AES-CTR
    KEYFILE = 0x00
    # repos with PASSPHRASE mode could not be created any more since borg 1.0, see #97.
    # in borg 2. all of its code and also the "borg key migrate-to-repokey" command was removed.
    # if you still need to, you can use "borg key migrate-to-repokey" with borg 1.0, 1.1 and 1.2.
    # Nowadays, we just dispatch this to RepoKey and assume the passphrase was migrated to a repokey.
    PASSPHRASE = 0x01  # legacy, borg < 1.0
    PLAINTEXT = 0x02
    REPO = 0x03
    BLAKE2KEYFILE = 0x04
    BLAKE2REPO = 0x05
    BLAKE2AUTHENTICATED = 0x06
    AUTHENTICATED = 0x07
    # new crypto
    # upper 4 bits are ciphersuite, lower 4 bits are keytype
    AESOCBKEYFILE = 0x10
    AESOCBREPO = 0x11
    CHPOKEYFILE = 0x20
    CHPOREPO = 0x21
    BLAKE2AESOCBKEYFILE = 0x30
    BLAKE2AESOCBREPO = 0x31
    BLAKE2CHPOKEYFILE = 0x40
    BLAKE2CHPOREPO = 0x41


CACHE_TAG_NAME = "CACHEDIR.TAG"
CACHE_TAG_CONTENTS = b"Signature: 8a477f597d28d172789f06886806bc55"

REPOSITORY_README = """This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
"""

CACHE_README = """This is a Borg Backup cache.
See https://borgbackup.readthedocs.io/
"""
