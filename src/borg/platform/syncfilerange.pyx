# cython: language_level=3

from libc.stdint cimport int64_t


# Some Linux systems (like Termux on Android 7 or earlier) do not have access
# to sync_file_range. By isolating the access to sync_file_range in this
# separate extension, it can be imported dynamically from linux.pyx only when
# available and systems without support can otherwise use the rest of
# linux.pyx.
cdef extern from "fcntl.h":
    int sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags)
    unsigned int SYNC_FILE_RANGE_WRITE
    unsigned int SYNC_FILE_RANGE_WAIT_BEFORE
    unsigned int SYNC_FILE_RANGE_WAIT_AFTER
