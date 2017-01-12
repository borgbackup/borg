import errno
import os
import uuid
import socket
import subprocess


cdef extern from "wchar.h":
    cdef int wcswidth(const Py_UNICODE *str, size_t n)


def swidth(s):
    str_len = len(s)
    terminal_width = wcswidth(s, str_len)
    if terminal_width >= 0:
        return terminal_width
    else:
        return str_len


# only determine the PID and hostname once.
# for FUSE mounts, we fork a child process that needs to release
# the lock made by the parent, so it needs to use the same PID for that.
_pid = os.getpid()
# XXX this sometimes requires live internet access for issuing a DNS query in the background.
_hostname = '%s@%s' % (socket.getfqdn(), uuid.getnode())


def get_process_id():
    """
    Return identification tuple (hostname, pid, thread_id) for 'us'. If this is a FUSE process, then the PID will be
    that of the parent, not the forked FUSE child.

    Note: Currently thread_id is *always* zero.
    """
    thread_id = 0
    return _hostname, _pid, thread_id


def process_alive(host, pid, thread):
    """
    Check if the (host, pid, thread_id) combination corresponds to a potentially alive process.

    If the process is local, then this will be accurate. If the process is not local, then this
    returns always True, since there is no real way to check.
    """
    from . import local_pid_alive

    if host != _hostname:
        return True

    if thread != 0:
        # Currently thread is always 0, if we ever decide to set this to a non-zero value,
        # this code needs to be revisited, too, to do a sensible thing
        return True

    return local_pid_alive(pid)


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    try:
        # This doesn't work on Windows.
        # This does not kill anything, 0 means "see if we can send a signal to this process or not".
        # Possible errors: No such process (== stale lock) or permission denied (not a stale lock).
        # If the exception is not raised that means such a pid is valid and we can send a signal to it.
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH = no such process
            return False
        # Any other error (eg. permissions) means that the process ID refers to a live process.
        return True


# most POSIX platforms (but not Linux)
def umount(mountpoint):
    return subprocess.call(['umount', mountpoint])
