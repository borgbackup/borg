import errno
import os

from . import posix_ug

from libc.errno cimport errno as c_errno


def get_errno():
    return c_errno


def process_alive(host, pid, thread):
    """
    Check whether the (host, pid, thread_id) combination corresponds to a process potentially alive.

    If the process is local, then this will be accurate. If the process is not local, then this
    always returns True, since there is no real way to check.
    """
    from . import local_pid_alive
    from . import hostid

    assert isinstance(host, str)
    assert isinstance(hostid, str)
    assert isinstance(pid, int)
    assert isinstance(thread, int)

    if host != hostid:
        return True

    if thread != 0:
        # Currently, thread is always 0; if we ever decide to set this to a non-zero value,
        # this code needs to be revisited to do a sensible thing.
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
        # Any other error (e.g., permissions) means that the process ID refers to a live process.
        return True


def posix_acl_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid."""
    assert isinstance(acl, bytes)
    from ..helpers import safe_decode, safe_encode
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if len(fields) == 4:
                entries.append(':'.join([fields[0], fields[3], fields[2]]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def getosusername():
    """Return the OS username."""
    uid = os.getuid()
    return posix_ug._uid2user(uid, uid)
