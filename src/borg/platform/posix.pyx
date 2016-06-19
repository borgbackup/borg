import os, pwd

cdef extern from "wchar.h":
    cdef int wcswidth(const Py_UNICODE *str, size_t n)
 
def swidth(s):
    str_len = len(s)
    terminal_width = wcswidth(s, str_len)
    if terminal_width >= 0:
        return terminal_width
    else:
        return str_len

def switch_to_user(username):
    pw = pwd.getpwnam(username)
    uid = pw.pw_uid
    gid = pw.pw_gid
    os.setgroups(())
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    os.environ['LOGNAME'] = username
    os.environ['USER'] = username
    os.environ['USERNAME'] = username
    os.environ['HOME'] = pw.pw_dir
