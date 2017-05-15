use std::ffi::CStr;
use std::os::raw::*;

use std::os::unix::ffi::OsStrExt;

use libc;

use shared::*;

#[cfg(target_os = "linux")]
const AT_EMPTY_PATH: c_int = libc::AT_EMPTY_PATH;

#[cfg(not(target_os = "linux"))]
const AT_EMPTY_PATH: c_int = 0; // x & 0 will always be 0

wrap! {
    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        let ret = ORIG_UNLINK(path);
        if ret == 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), false) {
                send(Message::Remove(path.as_os_str().as_bytes()));
            }
        }
        Ok(ret)
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let ret = ORIG_UNLINKAT(dfd, path, flags);
        if ret == 0 {
            if let Ok(path) = cpath_at(dfd, CStr::from_ptr(path), false) {
                send(Message::Remove(path.as_os_str().as_bytes()));
            }
        }
        Ok(ret)
    }

    unsafe fn rename:ORIG_RENAME(oldpath: *const c_char, newpath: *const c_char) -> c_int {
        let ret = ORIG_RENAME(oldpath, newpath);
        if ret == 0 {
            if let Ok(oldpath) = cpath(CStr::from_ptr(oldpath), false) {
                if let Ok(newpath) = cpath(CStr::from_ptr(newpath), false) {
                    send(Message::Rename(oldpath.as_os_str().as_bytes(),
                        newpath.as_os_str().as_bytes()));
                }
            }
        }
        Ok(ret)
    }

    unsafe fn renameat:ORIG_RENAMEAT(olddfd: c_int, oldpath: *const c_char, newdfd: c_int, newpath: *const c_char) -> c_int {
        let ret = ORIG_RENAMEAT(olddfd, oldpath, newdfd, newpath);
        if ret == 0 {
            if let Ok(oldpath) = cpath_at(olddfd, CStr::from_ptr(oldpath), false) {
                if let Ok(newpath) = cpath_at(newdfd, CStr::from_ptr(newpath), false) {
                    send(Message::Rename(oldpath.as_os_str().as_bytes(),
                        newpath.as_os_str().as_bytes()));
                }
            }
        }
        Ok(ret)
    }

    unsafe fn link:ORIG_LINK(oldpath: *const c_char, newpath: *const c_char) -> c_int {
        let ret = ORIG_LINK(oldpath, newpath);
        if ret == 0 {
            if let Ok(oldpath) = cpath(CStr::from_ptr(oldpath), false) {
                if let Ok(newpath) = cpath(CStr::from_ptr(newpath), false) {
                    send(Message::Link(oldpath.as_os_str().as_bytes(),
                        newpath.as_os_str().as_bytes()));
                }
            }
        }
        Ok(ret)
    }

    unsafe fn linkat:ORIG_LINKAT(olddfd: c_int, oldpath: *const c_char, newdfd: c_int, newpath: *const c_char, flags: c_int) -> c_int {
        let ret = ORIG_LINKAT(olddfd, oldpath, newdfd, newpath, flags);
        if ret == 0 {
            let holder1;
            let holder2;
            let oldpath = if (flags & AT_EMPTY_PATH) != 0 {
                holder1 = FD_PATHS.read().unwrap();
                open_comms();
                get_fd_path!(holder1, olddfd).map_err(|_| ())
            } else {
                holder2 = cpath_at(olddfd, CStr::from_ptr(oldpath), (flags & libc::AT_SYMLINK_FOLLOW) != 0);
                holder2.as_ref().map_err(|_| ())
            };
            if let Ok(oldpath) = oldpath {
                if let Ok(newpath) = cpath_at(newdfd, CStr::from_ptr(newpath), (flags & libc::AT_SYMLINK_FOLLOW) != 0) {
                    send(Message::Link(oldpath.as_os_str().as_bytes(),
                        newpath.as_os_str().as_bytes()));
                }
            }
        }
        Ok(ret)
    }
}
