use std::ffi::CStr;
use std::os::raw::*;

use libc::mode_t;

use shared::*;

wrap! {
    unsafe fn open:ORIG_OPEN(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPEN(path, flags, mode);
        if ret > 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), true) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }

    unsafe fn creat:ORIG_CREAT(path: *const c_char, mode: mode_t) -> c_int {
        let ret = ORIG_CREAT(path, mode);
        if ret > 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), false) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }

    unsafe fn openat:ORIG_OPENAT(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPENAT(dfd, path, flags, mode);
        if ret > 0 {
            if let Ok(path) = cpath_at(dfd, CStr::from_ptr(path), true) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }

    unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        let ret = ORIG_CLOSE(fd);
        if ret == 0 {
            FD_PATHS.write().unwrap().remove(&fd);
        }
        Ok(ret)
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn open64:ORIG_OPEN64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPEN64(path, flags, mode);
        if ret > 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), true) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }

    unsafe fn creat64:ORIG_CREAT64(path: *const c_char, mode: mode_t) -> c_int {
        let ret = ORIG_CREAT64(path, mode);
        if ret > 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), false) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }

    unsafe fn openat64:ORIG_OPENAT64(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPENAT64(dfd, path, flags, mode);
        if ret > 0 {
            if let Ok(path) = cpath_at(dfd, CStr::from_ptr(path), true) {
                FD_PATHS.write().unwrap().insert(ret, path);
            }
        }
        Ok(ret)
    }
}
