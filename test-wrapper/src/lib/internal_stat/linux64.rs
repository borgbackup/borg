use std::os::raw::*;
use std::ffi::CString;
use std::mem::transmute;

use libc::{self, dlsym, RTLD_NEXT};

pub type NativeStat = libc::stat64;

lazy_static! {
    static ref ORIGINAL_XSTAT: unsafe extern fn(ver: c_int, path: *const c_char, buf: *mut libc::stat64) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__xstat64").unwrap().as_ptr()))
    };
    static ref ORIGINAL_LXSTAT: unsafe extern fn(ver: c_int, path: *const c_char, buf: *mut libc::stat64) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__lxstat64").unwrap().as_ptr()))
    };
    static ref ORIGINAL_FXSTAT: unsafe extern fn(ver: c_int, fd: c_int, buf: *mut libc::stat64) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__fxstat64").unwrap().as_ptr()))
    };
    static ref ORIGINAL_FXSTATAT: unsafe extern fn(ver: c_int, dfd: c_int, path: *const c_char, buf: *mut libc::stat64, flags: c_int) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__fxstatat64").unwrap().as_ptr()))
    };
}

pub unsafe fn INTERNAL_STAT(path: *const c_char, buf: *mut NativeStat) -> c_int {
    ORIGINAL_XSTAT(1, path, buf)
}

pub unsafe fn INTERNAL_LSTAT(path: *const c_char, buf: *mut NativeStat) -> c_int {
    ORIGINAL_LXSTAT(1, path, buf)
}

pub unsafe fn INTERNAL_FSTAT(fd: c_int, buf: *mut NativeStat) -> c_int {
    ORIGINAL_FXSTAT(1, fd, buf)
}

pub unsafe fn INTERNAL_FSTATAT(dfd: c_int, path: *const c_char, buf: *mut NativeStat, flags: c_int) -> c_int {
    ORIGINAL_FXSTATAT(1, dfd, path, buf, flags)
}
