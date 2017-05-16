use std::os::raw::*;
use std::ffi::CString;
use std::mem::transmute;

use libc::{self, dlsym, RTLD_NEXT};

#[cfg(any(not(target_os = "linux"), not(target_pointer_width = "64")))]
pub type NativeStat = libc::stat;

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
pub type NativeStat = libc::stat64;

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
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

#[cfg(target_os = "linux")]
#[cfg(not(target_pointer_width = "64"))]
lazy_static! {
    static ref ORIGINAL_XSTAT: unsafe extern fn(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__xstat").unwrap().as_ptr()))
    };
    static ref ORIGINAL_LXSTAT: unsafe extern fn(ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__lxstat").unwrap().as_ptr()))
    };
    static ref ORIGINAL_FXSTAT: unsafe extern fn(ver: c_int, fd: c_int, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__fxstat").unwrap().as_ptr()))
    };
    static ref ORIGINAL_FXSTATAT: unsafe extern fn(ver: c_int, dfd: c_int, path: *const c_char, buf: *mut libc::stat, flags: c_int) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("__fxstatat").unwrap().as_ptr()))
    };
}

#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
pub unsafe fn INTERNAL_STAT(path: *const c_char, buf: *mut NativeStat) -> c_int {
    ORIGINAL_XSTAT(0, path, buf)
}

#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
pub unsafe fn INTERNAL_LSTAT(path: *const c_char, buf: *mut NativeStat) -> c_int {
    ORIGINAL_LXSTAT(0, path, buf)
}

#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
pub unsafe fn INTERNAL_FSTAT(fd: c_int, buf: *mut NativeStat) -> c_int {
    ORIGINAL_FXSTAT(0, fd, buf)
}

#[allow(non_snake_case)]
#[cfg(target_os = "linux")]
pub unsafe fn INTERNAL_FSTATAT(dfd: c_int, path: *const c_char, buf: *mut NativeStat, flags: c_int) -> c_int {
    ORIGINAL_FXSTATAT(0, dfd, path, buf, flags)
}

#[cfg(not(target_os = "linux"))]
lazy_static! {
    pub static ref INTERNAL_STAT: unsafe extern fn(path: *const c_char, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("stat").unwrap().as_ptr()))
    };
    pub static ref INTERNAL_LSTAT: unsafe extern fn(path: *const c_char, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("lstat").unwrap().as_ptr()))
    };
    pub static ref INTERNAL_FSTAT: unsafe extern fn(fd: c_int, buf: *mut libc::stat) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("fstat").unwrap().as_ptr()))
    };
    pub static ref INTERNAL_FSTATAT: unsafe extern fn(dfd: c_int, path: *const c_char, buf: *mut libc::stat, flags: c_int) -> c_int = unsafe {
        transmute(dlsym(RTLD_NEXT, CString::new("fstatat").unwrap().as_ptr()))
    };
}
