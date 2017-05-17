use std::os::raw::*;
use std::ffi::CString;
use std::mem::transmute;

use libc::{self, dlsym, RTLD_NEXT};

pub type NativeStat = libc::stat;

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
