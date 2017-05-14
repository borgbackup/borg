use std::slice;
use std::ptr;
use std::ffi::CStr;
use std::os::raw::*;
use std::path::Path;

use std::os::unix::ffi::OsStrExt;

use libc;

use shared::*;

unsafe fn setxattr_base(path: &Path, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> Result<c_int> {
    if !path.exists() {
        return Err(libc::ENOENT);
    }
    let err = request::<c_int>(Message::XattrsSet(
            path.as_os_str().as_bytes(),
            CStr::from_ptr(name).to_bytes(),
            slice::from_raw_parts(value as *const u8, size),
            flags));
    if err == 0 {
        Ok(0)
    } else {
        Err(err)
    }
}

unsafe fn getxattr_base(path: &Path, name: *const c_char, dest: *mut c_void, size: usize) -> Result<isize> {
    if !path.exists() {
        return Err(libc::ENOENT);
    }
    let res = request::<ReplyXattrsGet>(Message::XattrsGet(path.as_os_str().as_bytes(),
        CStr::from_ptr(name).to_bytes()));
    if let Some(value) = res.0 {
        if value.len() > (c_int::max_value() as usize) {
            return Err(libc::E2BIG);
        }
        if size == 0 {
            // TODO should this be a separate request not transfering the data just length?
            return Ok(value.len() as isize);
        }
        if value.len() > size {
            return Err(libc::ERANGE);
        }
        // TODO: deserialize directly into pointer to avoid copy
        // (custom deserialize impl? not sure that'd be possible)
        ptr::copy_nonoverlapping(value.as_ptr(), dest as *mut u8, value.len());
        Ok(value.len() as isize)
    } else {
        Err(libc::ENODATA)
    }
}

unsafe fn listxattr_base(path: &Path, dest: *mut c_char, size: usize) -> Result<isize> {
    if !path.exists() {
        return Err(libc::ENOENT);
    }
    let res = request::<ReplyXattrsList>(Message::XattrsList(path.as_os_str().as_bytes())).0;
    let total_size = res.len() + res.iter().map(|i| i.len()).sum::<usize>();
    if total_size > (c_int::max_value() as usize) {
        return Err(libc::E2BIG);
    }
    if size == 0 {
        // TODO should this be a separate request not transfering the data just length?
        return Ok(total_size as isize);
    }
    if total_size > size {
        return Err(libc::ERANGE);
    }
    let mut out = dest;
    for part in res {
        ptr::copy_nonoverlapping(part.as_ptr() as *const c_char, out, part.len());
        out = out.offset(part.len() as isize);
        *out = 0;
        out = out.offset(1);
    }
    Ok(total_size as isize)
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn setxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(&cpath(CStr::from_ptr(path), true)?, name, value, size, flags)
    }

    unsafe fn lsetxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(&cpath(CStr::from_ptr(path), false)?, name, value, size, flags)
    }

    unsafe fn fsetxattr:_(fd: c_int, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(get_fd_path!(fd)?, name, value, size, flags)
    }

    unsafe fn getxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(&cpath(CStr::from_ptr(path), true)?, name, dest, size)
    }

    unsafe fn lgetxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(&cpath(CStr::from_ptr(path), false)?, name, dest, size)
    }

    unsafe fn fgetxattr:_(fd: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(get_fd_path!(fd)?, name, dest, size)
    }

    unsafe fn listxattr:_(path: *const c_char, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), true)?, dest, size)
    }

    unsafe fn llistxattr:_(path: *const c_char, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), false)?, dest, size)
    }

    unsafe fn flistxattr:_(fd: c_int, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(get_fd_path!(fd)?, dest, size)
    }
}

#[cfg(target_os = "macos")]
wrap! {
    unsafe fn setxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, position: u32, flags: c_int) -> c_int {
        if position != 0 {
            return Err(libc::EINVAL);
        }
        setxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0)?, name, value, size, flags)
    }

    unsafe fn fsetxattr:_(fd: c_int, name: *const c_char, value: *const c_void, size: usize, position: u32, flags: c_int) -> c_int {
        if position != 0 {
            return Err(libc::EINVAL);
        }
        setxattr_base(get_fd_path!(fd)?, name, value, size, flags)
    }

    unsafe fn getxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize, position: u32, flags: c_int) -> isize {
        if position != 0 {
            return Err(libc::EINVAL);
        }
        getxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0)?, name, dest, size)
    }

    unsafe fn fgetxattr:_(fd: c_int, name: *const c_char, dest: *mut c_void, size: usize, position: u32, _: c_int) -> isize {
        if position != 0 {
            return Err(libc::EINVAL);
        }
        getxattr_base(get_fd_path!(fd)?, name, dest, size)
    }

    unsafe fn listxattr:_(path: *const c_char, dest: *mut c_char, size: usize, flags: c_int) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0)?, dest, size)
    }

    unsafe fn flistxattr:_(fd: c_int, dest: *mut c_char, size: usize, _: c_int) -> isize {
        listxattr_base(get_fd_path!(fd)?, dest, size)
    }
}
