use std::slice;
use std::ptr;
use std::ffi::CStr;
use std::os::raw::*;

use libc;

use shared::*;

extern crate byteorder;
use self::byteorder::{ReadBytesExt, WriteBytesExt, NativeEndian};

// Assumes c_int == i32
// If that isn't true, a compiler error will occur
unsafe fn get_full_name(namespace: c_int, name: *const c_char) -> Vec<u8> {
    let name = CStr::from_ptr(name);
    let name = name.to_bytes();
    let mut output_buf = Vec::with_capacity(4 + name.len());
    let _ = output_buf.write_i32::<NativeEndian>(namespace);
    output_buf.extend(name);
    output_buf
}

unsafe fn base_get(path: CPath, namespace: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> Result<isize> {
    let full_name = get_full_name(namespace, name);
    let res = request::<ReplyXattrsGet>(Message::XattrsGet(path.get_id()?,
        full_name.as_slice()));
    if let Some(value) = res.0 {
        if value.len() > (isize::max_value() as usize) {
            return Err(libc::E2BIG);
        }
        if size == 0 {
            return Ok(value.len() as isize);
        }
        if value.len() > size {
            return Err(libc::ERANGE);
        }
        ptr::copy_nonoverlapping(value.as_ptr(), dest as *mut u8, value.len());
        Ok(value.len() as isize)
    } else {
        Err(libc::ENOATTR)
    }
}

unsafe fn base_set(path: CPath, namespace: c_int, name: *const c_char, data: *const c_void, size: usize) -> Result<isize> {
    let full_name = get_full_name(namespace, name);
    let err = request::<c_int>(Message::XattrsSet(
            path.get_id()?,
            full_name.as_slice(),
            slice::from_raw_parts(data as *const u8, size),
            0));
    if err == 0 {
        Ok(0)
    } else {
        Err(err)
    }
}

unsafe fn base_delete(path: CPath, namespace: c_int, name: *const c_char) -> Result<c_int> {
    let full_name = get_full_name(namespace, name);
    let err = request::<c_int>(Message::XattrsDelete(
            path.get_id()?,
            full_name.as_slice()));
    if err == 0 {
        Ok(0)
    } else {
        Err(err)
    }
}

unsafe fn base_list(path: CPath, namespace: c_int, dest: *mut c_void, size: usize) -> Result<isize> {
    let res = request::<ReplyXattrsList>(Message::XattrsList(path.get_id()?)).0;
    let res = res.into_iter()
        .filter(|x| (&x[..4]).read_i32::<NativeEndian>().unwrap() == namespace)
        .collect::<Vec<_>>();
    let res = res.iter()
        .map(|x| {
            &x[4..]
        })
        .collect::<Vec<_>>();
    let total_size = res.iter().map(|x| 1 + x.len()).sum::<usize>();
    if total_size > (isize::max_value() as usize) || res.iter().any(|x| x.len() > u8::max_value().into()) {
        return Err(libc::E2BIG);
    }
    if size == 0 {
        return Ok(total_size as isize);
    }
    if total_size > size {
        return Err(libc::ERANGE);
    }
    let mut out = dest as *mut u8;
    for part in res {
        *out = part.len() as u8;
        out = out.offset(1);
        ptr::copy_nonoverlapping(part.as_ptr(), out, part.len());
        out = out.offset(part.len() as isize);
    }
    Ok(total_size as isize)
}

wrap! {
    unsafe fn extattr_get_fd:_(fd: c_int, namespace: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        base_get(CPath::from_fd(fd), namespace, name, dest, size)
    }

    unsafe fn extattr_set_fd:_(fd: c_int, namespace: c_int, name: *const c_char, data: *const c_void, size: usize) -> isize {
        base_set(CPath::from_fd(fd), namespace, name, data, size)
    }

    unsafe fn extattr_delete_fd:_(fd: c_int, namespace: c_int, name: *const c_char) -> c_int {
        base_delete(CPath::from_fd(fd), namespace, name)
    }

    unsafe fn extattr_list_fd:_(fd: c_int, namespace: c_int, dest: *mut c_void, size: usize) -> isize {
        base_list(CPath::from_fd(fd), namespace, dest, size)
    }

    unsafe fn extattr_get_file:_(path: *const c_char, namespace: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        base_get(CPath::from_path(path, true), namespace, name, dest, size)
    }

    unsafe fn extattr_set_file:_(path: *const c_char, namespace: c_int, name: *const c_char, data: *const c_void, size: usize) -> isize {
        base_set(CPath::from_path(path, true), namespace, name, data, size)
    }

    unsafe fn extattr_delete_file:_(path: *const c_char, namespace: c_int, name: *const c_char) -> c_int {
        base_delete(CPath::from_path(path, true), namespace, name)
    }

    unsafe fn extattr_list_file:_(path: *const c_char, namespace: c_int, dest: *mut c_void, size: usize) -> isize {
        base_list(CPath::from_path(path, true), namespace, dest, size)
    }

    unsafe fn extattr_get_link:_(path: *const c_char, namespace: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        base_get(CPath::from_path(path, false), namespace, name, dest, size)
    }

    unsafe fn extattr_set_link:_(path: *const c_char, namespace: c_int, name: *const c_char, data: *const c_void, size: usize) -> isize {
        base_set(CPath::from_path(path, false), namespace, name, data, size)
    }

    unsafe fn extattr_delete_link:_(path: *const c_char, namespace: c_int, name: *const c_char) -> c_int {
        base_delete(CPath::from_path(path, false), namespace, name)
    }

    unsafe fn extattr_list_link:_(path: *const c_char, namespace: c_int, dest: *mut c_void, size: usize) -> isize {
        base_list(CPath::from_path(path, false), namespace, dest, size)
    }
}
