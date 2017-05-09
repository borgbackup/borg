/// Contains the library which gets LD_PRELOADed. Wrapper functions use a custom macro which
/// automatically loads the original function with the right signature. Communicates with the
/// daemon through a Unix socket specified in the environment variable TEST_WRAPPER_SOCKET.

use std::env;
use std::mem;
use std::fs;
use std::slice;
use std::ptr;
use std::ops::DerefMut;
use std::path::Path;
use std::os::raw::*;
use std::ffi::{CStr, CString, OsStr};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::sync::RwLock;
use std::cell::RefCell;
use std::collections::HashMap;

use std::os::unix::net::UnixStream;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[macro_use]
extern crate lazy_static;

extern crate libc;
use libc::{dlsym, mode_t};

extern crate serde;
use serde::de::DeserializeOwned;

#[macro_use]
extern crate serde_derive;
extern crate bincode;
use bincode::{deserialize_from, serialize_into};

extern crate errno;
use errno::{Errno, set_errno};

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsGet(Option<Vec<u8>>);

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsList(Vec<Vec<u8>>);

#[derive(Debug, Serialize)]
pub enum Message<'a> {
    Remove(&'a [u8]),
    Rename(&'a [u8], &'a [u8]),
    XattrsGet(&'a [u8], &'a [u8]),
    XattrsSet(&'a [u8], &'a [u8], &'a [u8], c_int),
    XattrsList(&'a [u8]),
    XattrsReset(&'a [u8]),
}

macro_rules! define_dlsym_fn {
    ($name:ident, _; $( $arg_t:ty ),*; $ret_t:ty) => {};

    ($name:ident, $orig_name:ident; $( $arg_t:ty ),*; $ret_t:ty) => {
        lazy_static! {
            static ref $orig_name: extern fn($( $arg_t ),*) -> $ret_t = unsafe {
                mem::transmute(dlsym(libc::RTLD_NEXT, CString::new(stringify!($name)).unwrap().as_ptr()))
            };
        }
    };
}

macro_rules! wrap {
    {
        $(
            unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block
        )*
    } => {
        $(
            define_dlsym_fn!($name, $orig_name; $( $arg_t ),*; $ret_t);

            #[no_mangle]
            pub unsafe extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
                $code
            }
        )*
    };
}

thread_local! {
    static DAEMON_STREAM: (RefCell<BufReader<UnixStream>>, RefCell<BufWriter<UnixStream>>) = {
        let socket = UnixStream::connect(env::var("TEST_WRAPPER_SOCKET")
                .expect("libtestwrapper preloaded, but TEST_WRAPPER_SOCKET environment variable not passed"))
            .expect("Failed to connect to test-wrapper daemon");
        let reader = BufReader::new(socket.try_clone().expect("Failed to clone Unix socket"));
        (RefCell::new(reader), RefCell::new(BufWriter::new(socket)))
    };
}

fn send(message: Message) {
    DAEMON_STREAM.with(|&(_, ref writer)| {
        let mut writer = writer.borrow_mut();
        serialize_into(writer.deref_mut(), &message, bincode::Infinite)
            .expect("Failed to send message to daemon");
        writer.flush().expect("IO Error flushing Unix socket");
    });
}

fn receive<T: DeserializeOwned>() -> T {
    DAEMON_STREAM.with(|&(ref reader, _)| {
        deserialize_from(reader.borrow_mut().deref_mut(), bincode::Infinite)
            .expect("Failed to receive message from daemon")
    })
}

fn request<T: DeserializeOwned>(message: Message) -> T {
    send(message);
    receive()
}

lazy_static! {
    static ref FD_PATHS: RwLock<HashMap<c_int, Vec<u8>>> = RwLock::new(HashMap::new());
}

macro_rules! get_fd_path {
    ($fd:expr) => {
        if let Some(path) = FD_PATHS.read().unwrap().get(&$fd) {
            path
        } else {
            set_errno(Errno(libc::EBADF));
            return -1;
        }
    }
}

fn cpath_relative<P: AsRef<Path>>(root: P, path: &CStr, follow_symlinks: bool) -> Vec<u8> {
    let pathbuf;
    let mut path = OsStr::from_bytes(path.to_bytes());
    if follow_symlinks {
        if let Ok(lpath) = fs::read_link(path) {
            pathbuf = lpath;
            path = pathbuf.as_path().as_os_str();
        }
    }
    root.as_ref().join(path).into_os_string().into_vec()
}

fn cpath(path: &CStr, follow_symlinks: bool) -> Vec<u8> {
    cpath_relative(env::current_dir().unwrap_or_else(|_| "/".into()), path, follow_symlinks)
}

fn cpath_at(dfd: c_int, path: &CStr, follow_symlinks: bool) -> Vec<u8> {
    let tmp;
    let root = if dfd == libc::AT_FDCWD {
        None
    } else {
        tmp = FD_PATHS.read().unwrap();
        tmp.get(&dfd)
    };
    if let Some(root) = root {
        cpath_relative(OsStr::from_bytes(root), path, follow_symlinks)
    } else {
        cpath(path, follow_symlinks)
    }
}

unsafe fn setxattr_base(path: &Vec<u8>, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
    let err = request::<c_int>(Message::XattrsSet(
            path.as_slice(),
            CStr::from_ptr(name).to_bytes(),
            slice::from_raw_parts(value as *const u8, size),
            flags));
    if err == 0 {
        0
    } else {
        set_errno(Errno(err));
        -1
    }
}

unsafe fn getxattr_base(path: &Vec<u8>, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
    let res = request::<ReplyXattrsGet>(Message::XattrsGet(path.as_slice(), CStr::from_ptr(name).to_bytes()));
    if let Some(value) = res.0 {
        if value.len() > (c_int::max_value() as usize) {
            set_errno(Errno(libc::E2BIG));
            return -1;
        }
        if size == 0 {
            // TODO should this be a separate request not transfering the data just length?
            return value.len() as isize;
        }
        if value.len() > size {
            set_errno(Errno(libc::ERANGE));
            return -1;
        }
        // TODO: deserialize directly into pointer to avoid copy
        // (custom deserialize impl? not sure that'd be possible)
        ptr::copy_nonoverlapping(value.as_ptr(), dest as *mut u8, value.len());
        value.len() as isize
    } else {
        set_errno(Errno(libc::ENODATA));
        -1
    }
}

unsafe fn listxattr_base(path: &Vec<u8>, dest: *mut c_char, size: usize) -> isize {
    let res = request::<ReplyXattrsList>(Message::XattrsList(path.as_slice())).0;
    let total_size = res.len() + res.iter().map(|i| i.len()).sum::<usize>();
    if total_size > (c_int::max_value() as usize) {
        set_errno(Errno(libc::E2BIG));
        return -1;
    }
    if size == 0 {
        // TODO should this be a separate request not transfering the data just length?
        return total_size as isize;
    }
    if total_size > size {
        set_errno(Errno(libc::ERANGE));
        return -1;
    }
    let mut out = dest;
    for part in res {
        ptr::copy_nonoverlapping(part.as_ptr() as *const c_char, out, part.len());
        out = out.offset(part.len() as isize);
        *out = 0;
        out = out.offset(1);
    }
    total_size as isize
}

wrap! {
    unsafe fn open:ORIG_OPEN(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPEN(path, flags, mode);
        if ret > 0 {
            FD_PATHS.write().unwrap().insert(ret, cpath(CStr::from_ptr(path), true));
        }
        ret
    }

    unsafe fn creat:ORIG_CREAT(path: *const c_char, mode: mode_t) -> c_int {
        let ret = ORIG_CREAT(path, mode);
        if ret > 0 {
            FD_PATHS.write().unwrap().insert(ret, cpath(CStr::from_ptr(path), false));
        }
        ret
    }

    unsafe fn openat:ORIG_OPENAT(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPENAT(dfd, path, flags, mode);
        if ret > 0 {
            let path = cpath_at(dfd, CStr::from_ptr(path), true); // avoids FD_PATHS deadlock
            FD_PATHS.write().unwrap().insert(ret, path);
        }
        ret
    }

    unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        let ret = ORIG_CLOSE(fd);
        if ret == 0 {
            FD_PATHS.write().unwrap().remove(&fd);
        }
        ret
    }

    unsafe fn chmod:ORIG_CHMOD(path: *const c_char, mode: mode_t) -> c_int {
        let ret = ORIG_CHMOD(path, mode);
        if ret == 0 {
            send(Message::XattrsReset(CStr::from_ptr(path).to_bytes()));
        }
        ret
    }

    unsafe fn fchmod:ORIG_FCHMOD(fd: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_FCHMOD(fd, mode);
        if ret == 0 {
            if let Some(path) = FD_PATHS.read().unwrap().get(&fd) {
                send(Message::XattrsReset(path));
            }
        }
        ret
    }

    unsafe fn fchmodat:ORIG_FCHMODAT(dfd: c_int, path: *const c_char, mode: mode_t, flags: c_int) -> c_int {
        let ret = ORIG_FCHMODAT(dfd, path, mode, flags);
        if ret == 0 {
            send(Message::XattrsReset(cpath_at(dfd, CStr::from_ptr(path), true).as_slice()));
        }
        ret
    }

    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        let ret = ORIG_UNLINK(path);
        if ret == 0 {
            send(Message::Remove(cpath(CStr::from_ptr(path), false).as_slice()));
        }
        ret
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let ret = ORIG_UNLINKAT(dfd, path, flags);
        if ret == 0 {
            send(Message::Remove(cpath_at(dfd, CStr::from_ptr(path), false).as_slice()));
        }
        ret
    }

    unsafe fn rename:ORIG_RENAME(oldpath: *const c_char, newpath: *const c_char) -> c_int {
        let ret = ORIG_RENAME(oldpath, newpath);
        if ret == 0 {
            send(Message::Rename(cpath(CStr::from_ptr(oldpath), false).as_slice(), cpath(CStr::from_ptr(newpath), false).as_slice()));
        }
        ret
    }

    unsafe fn renameat:ORIG_RENAMEAT(olddfd: c_int, oldpath: *const c_char, newdfd: c_int, newpath: *const c_char) -> c_int {
        let ret = ORIG_RENAMEAT(olddfd, oldpath, newdfd, newpath);
        if ret == 0 {
            send(Message::Rename(cpath_at(olddfd, CStr::from_ptr(oldpath), false).as_slice(), cpath_at(newdfd, CStr::from_ptr(newpath), false).as_slice()));
        }
        ret
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn open64:ORIG_OPEN64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPEN64(path, flags, mode);
        if ret > 0 {
            FD_PATHS.write().unwrap().insert(ret, cpath(CStr::from_ptr(path), true));
        }
        ret
    }

    unsafe fn creat64:ORIG_CREAT64(path: *const c_char, mode: mode_t) -> c_int {
        let ret = ORIG_CREAT64(path, mode);
        if ret > 0 {
            FD_PATHS.write().unwrap().insert(ret, cpath(CStr::from_ptr(path), false));
        }
        ret
    }

    unsafe fn openat64:ORIG_OPENAT64(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let ret = ORIG_OPENAT64(dfd, path, flags, mode);
        if ret > 0 {
            let path = cpath_at(dfd, CStr::from_ptr(path), true); // avoids FD_PATHS deadlock
            FD_PATHS.write().unwrap().insert(ret, path);
        }
        ret
    }

    unsafe fn setxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(&cpath(CStr::from_ptr(path), true), name, value, size, flags)
    }

    unsafe fn lsetxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(&cpath(CStr::from_ptr(path), false), name, value, size, flags)
    }

    unsafe fn fsetxattr:_(fd: c_int, name: *const c_char, value: *const c_void, size: usize, flags: c_int) -> c_int {
        setxattr_base(get_fd_path!(fd), name, value, size, flags)
    }

    unsafe fn getxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(&cpath(CStr::from_ptr(path), true), name, dest, size)
    }

    unsafe fn lgetxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(&cpath(CStr::from_ptr(path), false), name, dest, size)
    }

    unsafe fn fgetxattr:_(fd: c_int, name: *const c_char, dest: *mut c_void, size: usize) -> isize {
        getxattr_base(get_fd_path!(fd), name, dest, size)
    }

    unsafe fn listxattr:_(path: *const c_char, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), true), dest, size)
    }

    unsafe fn llistxattr:_(path: *const c_char, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), false), dest, size)
    }

    unsafe fn flistxattr:_(fd: c_int, dest: *mut c_char, size: usize) -> isize {
        listxattr_base(get_fd_path!(fd), dest, size)
    }
}

#[cfg(target_os = "macos")]
wrap! {
    unsafe fn setxattr:_(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, position: u32, flags: c_int) -> i32 {
        if position != 0 {
            set_errno(Errno(libc::EINVAL));
            return -1;
        }
        setxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0), name, value, size, flags)
    }

    unsafe fn fsetxattr:_(fd: c_int, name: *const c_char, value: *const c_void, size: usize, position: u32, flags: c_int) -> i32 {
        if position != 0 {
            set_errno(Errno(libc::EINVAL));
            return -1;
        }
        setxattr_base(get_fd_path!(fd), name, value, size, flags)
    }

    unsafe fn getxattr:_(path: *const c_char, name: *const c_char, dest: *mut c_void, size: usize, position: u32, flags: c_int) -> isize {
        if position != 0 {
            set_errno(Errno(libc::EINVAL));
            return -1;
        }
        getxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0), name, dest, size)
    }

    unsafe fn fgetxattr:_(fd: c_int, name: *const c_char, dest: *mut c_void, size: usize, position: u32, _: c_int) -> isize {
        if position != 0 {
            set_errno(Errno(libc::EINVAL));
            return -1;
        }
        getxattr_base(get_fd_path!(fd), name, dest, size)
    }

    unsafe fn listxattr:_(path: *const c_char, dest: *mut c_char, size: usize, flags: c_int) -> isize {
        listxattr_base(&cpath(CStr::from_ptr(path), (flags & libc::XATTR_NOFOLLOW) == 0), dest, size)
    }

    unsafe fn flistxattr:_(fd: c_int, dest: *mut c_char, size: usize, _: c_int) -> isize {
        listxattr_base(get_fd_path!(fd), dest, size)
    }
}
