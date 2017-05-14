use std::env;
use std::fs;
use std::path::Path;
use std::os::raw::*;
use std::ffi::{CStr, OsStr};
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::sync::{RwLock, Mutex};
use std::collections::HashMap;
use std::path::PathBuf;
use std::borrow::Borrow;

use std::os::unix::net::UnixStream;
use std::os::unix::ffi::OsStrExt;

use libc::{self, mode_t, uid_t, gid_t, dev_t};

use serde::de::DeserializeOwned;

use bincode::{self, deserialize_from, serialize_into};

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsGet(pub Option<Vec<u8>>);

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsList(pub Vec<Vec<u8>>);

#[derive(Debug, Deserialize)]
pub struct ReplyGetPermissions{
    pub mode_and_mask: Option<(mode_t, mode_t)>,
    pub owner: Option<uid_t>,
    pub group: Option<gid_t>,
    pub dev: Option<dev_t>,
}

#[derive(Debug, Serialize)]
pub enum Message<'a> {
    Remove(&'a [u8]),
    Rename(&'a [u8], &'a [u8]),
    XattrsGet(&'a [u8], &'a [u8]),
    XattrsSet(&'a [u8], &'a [u8], &'a [u8], c_int),
    XattrsList(&'a [u8]),
    OverrideMode(&'a [u8], mode_t, mode_t, Option<dev_t>),
    OverrideOwner(&'a [u8], Option<uid_t>, Option<gid_t>),
    GetPermissions(&'a [u8]),
    Link(&'a [u8], &'a [u8]),
}

pub type Result<T> = ::std::result::Result<T, c_int>;

macro_rules! define_dlsym_fn {
    ($name:ident, _; $( $arg_t:ty ),*; $ret_t:ty) => {};

    ($name:ident, $orig_name:ident; $( $arg_t:ty ),*; $ret_t:ty) => {
        lazy_static! {
            static ref $orig_name: extern fn($( $arg_t ),*) -> $ret_t = unsafe {
                ::std::mem::transmute(::libc::dlsym(::libc::RTLD_NEXT, ::std::ffi::CString::new(stringify!($name)).unwrap().as_ptr()))
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
            #[no_mangle]
            pub unsafe extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
                define_dlsym_fn!($name, $orig_name; $( $arg_t ),*; $ret_t);

                let old_errno = ::errno::errno();
                match (move || -> Result<$ret_t> { $code })() {
                    Ok(r) => {
                        if r != -1 {
                            ::errno::set_errno(old_errno);
                        }
                        r
                    },
                    Err(e) => {
                        ::errno::set_errno(::errno::Errno(e));
                        -1
                    }
                }
            }
        )*
    };
}

lazy_static! {
    static ref DAEMON_STREAM: Mutex<(BufReader<UnixStream>, BufWriter<UnixStream>)> = {
        let socket = UnixStream::connect(env::var("TEST_WRAPPER_SOCKET")
                .expect("libtestwrapper preloaded, but TEST_WRAPPER_SOCKET environment variable not passed"))
            .expect("Failed to connect to test-wrapper daemon");
        let reader = BufReader::new(socket.try_clone().expect("Failed to clone Unix socket"));
        Mutex::new((reader, BufWriter::new(socket)))
    };
}

pub fn send<'a, M: Borrow<Message<'a>>>(message: M) {
    let writer = &mut DAEMON_STREAM.lock().unwrap().1;
    serialize_into(writer, message.borrow(), bincode::Infinite)
        .expect("Failed to send message to daemon");
    writer.flush().expect("IO Error flushing Unix socket");
}

pub fn receive<T: DeserializeOwned>() -> T {
    let reader = &mut DAEMON_STREAM.lock().unwrap().0;
    deserialize_from(reader, bincode::Infinite)
        .expect("Failed to receive message from daemon")
}

pub fn request<T: DeserializeOwned>(message: Message) -> T {
    send(message);
    receive()
}

lazy_static! {
    pub static ref FD_PATHS: RwLock<HashMap<c_int, PathBuf>> = RwLock::new(HashMap::new());
}

macro_rules! get_fd_path {
    ($fd_paths:expr, $fd: expr) => {
        $fd_paths.get(&$fd).ok_or(libc::EBADF)
    };

    ($fd:expr) => {
        get_fd_path!(::shared::FD_PATHS.read().unwrap(), $fd)
    };
}

pub fn cpath_relative<P: AsRef<Path>>(root: P, path: &CStr, follow_symlinks: bool) -> Result<PathBuf> {
    let pathbuf;
    let mut path = OsStr::from_bytes(path.to_bytes());
    if follow_symlinks {
        if let Ok(lpath) = fs::read_link(path) {
            pathbuf = lpath;
            path = pathbuf.as_path().as_os_str();
        }
    }
    let path = root.as_ref().join(path);
    Ok(path)
}

pub fn cpath(path: &CStr, follow_symlinks: bool) -> Result<PathBuf> {
    cpath_relative(env::current_dir().unwrap_or_else(|_| "/".into()), path, follow_symlinks)
}

pub fn cpath_at(dfd: c_int, path: &CStr, follow_symlinks: bool) -> Result<PathBuf> {
    if dfd == libc::AT_FDCWD {
        cpath(path, follow_symlinks)
    } else {
        cpath_relative(get_fd_path!(dfd)?, path, follow_symlinks)
    }
}
