use std::env;
use std::mem;
use std::os::raw::*;
use std::ffi::CStr;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::sync::Mutex;
use std::collections::{hash_map, HashMap};
use std::borrow::Borrow;
use std::hash::BuildHasherDefault;

use std::os::unix::net::UnixStream;

use libc::{self, mode_t, uid_t, gid_t, dev_t};
use serde::de::DeserializeOwned;
use bincode::{self, deserialize_from, serialize_into};
use twox_hash::XxHash;
use errno::errno;
use internal_stat::*;

#[allow(non_camel_case_types)]
#[cfg(any(not(target_os = "linux"), not(target_pointer_width = "64")))]
type ino_t = libc::ino_t;

#[allow(non_camel_case_types)]
#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
type ino_t = libc::ino64_t;

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsGet(pub Option<Vec<u8>>);

#[derive(Debug, Deserialize)]
pub struct ReplyXattrsList(pub Vec<Vec<u8>>);

#[derive(Debug, Deserialize)]
pub struct ReplyGetPermissions {
    pub mode_and_mask: Option<(mode_t, mode_t)>,
    pub owner: Option<uid_t>,
    pub group: Option<gid_t>,
    pub dev: Option<dev_t>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub enum NetworkLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Serialize)]
pub enum Message<'a> {
    Remove(u64),
    XattrsGet(u64, &'a [u8]),
    XattrsSet(u64, &'a [u8], &'a [u8], c_int),
    XattrsList(u64),
    OverrideMode(u64, mode_t, mode_t, Option<dev_t>),
    OverrideOwner(u64, Option<uid_t>, Option<gid_t>),
    GetPermissions(u64),
    Log(NetworkLogLevel, &'a str),
}

pub type Result<T> = ::std::result::Result<T, c_int>;

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

pub fn request<T: DeserializeOwned>(message: Message) -> T {
    let stream = &mut DAEMON_STREAM.lock().unwrap();
    {
        let writer = &mut stream.1;
        serialize_into(writer, message.borrow(), bincode::Infinite)
            .expect("Failed to send message to daemon");
        writer.flush().expect("IO Error flushing Unix socket");
    }
    let reader = &mut stream.0;
    deserialize_from(reader, bincode::Infinite)
        .expect("Failed to receive message from daemon")
}

macro_rules! error {
    ($( $x:tt )*) => {
        send(Message::Log(NetworkLogLevel::Error, format!($( $x )*).as_str()));
    }
}

macro_rules! warn {
    ($( $x:tt )*) => {
        send(Message::Log(NetworkLogLevel::Warn, format!($( $x )*).as_str()));
    }
}

macro_rules! info {
    ($( $x:tt )*) => {
        send(Message::Log(NetworkLogLevel::Info, format!($( $x )*).as_str()));
    }
}

macro_rules! debug {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            send(Message::Log(NetworkLogLevel::Error, format!($( $x )*).as_str()));
        }
    }
}

macro_rules! trace {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            send(Message::Log(NetworkLogLevel::Trace, format!($( $x )*).as_str()));
        }
    }
}

macro_rules! define_dlsym_fn {
    ($name:ident, _; $( $arg_t:ty ),*; $ret_t:ty) => {};

    ($name:ident, $orig_name:ident; $( $arg_t:ty ),*; $ret_t:ty) => {
        lazy_static! {
            static ref $orig_name: extern fn($( $arg_t ),*) -> $ret_t = unsafe {
                trace!("Finding original {}", stringify!($name));
                ::std::mem::transmute(::libc::dlsym(::libc::RTLD_NEXT, ::std::ffi::CString::new(stringify!($name)).unwrap().as_ptr()))
            };
        }
    };
}

macro_rules! __wrap_arg_string {
    ( _ ) => { ", _{}" };

    ( $arg_n: ident ) => {
        concat!(", ", stringify!($arg_n), ": {:?}")
    };
}

macro_rules! __wrap_maybe_ident {
    ( _ ) => { "" };

    ( $arg_n: ident ) => {
        $arg_n
    };
}

macro_rules! __wrap_fn {
    ( unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
            trace!(concat!(stringify!($name), $( __wrap_arg_string!($arg_n) ),*), $( __wrap_maybe_ident!($arg_n) ),*);
            define_dlsym_fn!($name, $orig_name; $( $arg_t ),*; $ret_t);

            let old_errno = ::errno::errno();
            match (move || -> Result<$ret_t> { $code })() {
                Ok(r) => {
                    if r == -1 {
                        trace!(concat!(stringify!($name), " -> Ok(-1) errno {:?}"), ::errno::errno());
                    } else {
                        trace!(concat!(stringify!($name), " -> Ok({})"), r);
                        ::errno::set_errno(old_errno);
                    }
                    r
                },
                Err(e) => {
                    if e == 0 {
                        trace!(concat!(stringify!($name), " -> Err(0) errno {}"), ::errno::errno().0);
                    } else {
                        trace!(concat!(stringify!($name), " -> Err({})"), e);
                        ::errno::set_errno(::errno::Errno(e));
                    }
                    -1
                }
            }
        }
    };

    ( !notrace unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
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
                    if e != 0 {
                        ::errno::set_errno(::errno::Errno(e));
                    }
                    -1
                }
            }
        }
    };
}

macro_rules! wrap {
    {
        $(
            $( ! $modifier:ident )* unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block
        )*
    } => {
        $(
            __wrap_fn!( $( ! $modifier )* unsafe fn $name : $orig_name( $( $arg_n : $arg_t ),*) -> $ret_t $code );
        )*
    };
}

lazy_static! {
    pub static ref FD_INOS: Mutex<HashMap<c_int, ino_t, BuildHasherDefault<XxHash>>> = Mutex::new(Default::default());
}

pub enum CPath {
    FileDescriptor(c_int),
    Path(*const c_char, bool),
    PathAt(c_int, *const c_char, c_int),
}

impl CPath {
    pub fn from_fd(fd: c_int) -> CPath {
        CPath::FileDescriptor(fd)
    }

    pub unsafe fn from_path(path: *const c_char, follow_symlinks: bool) -> CPath {
        CPath::Path(path, follow_symlinks)
    }

    pub unsafe fn from_path_at(dfd: c_int, path: *const c_char, flags: c_int) -> CPath {
        CPath::PathAt(dfd, path, flags)
    }

    pub fn get_stat(&self) -> Result<NativeStat> {
        unsafe {
            match *self {
                CPath::FileDescriptor(fd) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    if INTERNAL_FSTAT(fd, &mut statbuf as *mut _) == 0 {
                        trace!("get_stat fd {} -> ino {}", fd, statbuf.st_ino);
                        Ok(statbuf)
                    } else {
                        trace!("get_stat fd {} -> {}", fd, errno());
                        Err(0)
                    }
                }
                CPath::Path(path, follow_symlinks) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    let stat = if follow_symlinks { INTERNAL_STAT } else { INTERNAL_LSTAT };
                    if stat(path, &mut statbuf as *mut _) == 0 {
                        trace!("get_stat path {:?} -> ino {}", CStr::from_ptr(path), statbuf.st_ino);
                        Ok(statbuf)
                    } else {
                        trace!("get_stat path {:?} -> {}", CStr::from_ptr(path), errno());
                        Err(0)
                    }
                }
                CPath::PathAt(dfd, path, flags) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    if INTERNAL_FSTATAT(dfd, path, &mut statbuf as *mut _, flags) == 0 {
                        trace!("get_stat dfd {} path {:?} -> ino {}", dfd, CStr::from_ptr(path), statbuf.st_ino);
                        Ok(statbuf)
                    } else {
                        trace!("get_stat dfd {} path {:?} -> {}", dfd, CStr::from_ptr(path), errno());
                        Err(0)
                    }
                }
            }
        }
    }

    pub fn get_ino(&self) -> Result<ino_t> {
        match *self {
            CPath::FileDescriptor(fd) => {
                let fd_inos = &mut FD_INOS.lock().unwrap();
                match fd_inos.entry(fd) {
                    hash_map::Entry::Vacant(entry) => {
                        let ino = self.get_stat()?.st_ino;
                        entry.insert(ino);
                        Ok(ino)
                    }
                    hash_map::Entry::Occupied(entry) => {
                        let ino = entry.get().clone();
                        trace!("get_ino fd {} -> cached {}", fd, ino);
                        Ok(ino)
                    }
                }
            }
            _ => {
                self.get_stat().map(|stat| stat.st_ino)
            }
        }
    }
}
