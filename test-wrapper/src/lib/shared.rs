use std::env;
use std::mem;
use std::process;
use std::result;
use std::os::raw::*;
use std::ffi::CStr;
use std::io::prelude::*;
use std::io::{self, BufReader, BufWriter};
use std::sync::Mutex;
use std::collections::hash_map;
use std::borrow::Borrow;
use std::fmt::{self, Debug};
use std::ops::Deref;
use std::cell::RefCell;

use std::os::unix::net::UnixStream;

use libc::{self, mode_t, uid_t, gid_t, dev_t};
use serde::de::DeserializeOwned;
use bincode::{self, deserialize_from, serialize_into};
use fnv::FnvHashMap;
use rand;

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
    pub rdev: Option<dev_t>,
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

#[derive(Debug, Serialize, Hash, PartialEq, Eq, Clone, Copy)]
pub struct FileId(dev_t, ino_t);

impl From<libc::stat> for FileId {
    fn from(stat: libc::stat) -> FileId {
        FileId(stat.st_dev, stat.st_ino)
    }
}

impl<'a> From<&'a libc::stat> for FileId {
    fn from(stat: &'a libc::stat) -> FileId {
        FileId(stat.st_dev, stat.st_ino)
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl From<libc::stat64> for FileId {
    fn from(stat: libc::stat64) -> FileId {
        FileId(stat.st_dev, stat.st_ino)
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl<'a> From<&'a libc::stat64> for FileId {
    fn from(stat: &'a libc::stat64) -> FileId {
        FileId(stat.st_dev, stat.st_ino)
    }
}

#[derive(Debug, Serialize)]
#[allow(dead_code)] // not all variants are used on all platforms
pub enum Message<'a> {
    BeginRemove(FileId),
    FinishRemove(FileId, bool),
    XattrsGet(FileId, &'a [u8]),
    XattrsSet(FileId, &'a [u8], &'a [u8], c_int),
    XattrsDelete(FileId, &'a [u8]),
    XattrsList(FileId),
    OverrideMode(FileId, mode_t, mode_t, Option<dev_t>),
    OverrideOwner(FileId, Option<uid_t>, Option<gid_t>),
    GetPermissions(FileId),
    Log(NetworkLogLevel, &'a str),
}

pub type Result<T> = ::std::result::Result<T, c_int>;

fn create_daemon_stream() -> (BufReader<UnixStream>, BufWriter<UnixStream>) {
    let socket = UnixStream::connect(env::var("TEST_WRAPPER_SOCKET")
            .expect("libtestwrapper preloaded, but TEST_WRAPPER_SOCKET environment variable not passed"))
        .expect("Failed to connect to test-wrapper daemon");
    let reader = BufReader::new(socket.try_clone().expect("Failed to clone Unix socket"));
    (reader, BufWriter::new(socket))
}

lazy_static! {
    static ref DAEMON_STREAM: Mutex<(BufReader<UnixStream>, BufWriter<UnixStream>)> = {
        unsafe {
           libc::pthread_atfork(None, None, Some(new_daemon_stream));
        }
        Mutex::new(create_daemon_stream())
    };
}

extern "C" fn new_daemon_stream() {
    *DAEMON_STREAM.lock().unwrap() = create_daemon_stream();
}

pub fn daemon_error(err: &io::Error) -> ! {
    let kind = err.kind();
    if kind == io::ErrorKind::ConnectionReset || kind == io::ErrorKind::BrokenPipe {
        if cfg!(debug_assertions) {
            let _ = writeln!(io::stderr(), "Daemon process exited, exiting");
        }
        process::exit(0)
    } else {
        panic!("Error messaging daemon: {:?}", err)
    }
}

pub fn daemon_result<T>(result: result::Result<T, io::Error>) -> T {
    match result {
        Ok(x) => x,
        Err(e) => daemon_error(&e),
    }
}

pub fn bincode_result<T>(result: result::Result<T, Box<bincode::ErrorKind>>) -> T {
    match result {
        Ok(x) => x,
        Err(err) => {
            if let &bincode::ErrorKind::IoError(ref err) = err.deref() {
                daemon_error(&err);
            } else {
                panic!("Error messaging daemon: {:?}", err);
            }
        }
    }
}

pub fn request<T: DeserializeOwned>(message: Message) -> T {
    let stream = &mut DAEMON_STREAM.lock().unwrap();
    {
        let writer = &mut stream.1;
        bincode_result(serialize_into(writer, message.borrow(), bincode::Infinite));
        daemon_result(writer.flush());
    }
    let reader = &mut stream.0;
    bincode_result(deserialize_from(reader, bincode::Infinite))
}

// The reply is important, as it ensures the operation is finished serverside
pub fn message(message: Message) -> Result<()> {
    match request(message) {
        0 => Ok(()),
        e => Err(e),
    }
}

// TODO pass on line numbers and file to daemon
// Maybe configure lib and daemon separately too

macro_rules! error {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Error, format!($( $x )*).as_str()));
    }
}

macro_rules! warn {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Warn, format!($( $x )*).as_str()));
    }
}

macro_rules! info {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Info, format!($( $x )*).as_str()));
    }
}

macro_rules! debug {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Debug, format!($( $x )*).as_str()));
        }
    }
}

macro_rules! trace {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Trace, format!($( $x )*).as_str()));
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

thread_local! {
    pub static THREAD_WEAK_RNG: RefCell<rand::XorShiftRng> = RefCell::new(rand::weak_rng());
}

macro_rules! __wrap_fn {
    ( $( [ $attr:meta ] ),* ; unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        $( #[ $attr ] )*
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
            trace!(concat!(stringify!($name), $( __wrap_arg_string!($arg_n) ),*), $( __wrap_maybe_ident!($arg_n) ),*);
            define_dlsym_fn!($name, $orig_name; $( $arg_t ),*; $ret_t);
            let old_errno = ::errno::errno();

            let overrides = ::overrides::get_overrides();
            let mut fn_override = overrides.get(stringify!($name));
            let override_inv_prob = fn_override.map(|x| x.inverse_probability);
            if let Some(inv_prob) = override_inv_prob {
                if inv_prob > 1 {
                    let should_override = ::shared::THREAD_WEAK_RNG.with(|rng| {
                        ::rand::Rng::gen_weighted_bool(&mut *rng.borrow_mut(), inv_prob)
                    });
                    if !should_override {
                        fn_override = None;
                    }
                }
            }
            let side_effect = fn_override.map(|x| x.side_effect).unwrap_or(true);

            let return_value = if side_effect {
                match (move || -> Result<$ret_t> { $code })() {
                    Ok(r) => {
                        if r == -1 {
                            debug!(concat!(stringify!($name), " -> Ok(-1) {:?}"), ::errno::errno());
                        } else {
                            trace!(concat!(stringify!($name), " -> Ok({})"), r);
                            ::errno::set_errno(old_errno);
                        }
                        r
                    },
                    Err(e) => {
                        if e == 0 {
                            debug!(concat!(stringify!($name), " -> Err(0) {:?}"), ::errno::errno());
                        } else {
                            debug!(concat!(stringify!($name), " -> Err({})"), e);
                            ::errno::set_errno(::errno::Errno(e));
                        }
                        -1
                    }
                }
            } else {
                0
            };

            if let Some(fn_override) = fn_override {
                if let Some(errno) = fn_override.set_errno {
                    ::errno::set_errno(::errno::Errno(errno));
                }
                if let Some(ret) = fn_override.return_value {
                    ret as _
                } else {
                    return_value
                }
            } else {
                return_value
            }
        }
    };

    ( $( [ $attr:meta ] ),* ; !notrace unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        $( #[ $attr ] )*
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
            $( #[ $attr:meta ] )*
            $( ! $modifier:ident )* unsafe fn $name:ident : $orig_name:tt ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block
        )*
    } => {
        $(
            __wrap_fn!( $( [ $attr ] ),* ; $( ! $modifier )* unsafe fn $name : $orig_name( $( $arg_n : $arg_t ),*) -> $ret_t $code );
        )*
    };
}

lazy_static! {
    pub static ref FD_ID_CACHE: Mutex<FnvHashMap<c_int, FileId>> = Mutex::new(Default::default());
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
            let ret = match *self {
                CPath::FileDescriptor(fd) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    if INTERNAL_FSTAT(fd, &mut statbuf as *mut _) == 0 {
                        Ok(statbuf)
                    } else {
                        Err(0)
                    }
                }
                CPath::Path(path, follow_symlinks) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    let ret = if follow_symlinks {
                        INTERNAL_STAT(path, &mut statbuf as *mut _)
                    } else {
                        INTERNAL_LSTAT(path, &mut statbuf as *mut _)
                    };
                    if ret == 0 {
                        Ok(statbuf)
                    } else {
                        Err(0)
                    }
                }
                CPath::PathAt(dfd, path, flags) => {
                    let mut statbuf: NativeStat = mem::uninitialized();
                    if INTERNAL_FSTATAT(dfd, path, &mut statbuf as *mut _, flags) == 0 {
                        Ok(statbuf)
                    } else {
                        Err(0)
                    }
                }
            };
            trace!("get_stat {:?} -> {:?}", self, ret.map(|stat| (stat.st_dev, stat.st_ino)));
            ret
        }
    }

    pub fn get_id(&self) -> Result<FileId> {
        match *self {
            CPath::FileDescriptor(fd) => {
                let fd_id_cache = &mut FD_ID_CACHE.lock().unwrap();
                match fd_id_cache.entry(fd) {
                    hash_map::Entry::Vacant(entry) => {
                        let stat = self.get_stat()?;
                        let id: FileId = stat.into();
                        entry.insert(id);
                        Ok(id)
                    }
                    hash_map::Entry::Occupied(entry) => {
                        let id = entry.get();
                        trace!("get_id FD {} -> cached {:?}", fd, id);
                        Ok(id.clone())
                    }
                }
            }
            _ => {
                self.get_stat().map(|stat| FileId(stat.st_dev, stat.st_ino))
            }
        }
    }
}

impl Debug for CPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CPath::FileDescriptor(fd) => write!(f, "FD {}", fd),
            CPath::Path(path, follow_symlinks) => unsafe {
                write!(f, "{:?} (follow_symlinks: {})", CStr::from_ptr(path), follow_symlinks)
            },
            CPath::PathAt(dfd, path, flags) => unsafe {
                write!(f, "DFD {} + {:?} (flags: 0x{:x})", dfd, CStr::from_ptr(path), flags)
            },
        }
    }
}
