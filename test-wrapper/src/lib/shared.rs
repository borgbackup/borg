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
use std::cell::Cell;

use std::os::unix::net::UnixStream;

use libc::{self, mode_t, uid_t, gid_t, dev_t};
use serde::de::DeserializeOwned;
use bincode::{self, deserialize_from, serialize_into};
use fnv::FnvHashMap;

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

impl FileId {
    pub fn from_stat(stat: &StatBase) -> FileId {
        FileId(stat.get_dev(), stat.get_ino())
    }
}

#[derive(Debug, Serialize)]
#[allow(dead_code)] // not all variants are used on all platforms
pub enum Message<'a> {
    ReadyDeletion(FileId),
    Reference(FileId),
    DropReference(FileId),
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
    let reader = BufReader::new(socket.try_clone().expect("Failed to clone unix socket"));
    (reader, BufWriter::new(socket))
}

lazy_static! {
    pub static ref DAEMON_STREAM: Mutex<(BufReader<UnixStream>, BufWriter<UnixStream>)> = {
        unsafe {
           libc::pthread_atfork(None, None, Some(new_daemon_stream));
        }
        let old_reentrant = REENTRANT.with(|c| c.replace(true));
        let stream = create_daemon_stream();
        REENTRANT.with(|c| c.set(old_reentrant));
        Mutex::new(stream)
    };

    pub static ref FD_ID_CACHE: Mutex<FnvHashMap<c_int, FileId>> = Mutex::new(Default::default());

    pub static ref FILE_REF_COUNTS: Mutex<FnvHashMap<FileId, u32>> = Mutex::new(Default::default());
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

extern "C" fn new_daemon_stream() {
    let old_reentrant = REENTRANT.with(|c| c.replace(true));
    {
        let mut daemon_stream = DAEMON_STREAM.lock().unwrap();
        *daemon_stream = create_daemon_stream();
        let file_ref_counts = FILE_REF_COUNTS.lock().unwrap();
        for (&file, &count) in file_ref_counts.iter() {
            if count > 0 {
                bincode_result(serialize_into(&mut daemon_stream.1, &Message::Reference(file), bincode::Infinite));
                daemon_result(daemon_stream.1.flush());
                bincode_result(deserialize_from::<_, c_int, _>(&mut daemon_stream.0, bincode::Infinite));
            }
        }
    }
    REENTRANT.with(|c| c.set(old_reentrant));
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
    let res: c_int = request(message);
    match res {
        0 => Ok(()),
        e => Err(e),
    }
}

thread_local! {
    pub static REENTRANT: Cell<bool> = Cell::new(false);
}

// TODO pass on line numbers and file to daemon
// Maybe configure lib and daemon separately too

#[allow(unused_macros)]
macro_rules! error {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Error, format!($( $x )*).as_str()));
    }
}

#[allow(unused_macros)]
macro_rules! warn {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Warn, format!($( $x )*).as_str()));
    }
}

#[allow(unused_macros)]
macro_rules! info {
    ($( $x:tt )*) => {
        let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Info, format!($( $x )*).as_str()));
    }
}

#[allow(unused_macros)]
macro_rules! debug {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Debug, format!($( $x )*).as_str()));
        }
    }
}

#[allow(unused_macros)]
macro_rules! trace {
    ($( $x:tt )*) => {
        if cfg!(debug_assertions) {
            let _ = ::shared::message(::shared::Message::Log(::shared::NetworkLogLevel::Trace, format!($( $x )*).as_str()));
        }
    }
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

// TODO allow _ for argument
macro_rules! __wrap_fn {
    ( $( [ $attr:meta ] ),* ; unsafe fn $name:ident : $orig_name:ident ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        $( #[ $attr ] )*
        #[no_mangle]
        pub unsafe extern "C" fn $name($( $arg_n: $arg_t ),*) -> $ret_t {
            lazy_static! {
                static ref $orig_name: extern fn($( $arg_t ),*) -> $ret_t = unsafe {
                    ::std::mem::transmute(::libc::dlsym(::libc::RTLD_NEXT, ::std::ffi::CString::new(stringify!($name)).unwrap().as_ptr()))
                };
            }

            if REENTRANT.with(|c| c.replace(true)) {
                return $orig_name($( $arg_n ),*);
            }

            trace!(concat!(stringify!($name), $( __wrap_arg_string!($arg_n) ),*), $( __wrap_maybe_ident!($arg_n) ),*);
            let old_errno = ::errno::errno();

            let overrides = ::overrides::get_overrides();
            let mut fn_override = overrides.get(stringify!($name));
            let override_inv_prob = fn_override.map(|x| x.inverse_probability);
            if let Some(inv_prob) = override_inv_prob {
                if inv_prob > 1 {
                    let should_override = ::rand::Rng::gen_weighted_bool(&mut ::rand::thread_rng(), inv_prob);
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

            REENTRANT.with(|c| c.set(false));
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
}

macro_rules! __wrap_fn_ident {
    ( $( [ $attr:meta ] ),* ; $( ! $modifier:ident )* unsafe fn $name:ident : _ ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        __wrap_fn!( $( [ $attr ] ),* ; $( ! $modifier )* unsafe fn $name : ORIG_NAME( $( $arg_n : $arg_t ),*) -> $ret_t $code );
    };
    ( $( [ $attr:meta ] ),* ; $( ! $modifier:ident )* unsafe fn $name:ident : $orig_name:ident ($( $arg_n:tt : $arg_t:ty ),*) -> $ret_t:ty $code:block ) => {
        __wrap_fn!( $( [ $attr ] ),* ; $( ! $modifier )* unsafe fn $name : $orig_name( $( $arg_n : $arg_t ),*) -> $ret_t $code );
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
            __wrap_fn_ident!( $( [ $attr ] ),* ; $( ! $modifier )* unsafe fn $name : $orig_name( $( $arg_n : $arg_t ),*) -> $ret_t $code );
        )*
    };
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

    pub fn get_stat_notrace(&self) -> Result<NativeStat> {
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
            ret
        }
    }

    pub fn get_stat(&self) -> Result<NativeStat> {
        let ret = self.get_stat_notrace();
        trace!("get_stat {:?} -> {:?}", self, ret.map(|stat| (stat.st_dev, stat.st_ino)));
        ret
    }

    pub fn get_id(&self) -> Result<FileId> {
        match *self {
            CPath::FileDescriptor(fd) => {
                let fd_id_cache = &mut FD_ID_CACHE.lock().unwrap();
                match fd_id_cache.entry(fd) {
                    hash_map::Entry::Vacant(entry) => {
                        let stat = self.get_stat()?;
                        let id = FileId::from_stat(&stat);
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
                self.get_stat().map(|stat| FileId::from_stat(&stat))
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

pub fn dec_file_ref_count(id: FileId) -> Result<()> {
    let mut file_ref_counts = FILE_REF_COUNTS.lock().unwrap();
    if let Some(count) = file_ref_counts.get_mut(&id) {
        if *count != 0 {
            *count -= 1;
            if *count == 0 {
                return message(Message::DropReference(id));
            }
            return Ok(());
        }
    }
    warn!("Tried to drop ref to file with no references");
    Ok(())
}

pub fn inc_file_ref_count(id: FileId) -> Result<()> {
    let mut file_ref_counts = FILE_REF_COUNTS.lock().unwrap();
    let is_new = match file_ref_counts.entry(id) {
        hash_map::Entry::Vacant(entry) => {
            entry.insert(1);
            true
        }
        hash_map::Entry::Occupied(mut entry) => {
            let entry = entry.get_mut();
            *entry += 1;
            *entry == 1
        }
    };
    if is_new {
        message(Message::Reference(id))
    } else {
        Ok(())
    }
}
