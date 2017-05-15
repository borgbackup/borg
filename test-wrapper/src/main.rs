/// Wraps various libc functions for Borg's tests.
/// Currently overrides permissions/modes and xattrs. Previously fakeroot was used, but it caused
/// other problems.
///
/// This file contains the binary, which functions as both a daemon and a launcher for whatever's
/// being run through this wrapper.

use std::env;
use std::fs;
use std::thread;
use std::borrow::Borrow;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use std::process::{self, Command};
use std::ffi::OsStr;
use std::os::raw::*;
use std::path::PathBuf;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, ErrorKind};
use std::collections::hash_map;
use std::hash::BuildHasherDefault;

use std::os::unix::net::{UnixListener, UnixStream};

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate rand;
use rand::{Rng, thread_rng};

extern crate serde;
use serde::ser::Serialize;

extern crate libc;
use libc::{mode_t, uid_t, gid_t, dev_t};

extern crate twox_hash;
use twox_hash::XxHash;

#[macro_use]
extern crate serde_derive;
extern crate bincode;
use bincode::{deserialize_from, serialize_into};

#[derive(Debug, Serialize)]
pub struct ReplyXattrsGet<'a>(Option<&'a [u8]>);

#[derive(Debug, Serialize)]
pub struct ReplyXattrsList<'a>(&'a [&'a Vec<u8>]);

#[derive(Debug, Serialize)]
pub struct ReplyGetPermissions {
    mode_and_mask: Option<(mode_t, mode_t)>,
    owner: Option<uid_t>,
    group: Option<gid_t>,
    dev: Option<dev_t>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub enum NetworkLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Into<log::LogLevel> for NetworkLogLevel {
    fn into(self) -> log::LogLevel {
        match self {
            NetworkLogLevel::Error => log::LogLevel::Error,
            NetworkLogLevel::Warn => log::LogLevel::Warn,
            NetworkLogLevel::Info => log::LogLevel::Info,
            NetworkLogLevel::Debug => log::LogLevel::Debug,
            NetworkLogLevel::Trace => log::LogLevel::Trace,
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum Message {
    Remove(Vec<u8>),
    Rename(Vec<u8>, Vec<u8>),
    XattrsGet(Vec<u8>, Vec<u8>),
    XattrsSet(Vec<u8>, Vec<u8>, Vec<u8>, c_int),
    XattrsList(Vec<u8>),
    OverrideMode(Vec<u8>, mode_t, mode_t, Option<dev_t>),
    OverrideOwner(Vec<u8>, Option<uid_t>, Option<gid_t>),
    GetPermissions(Vec<u8>),
    Link(Vec<u8>, Vec<u8>),
    Log(NetworkLogLevel, String),
}

#[derive(Default)]
struct FileEntry {
    xattrs: HashMap<Vec<u8>, Vec<u8>, BuildHasherDefault<XxHash>>,
    mode_and_mask: Option<(mode_t, mode_t)>,
    owner: Option<uid_t>,
    group: Option<gid_t>,
    dev: Option<dev_t>,
}

lazy_static! {
    static ref DATABASE: Mutex<HashMap<Vec<u8>, Arc<Mutex<FileEntry>>, BuildHasherDefault<XxHash>>> = Mutex::new(Default::default());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const XATTR_CREATE: c_int = libc::XATTR_CREATE;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const XATTR_REPLACE: c_int = libc::XATTR_REPLACE;

// These platforms don't support xattr
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const XATTR_CREATE: c_int = 0;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const XATTR_REPLACE: c_int = 0;

#[cfg(target_os = "macos")]
const LIB_NAME: &'static str = "libtestwrapper.dylib";
#[cfg(not(target_os = "macos"))]
const LIB_NAME: &'static str = "libtestwrapper.so";

#[cfg(target_os = "macos")]
const LIB_INJECT_ENV: &'static str = "DYLD_INSERT_LIBRARIES";
#[cfg(not(target_os = "macos"))]
const LIB_INJECT_ENV: &'static str = "LD_PRELOAD";

fn reply<T: Serialize>(writer: &mut BufWriter<UnixStream>, obj: &T) {
    serialize_into(writer, obj, bincode::Infinite)
        .expect("Failed to write reply to Unix socket");
    writer.flush().expect("IO Error flushing Unix socket");
}

fn main() {
    env_logger::init().unwrap();
    let mut args = env::args();
    let mut our_path = PathBuf::from(args.next().expect("Executable path not passed as argument"));
    let mut rng = thread_rng();
    let mut socket_path = env::temp_dir();
    socket_path.push(format!("test-wrapper-{:016x}", rng.gen::<u64>()));
    let socket = UnixListener::bind(&socket_path).unwrap();
    our_path.pop();
    if our_path.is_relative() {
        our_path = env::current_dir().expect("Failed to get current directory").join(our_path);
    }
    let lib_path = our_path.join(LIB_NAME);
    if !lib_path.exists() {
        panic!("Failed to find library to inject");
    }
    let inject_path = match env::var_os(LIB_INJECT_ENV) {
        Some(var) => {
            let mut res = lib_path.into_os_string();
            res.push(OsStr::new(":"));
            res.push(var);
            res
        },
        None => lib_path.into_os_string(),
    };
    let mut command = Command::new(args.next().unwrap_or_else(|| "sh".to_string()))
        .args(args)
        .env(LIB_INJECT_ENV, inject_path)
        .env("TEST_WRAPPER_SOCKET", &socket_path)
        .spawn().expect("Failed to execute child process");
    thread::spawn(move || {
        let exit_code = command.wait().expect("Failed to manage child process");
        fs::remove_file(socket_path).expect("Failed to clean up Unix socket");
        process::exit(exit_code.code().unwrap_or(0));
    });
    let mut conn_num = 0;
    info!("Listening for connections");
    for conn in socket.incoming() {
        let conn = conn.expect("Failed to open incoming Unix socket connection");
        conn_num += 1;
        let conn_num = conn_num.clone();
        thread::spawn(move || {
            info!("Client {} connected", conn_num);
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut writer = BufWriter::new(conn);
            loop {
                let message: Message = match deserialize_from(&mut reader, bincode::Infinite) {
                    Ok(m) => m,
                    Err(err) => {
                        if let bincode::internal::ErrorKind::IoError(ref io_err) = *err.borrow() {
                            if io_err.kind() == ErrorKind::UnexpectedEof {
                                info!("Client {} disconnected", conn_num);
                                break;
                            }
                        }
                        error!("Failed to get message from Unix socket: {:?}", err);
                        break;
                    }
                };
                match message {
                    Message::Log(_, _) => {},
                    _ => debug!("{:?}", message),
                }
                let mut database = DATABASE.lock().unwrap();
                match message {
                    Message::Remove(path) => {
                        database.remove(&path);
                    }
                    Message::Rename(old, new) => {
                        let old_val = match database.remove(&old) {
                            Some(x) => x,
                            None => continue,
                        };
                        database.insert(new, old_val);
                    }
                    Message::XattrsGet(path, attr) => {
                        if let Some(file) = database.get(&path) {
                            let file = file.lock().unwrap();
                            if let Some(vec) = file.xattrs.get(&attr) {
                                reply(&mut writer, &ReplyXattrsGet(Some(vec.as_slice())));
                                continue;
                            }
                        }
                        reply(&mut writer, &ReplyXattrsGet(None));
                    }
                    Message::XattrsSet(path, attr, value, flags) => {
                        let file = database.entry(path).or_insert_with(|| Arc::new(Mutex::new(FileEntry::default())));
                        let mut file = file.lock().unwrap();
                        if file.xattrs.contains_key(&attr) {
                            if (flags & XATTR_CREATE) != 0 {
                                reply(&mut writer, &libc::EEXIST);
                                continue;
                            }
                        } else if (flags & XATTR_REPLACE) != 0 {
                            reply(&mut writer, &libc::ENODATA);
                            continue;
                        }
                        file.xattrs.insert(attr, value);
                        reply(&mut writer, &0);
                    }
                    Message::XattrsList(path) => {
                        if let Some(file) = database.get(&path) {
                            let file = file.lock().unwrap();
                            let list = file.xattrs.keys().collect::<Vec<_>>();
                            reply(&mut writer, &ReplyXattrsList(list.as_slice()));
                        } else {
                            reply(&mut writer, &ReplyXattrsList(&[]));
                        }
                    }
                    Message::OverrideMode(path, mode, mask, dev) => {
                        debug_assert_eq!(mode & !mask, 0);
                        let file = database.entry(path);
                        match file {
                            hash_map::Entry::Occupied(entry) => {
                                let mut file = entry.get().lock().unwrap();
                                file.xattrs.clear();
                                if let Some((old_mode, old_mask)) = file.mode_and_mask {
                                    file.mode_and_mask = Some((mode | (old_mode & !mask), mask | old_mask));
                                } else {
                                    file.mode_and_mask = Some((mode, mask));
                                }
                                file.dev = dev.or(file.dev);
                            }
                            hash_map::Entry::Vacant(entry) => {
                                let mut file_entry = FileEntry::default();
                                file_entry.mode_and_mask = Some((mode, mask));
                                file_entry.dev = dev;
                                entry.insert(Arc::new(Mutex::new(file_entry)));
                            }
                        }
                    }
                    Message::OverrideOwner(path, uid, gid) => {
                        let file = database.entry(path);
                        match file {
                            hash_map::Entry::Occupied(entry) => {
                                let mut file = entry.get().lock().unwrap();
                                if let Some(uid) = uid {
                                    file.owner = Some(uid);
                                }
                                if let Some(gid) = gid {
                                    file.group = Some(gid);
                                }
                            }
                            hash_map::Entry::Vacant(entry) => {
                                let mut file_entry = FileEntry::default();
                                file_entry.owner = uid;
                                file_entry.group = gid;
                                entry.insert(Arc::new(Mutex::new(file_entry)));
                            }
                        }
                    }
                    Message::GetPermissions(path) => {
                        let file = database.get(&path).map(|file| file.lock().unwrap());
                        let file = file.as_ref();
                        let response = ReplyGetPermissions {
                            mode_and_mask: file.and_then(|file| file.mode_and_mask),
                            owner: file.and_then(|file| file.owner),
                            group: file.and_then(|file| file.group),
                            dev: file.and_then(|file| file.dev),
                        };
                        reply(&mut writer, &response);
                    }
                    Message::Link(oldpath, newpath) => {
                        let file = match database.entry(oldpath) {
                            hash_map::Entry::Occupied(entry) => {
                                entry.get().clone() // entry is an Rc, so this is cloning a reference
                            }
                            hash_map::Entry::Vacant(entry) => {
                                let newfile = FileEntry::default();
                                let arc = Arc::new(Mutex::new(newfile));
                                entry.insert(arc.clone());
                                arc
                            }
                        };
                        database.insert(newpath, file);
                    }
                    Message::Log(log_level, message) => {
                        log!(log_level.into(), "Client {}: {}", conn_num, message);
                    }
                }
            }
        });
    }
}
