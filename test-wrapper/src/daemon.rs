use std::borrow::Borrow;
use std::os::raw::*;
use std::io::prelude::*;
use std::sync::RwLock;
use std::io::{BufReader, BufWriter, ErrorKind};
use std::collections::hash_map;
use std::fmt::Debug;

use std::os::unix::net::UnixStream;

use bincode::{self, deserialize_from, serialize_into};
use fnv::{FnvHashMap, FnvHashSet};
use libc::{self, mode_t, uid_t, gid_t, dev_t};
use serde::ser::Serialize;
use log;

#[derive(Debug, Serialize)]
pub struct ReplyXattrsGet<'a>(Option<&'a [u8]>);

#[derive(Debug, Serialize)]
pub struct ReplyXattrsList<'a>(&'a [&'a Vec<u8>]);

#[derive(Debug, Serialize)]
pub struct ReplyGetPermissions {
    mode_and_mask: Option<(mode_t, mode_t)>,
    owner: Option<uid_t>,
    group: Option<gid_t>,
    rdev: Option<dev_t>,
}

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

#[allow(non_camel_case_types)]
#[cfg(any(not(target_os = "linux"), not(target_pointer_width = "64")))]
type ino_t = libc::ino_t;

#[allow(non_camel_case_types)]
#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
type ino_t = libc::ino64_t;

#[derive(Debug, Deserialize, Hash, PartialEq, Eq, Clone, Copy)]
pub struct FileId(dev_t, ino_t);

#[derive(Debug, Deserialize)]
enum Message {
    ReadyDeletion(FileId),
    Reference(FileId),
    DropReference(FileId),
    XattrsGet(FileId, Vec<u8>),
    XattrsSet(FileId, Vec<u8>, Vec<u8>, c_int),
    XattrsDelete(FileId, Vec<u8>),
    XattrsList(FileId),
    OverrideMode(FileId, mode_t, mode_t, Option<dev_t>),
    OverrideOwner(FileId, Option<uid_t>, Option<gid_t>),
    GetPermissions(FileId),
    Log(NetworkLogLevel, String),
}

#[derive(Default)]
pub struct FileEntry {
    xattrs: FnvHashMap<Vec<u8>, Vec<u8>>,
    mode_and_mask: Option<(mode_t, mode_t)>,
    owner: Option<uid_t>,
    group: Option<gid_t>,
    rdev: Option<dev_t>,
    reference_count: u32,
    deletion_ready: bool,
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

lazy_static! {
    static ref DATABASE: RwLock<FnvHashMap<FileId, FileEntry>> = RwLock::new(Default::default());
}

fn reply<T: Serialize + Debug>(writer: &mut BufWriter<UnixStream>, obj: &T) {
    trace!("Reply: {:?}", obj);
    serialize_into(writer, obj, bincode::Infinite)
        .expect("Failed to write reply to client socket");
    writer.flush().expect("IO Error flushing client socket");
}

fn reply_zero(writer: &mut BufWriter<UnixStream>) {
    let zero: c_int = 0;
    serialize_into(writer, &zero, bincode::Infinite)
        .expect("Failed to write reply to client socket");
    writer.flush().expect("IO Error flushing client socket");
}

fn drop_ref(id: FileId) {
    let mut database = DATABASE.write().unwrap();
    match database.entry(id) {
        hash_map::Entry::Occupied(mut entry) => {
            let should_drop = {
                let file = entry.get_mut();
                if file.reference_count == 0 {
                    warn!("Tried to drop ref to file with no references");
                }
                file.reference_count = file.reference_count.saturating_sub(1);
                file.reference_count == 0 && file.deletion_ready
            };
            if should_drop {
                entry.remove();
            }
        }
        hash_map::Entry::Vacant(entry) => {
            error!("Tried to drop reference for nonexistant file {:?}", entry.into_key());
        }
    }
}

pub fn connection(conn: UnixStream, conn_num: u32) {
    info!("Client {} connected", conn_num);
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut writer = BufWriter::new(conn);
    let mut conn_references = FnvHashSet::default();
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
            _ => trace!("Client {}: {:?}", conn_num, message),
        }
        match message {
            Message::ReadyDeletion(id) => {
                let mut database = DATABASE.write().unwrap();
                match database.entry(id) {
                    hash_map::Entry::Occupied(mut entry) => {
                        let should_remove = {
                            let file = entry.get_mut();
                            file.deletion_ready = true;
                            file.reference_count == 0
                        };
                        if should_remove {
                            entry.remove();
                        }
                    }
                    _ => error!("Client {} called ReadyDeletion for unknown file {:?}", conn_num, id)
                }
            }
            Message::Reference(id) => {
                let mut database = DATABASE.write().unwrap();
                if conn_references.insert(id) {
                    database.entry(id).or_insert_with(Default::default).reference_count += 1;
                } else {
                    error!("Client {} double referenced {:?}", conn_num, id);
                }
            }
            Message::DropReference(id) => {
                if conn_references.remove(&id) {
                    drop_ref(id);
                } else {
                    error!("Client {} tried to remove already removed file {:?}", conn_num, id);
                }
            }
            Message::XattrsGet(id, attr) => {
                {
                    let database = DATABASE.read().unwrap();
                    if let Some(file) = database.get(&id) {
                        if let Some(vec) = file.xattrs.get(&attr) {
                            reply(&mut writer, &ReplyXattrsGet(Some(vec.as_slice())));
                            continue;
                        }
                    }
                }
                reply(&mut writer, &ReplyXattrsGet(None));
                continue;
            }
            Message::XattrsSet(id, attr, value, flags) => {
                let mut database = DATABASE.write().unwrap();
                let file = database.entry(id).or_insert_with(FileEntry::default);
                if file.xattrs.contains_key(&attr) {
                    if XATTR_CREATE != 0 && flags & XATTR_CREATE == XATTR_CREATE {
                        reply(&mut writer, &libc::EEXIST);
                        continue;
                    }
                } else if XATTR_REPLACE != 0 && flags & XATTR_REPLACE == XATTR_REPLACE {
                    reply(&mut writer, &libc::ENOATTR);
                    continue;
                }
                file.xattrs.insert(attr, value);
            }
            Message::XattrsDelete(id, attr) => {
                let mut database = DATABASE.write().unwrap();
                let file = database.entry(id);
                match file {
                    hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().xattrs.remove(&attr);
                    }
                    _ => {}
                }
            }
            Message::XattrsList(id) => {
                let database = DATABASE.read().unwrap();
                if let Some(file) = database.get(&id) {
                    let list = file.xattrs.keys().collect::<Vec<_>>();
                    reply(&mut writer, &ReplyXattrsList(list.as_slice()));
                } else {
                    reply(&mut writer, &ReplyXattrsList(&[]));
                }
                continue;
            }
            Message::OverrideMode(id, mode, mask, rdev) => {
                debug_assert_eq!(mode & !mask, 0);
                let mut database = DATABASE.write().unwrap();
                let file = database.entry(id);
                match file {
                    hash_map::Entry::Occupied(mut entry) => {
                        let file = entry.get_mut();
                        file.xattrs.clear();
                        if let Some((old_mode, old_mask)) = file.mode_and_mask {
                            file.mode_and_mask = Some((mode | (old_mode & !mask), mask | old_mask));
                        } else {
                            file.mode_and_mask = Some((mode, mask));
                        }
                        file.rdev = rdev.or(file.rdev);
                    }
                    hash_map::Entry::Vacant(entry) => {
                        let mut file_entry = FileEntry::default();
                        file_entry.mode_and_mask = Some((mode, mask));
                        file_entry.rdev = rdev;
                        entry.insert(file_entry);
                    }
                }
            }
            Message::OverrideOwner(id, uid, gid) => {
                let mut database = DATABASE.write().unwrap();
                let file = database.entry(id);
                match file {
                    hash_map::Entry::Occupied(mut entry) => {
                        let file = entry.get_mut();
                        file.xattrs.clear();
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
                        entry.insert(file_entry);
                    }
                }
            }
            Message::GetPermissions(id) => {
                let response = {
                    let database = DATABASE.read().unwrap();
                    let file = database.get(&id);
                    let file = file.as_ref();
                    ReplyGetPermissions {
                        mode_and_mask: file.and_then(|file| file.mode_and_mask),
                        owner: file.and_then(|file| file.owner),
                        group: file.and_then(|file| file.group),
                        rdev: file.and_then(|file| file.rdev),
                    }
                };
                reply(&mut writer, &response);
                continue;
            }
            Message::Log(log_level, message) => {
                log!(log_level.into(), "Client {}: {}", conn_num, message);
            }
        }
        reply_zero(&mut writer);
    }
    for id in conn_references {
        drop_ref(id);
    }
}
