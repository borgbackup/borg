/// Wraps various libc functions for Borg's tests.
/// Currently just overrides xattr functions so that tests can run even when the FS doesn't support
/// xattrs. Originally fakeroot was used for this, but it caused other problems because it wrapped
/// a much bigger surface area than necessary for our use.
///
/// This file contains the binary, which functions as both a daemon and a launcher for whatever's
/// being run through this wrapper.

use std::env;
use std::fs;
use std::thread;
use std::borrow::Borrow;
use std::sync::RwLock;
use std::collections::HashMap;
use std::process::{self, Command};
use std::ffi::OsStr;
use std::os::raw::*;
use std::path::PathBuf;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, ErrorKind};

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

#[macro_use]
extern crate serde_derive;
extern crate bincode;
use bincode::{deserialize_from, serialize_into};

#[derive(Debug, Serialize)]
pub struct ReplyXattrsGet<'a>(Option<&'a [u8]>);

#[derive(Debug, Serialize)]
pub struct ReplyXattrsList<'a>(Vec<&'a Vec<u8>>);

#[derive(Debug, Deserialize)]
pub enum Message {
    Remove(Vec<u8>),
    Rename(Vec<u8>, Vec<u8>),
    XattrsGet(Vec<u8>, Vec<u8>),
    XattrsSet(Vec<u8>, Vec<u8>, Vec<u8>, c_int),
    XattrsList(Vec<u8>),
    XattrsReset(Vec<u8>),
}

#[derive(Default)]
struct FileEntry {
    xattrs: HashMap<Vec<u8>, Vec<u8>>,
}

lazy_static! {
    static ref DATABASE: RwLock<HashMap<Vec<u8>, FileEntry>> = RwLock::new(HashMap::new());
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
        panic!("Failed to find library to LD_PRELOAD");
    }
    let ld_preload = match env::var_os("LD_PRELOAD") {
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
        .env("LD_PRELOAD", ld_preload)
        .env("TEST_WRAPPER_SOCKET", &socket_path)
        .spawn().expect("Failed to execute child process");
    thread::spawn(move || {
        let exit_code = command.wait().expect("Failed to manage child process");
        fs::remove_file(socket_path).expect("Failed to clean up Unix socket");
        process::exit(exit_code.code().unwrap_or(0));
    });
    info!("Listening for connections");
    for conn in socket.incoming() {
        let conn = conn.expect("Failed to open incoming Unix socket connection");
        thread::spawn(move || {
            info!("Socket opened");
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut writer = BufWriter::new(conn);
            loop {
                let message: Message = match deserialize_from(&mut reader, bincode::Infinite) {
                    Ok(m) => m,
                    Err(err) => {
                        if let &bincode::internal::ErrorKind::IoError(ref io_err) = err.borrow() {
                            if io_err.kind() == ErrorKind::UnexpectedEof {
                                break;
                            }
                        }
                        error!("Failed to get message from Unix socket: {:?}", err);
                        break;
                    }
                };
                debug!("{:?}", message);
                match message {
                    Message::Remove(path) => {
                        DATABASE.write().unwrap().remove(&path);
                    }
                    Message::Rename(old, new) => {
                        let mut database = DATABASE.write().unwrap();
                        let old_val = match database.remove(&old) {
                            Some(x) => x,
                            None => continue,
                        };
                        database.insert(new, old_val);
                    }
                    Message::XattrsGet(path, attr) => {
                        let database = DATABASE.read().unwrap();
                        let res = database.get(&path).and_then(|file| file.xattrs.get(&attr));
                        reply(&mut writer, &ReplyXattrsGet(res.map(Borrow::borrow)));
                    }
                    Message::XattrsSet(path, attr, value, flags) => {
                        let mut database = DATABASE.write().unwrap();
                        let file = database.entry(path).or_insert_with(FileEntry::default);
                        if file.xattrs.contains_key(&attr) {
                            if (flags & XATTR_CREATE) != 0 {
                                reply(&mut writer, &libc::EEXIST);
                                continue;
                            }
                        } else {
                            if (flags & XATTR_REPLACE) != 0 {
                                reply(&mut writer, &libc::ENODATA);
                                continue;
                            }
                        }
                        file.xattrs.insert(attr, value);
                        reply(&mut writer, &0);
                    }
                    Message::XattrsList(path) => {
                        let database = DATABASE.read().unwrap();
                        let list = database.get(&path).map(|file| file.xattrs.keys().collect::<Vec<_>>()).unwrap_or_else(Vec::new);
                        reply(&mut writer, &ReplyXattrsList(list));
                    }
                    Message::XattrsReset(path) => {
                        DATABASE.write().unwrap().remove(&path);
                    }
                }
            }
        });
    }
}
