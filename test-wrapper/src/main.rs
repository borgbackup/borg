/// Wraps various libc functions for Borg's tests.
/// Currently overrides permissions/modes and xattrs. Previously fakeroot was used, but it caused
/// other problems.
///
/// This file contains the binary, which functions as both a daemon and a launcher for whatever's
/// being run through this wrapper.

use std::env;
use std::fs;
use std::thread;
use std::ffi::OsStr;
use std::process::{self, Command};
use std::path::PathBuf;

use std::os::unix::net::UnixListener;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate rand;
use rand::{Rng, thread_rng};

extern crate serde;

extern crate libc;

extern crate fnv;

#[macro_use]
extern crate serde_derive;
extern crate bincode;

mod daemon;

#[cfg(target_os = "macos")]
const LIB_NAME: &'static str = "libtestwrapper.dylib";
#[cfg(not(target_os = "macos"))]
const LIB_NAME: &'static str = "libtestwrapper.so";

#[cfg(target_os = "macos")]
const LIB_INJECT_ENV: &'static str = "DYLD_INSERT_LIBRARIES";
#[cfg(not(target_os = "macos"))]
const LIB_INJECT_ENV: &'static str = "LD_PRELOAD";

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
    let mut command = Command::new(args.next().unwrap_or_else(|| "sh".to_string()));
    let command = command
        .args(args)
        .env(LIB_INJECT_ENV, inject_path)
        .env("TEST_WRAPPER_SOCKET", &socket_path);
    if cfg!(target_os = "macos") {
        command.env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    }
    let mut command = command.spawn().expect("Failed to execute child process");
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
            daemon::connection(conn, conn_num);
        });
    }
}
