use std::os::raw::*;

use shared::*;

use libc::{self, mode_t};
use errno::errno;

fn override_base(path: CPath, mode: mode_t, mask: mode_t) {
    if let Ok(id) = path.get_id() {
        send(Message::OverrideMode(id, mode & mask, mask, None));
    } else {
        warn!("Failed to get creation path: {:?} {:?}", path, errno());
    }
}

const MKDIR_MASK: mode_t = 0o777 | (libc::S_ISVTX as mode_t);

wrap! {
    unsafe fn mkdir:ORIG_MKDIR(path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_MKDIR(path, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path(path, false), mode, MKDIR_MASK);
        }
        Ok(ret)
    }

    unsafe fn mkdirat:ORIG_MKDIRAT(dfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_MKDIRAT(dfd, path, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path_at(dfd, path, libc::AT_SYMLINK_NOFOLLOW), mode, MKDIR_MASK);
        }
        Ok(ret)
    }

    unsafe fn open:ORIG_OPEN(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let fs_mode = if flags & libc::O_CREAT == libc::O_CREAT {
            mode | 0o600
        } else {
            mode
        };
        let ret = ORIG_OPEN(path, flags, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path(path, false), mode, 0o7777);
        }
        Ok(ret)
    }

    unsafe fn openat:ORIG_OPENAT(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let fs_mode = if flags & libc::O_CREAT == libc::O_CREAT {
            mode | 0o600
        } else {
            mode
        };
        let ret = ORIG_OPENAT(dfd, path, flags, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path_at(dfd, path, libc::AT_SYMLINK_NOFOLLOW), mode, 0o7777);
        }
        Ok(ret)
    }

    unsafe fn creat:ORIG_CREAT(path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_CREAT(path, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path(path, false), mode, 0o7777);
        }
        Ok(ret)
    }
}
