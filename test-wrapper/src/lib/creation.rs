use std::os::raw::*;

use shared::*;

use libc::{self, mode_t, dev_t};
use errno::errno;

fn override_base(path: CPath, mode: mode_t, mask: mode_t) {
    if let Ok(id) = path.get_id() {
        let _ = message(Message::OverrideMode(id, mode & mask, mask, None));
    } else {
        warn!("Failed to get creation path: {:?} {:?}", path, errno());
    }
}

fn open_base_inner(ret: c_int, fs_mode: mode_t, mode: mode_t) -> Result<()> {
    if ret >= 0 {
        let id = CPath::from_fd(ret).get_id()?;
        if fs_mode != mode {
            message(Message::OverrideMode(id, mode & 0o7777, 0o7777, None))?;
        }
        inc_file_ref_count(id)
    } else {
        Ok(())
    }
}

fn open_base(ret: c_int, fs_mode: mode_t, mode: mode_t) {
    if let Err(err) = open_base_inner(ret, fs_mode, mode) {
        warn!("Failed to process open: {:?}", err);
    }
}

fn mknod_base<'a, F: Fn() -> CPath, M: Fn(mode_t) -> c_int>(get_path: F, mode: mode_t, dev: dev_t, mknod: M) -> Result<c_int> {
    let override_mode = mode & libc::S_IFCHR == libc::S_IFCHR || mode & libc::S_IFBLK == libc::S_IFBLK;
    let base_mode = if override_mode {
        libc::S_IFREG | 0o600 | (mode & 0o777)
    } else {
        mode
    };
    let ret = mknod(base_mode);
    if ret == 0 && override_mode {
        let _ = message(Message::OverrideMode(get_path().get_id()?, mode, mode_t::max_value(), Some(dev)));
    }
    Ok(ret)
}

const MKDIR_MASK: mode_t = 0o777 | (libc::S_ISVTX as mode_t);

wrap! {
    unsafe fn mkdir:ORIG_MKDIR(path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_MKDIR(path, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path(path, false), mode & MKDIR_MASK, MKDIR_MASK);
        }
        Ok(ret)
    }

    unsafe fn mkdirat:ORIG_MKDIRAT(dfd: c_int, path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_MKDIRAT(dfd, path, fs_mode);
        if ret == 0 && fs_mode != mode {
            override_base(CPath::from_path_at(dfd, path, libc::AT_SYMLINK_NOFOLLOW), mode & MKDIR_MASK, MKDIR_MASK);
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
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }

    unsafe fn openat:ORIG_OPENAT(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let fs_mode = if flags & libc::O_CREAT == libc::O_CREAT {
            mode | 0o600
        } else {
            mode
        };
        let ret = ORIG_OPENAT(dfd, path, flags, fs_mode);
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }

    unsafe fn creat:ORIG_CREAT(path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_CREAT(path, fs_mode);
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }
}

#[cfg(not(target_os = "linux"))]
wrap! {
    unsafe fn mknod:ORIG_MKNOD(path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path(path, false), mode, dev, |mode| ORIG_MKNOD(path, mode, dev))
    }

    unsafe fn mknodat:ORIG_MKNODAT(dfd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path_at(dfd, path, 0), mode, dev, |mode| ORIG_MKNODAT(dfd, path, mode, dev))
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn __xmknod:ORIG_XMKNOD(ver: c_int, path: *const c_char, mode: mode_t, dev: *const dev_t) -> c_int {
        mknod_base(|| CPath::from_path(path, false), mode, *dev, |mode| ORIG_XMKNOD(ver, path, mode, dev))
    }

    unsafe fn __xmknodat:ORIG_XMKNODAT(ver: c_int, dfd: c_int, path: *const c_char, mode: mode_t, dev: *const dev_t) -> c_int {
        mknod_base(|| CPath::from_path_at(dfd, path, 0), mode, *dev, |mode| ORIG_XMKNODAT(ver, dfd, path, mode, dev))
    }

    unsafe fn open64:ORIG_OPEN64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let fs_mode = if flags & libc::O_CREAT == libc::O_CREAT {
            mode | 0o600
        } else {
            mode
        };
        let ret = ORIG_OPEN64(path, flags, fs_mode);
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }

    unsafe fn openat64:ORIG_OPENAT64(dfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
        let fs_mode = if flags & libc::O_CREAT == libc::O_CREAT {
            mode | 0o600
        } else {
            mode
        };
        let ret = ORIG_OPENAT64(dfd, path, flags, fs_mode);
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }

    unsafe fn creat64:ORIG_CREAT64(path: *const c_char, mode: mode_t) -> c_int {
        let fs_mode = mode | 0o600;
        let ret = ORIG_CREAT64(path, fs_mode);
        open_base(ret, fs_mode, mode);
        Ok(ret)
    }
}
