use std::os::raw::*;

use errno::errno;

use libc::{self, mode_t, uid_t, gid_t, dev_t};

use shared::*;

trait StatBase {
    fn get_fileid(&self) -> FileId;
    fn set_mode(&mut self, mode: mode_t, mask: mode_t);
    fn set_owner(&mut self, owner: uid_t);
    fn set_group(&mut self, group: gid_t);
    fn set_rdev(&mut self, dev: dev_t);
}

impl StatBase for libc::stat {
    fn get_fileid(&self) -> FileId {
        self.clone().into()
    }

    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        assert_eq!(mode & !mask, 0);
        let new_mode = mode | (self.st_mode & !mask);
        trace!("Faking mode 0o{:o} with 0o{:o} & 0o{:o} -> 0o{:o}", self.st_mode, mode, mask, new_mode);
        self.st_mode = new_mode;
    }

    fn set_owner(&mut self, owner: uid_t) {
        self.st_uid = owner;
    }

    fn set_group(&mut self, group: gid_t) {
        self.st_gid = group;
    }

    fn set_rdev(&mut self, rdev: dev_t) {
        self.st_rdev = rdev;
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl StatBase for libc::stat64 {
    fn get_fileid(&self) -> FileId {
        self.clone().into()
    }

    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        assert_eq!(mode & !mask, 0);
        let new_mode = mode | (self.st_mode & !mask);
        trace!("Faking mode 0o{:o} with 0o{:o} & 0o{:o} -> 0o{:o}", self.st_mode, mode, mask, new_mode);
        self.st_mode = new_mode;
    }

    fn set_owner(&mut self, owner: uid_t) {
        self.st_uid = owner;
    }

    fn set_group(&mut self, group: gid_t) {
        self.st_gid = group;
    }

    fn set_rdev(&mut self, rdev: dev_t) {
        self.st_rdev = rdev;
    }
}

fn stat_base(statbuf: &mut StatBase) {
    let overrides = request::<ReplyGetPermissions>(Message::GetPermissions(statbuf.get_fileid()));
    if let Some((mode, mask)) = overrides.mode_and_mask {
        statbuf.set_mode(mode, mask);
    }
    if let Some(owner) = overrides.owner {
        statbuf.set_owner(owner);
    }
    if let Some(group) = overrides.group {
        statbuf.set_group(group);
    }
    if let Some(rdev) = overrides.rdev {
        statbuf.set_rdev(rdev);
    }
}

fn chmod_base<'a, F: Fn(mode_t) -> c_int>(path: CPath, mode: mode_t, orig_chmod: F) -> Result<c_int> {
    let fs_mode = mode | 0o600;
    let mut override_mode = fs_mode != mode;
    if orig_chmod(fs_mode) == -1 {
        if errno().0 == libc::EPERM {
            override_mode = true;
        } else {
            return Err(0);
        }
    }
    if override_mode {
        message(Message::OverrideMode(path.get_id()?, mode & 0o7777, 0o7777, None))?;
    }
    Ok(0)
}

fn chown_base(path: CPath, owner: uid_t, group: gid_t) -> Result<c_int> {
    let owner = if (owner as i32) == -1 { None } else { Some(owner) };
    let group = if (group as i32) == -1 { None } else { Some(group) };
    message(Message::OverrideOwner(path.get_id()?, owner, group))?;
    Ok(0)
}

wrap! {
    unsafe fn chmod:ORIG_CHMOD(path: *const c_char, mode: mode_t) -> c_int {
        chmod_base(CPath::from_path(path, true), mode, |fs_mode| ORIG_CHMOD(path, fs_mode))
    }

    unsafe fn fchmod:ORIG_FCHMOD(fd: c_int, mode: mode_t) -> c_int {
        chmod_base(CPath::from_fd(fd), mode, |fs_mode| ORIG_FCHMOD(fd, fs_mode))
    }

    unsafe fn fchmodat:ORIG_FCHMODAT(dfd: c_int, path: *const c_char, mode: mode_t, flags: c_int) -> c_int {
        chmod_base(CPath::from_path_at(dfd, path, flags), mode, |fs_mode| ORIG_FCHMODAT(dfd, path, fs_mode, flags))
    }

    unsafe fn chown:_(path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
        chown_base(CPath::from_path(path, true), owner, group)
    }

    unsafe fn lchown:_(path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
        chown_base(CPath::from_path(path, false), owner, group)
    }

    unsafe fn fchown:_(fd: c_int, owner: uid_t, group: gid_t) -> c_int {
        chown_base(CPath::from_fd(fd), owner, group)
    }

    unsafe fn fchownat:_(dfd: c_int, path: *const c_char, owner: uid_t, group: gid_t, flags: c_int) -> c_int {
        chown_base(CPath::from_path_at(dfd, path, flags), owner, group)
    }
}

#[cfg(not(target_os = "linux"))]
wrap! {
    unsafe fn stat:ORIG_STAT(path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_STAT(path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn lstat:ORIG_LSTAT(path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LSTAT(path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn fstat:ORIG_FSTAT(fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FSTAT(fd, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn fstatat:ORIG_FSTATAT(dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FSTATAT(dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn __xstat:ORIG_XSTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_XSTAT(ver, path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __lxstat:ORIG_LXSTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LXSTAT(ver, path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstat:ORIG_FXSTAT(ver: c_int, fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FXSTAT(ver, fd, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstatat:ORIG_FXSTATAT(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __xstat64:ORIG_XSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_XSTAT64(ver, path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __lxstat64:ORIG_LXSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_LXSTAT64(ver, path, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstat64:ORIG_FXSTAT64(ver: c_int, fd: c_int, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_FXSTAT64(ver, fd, statbuf);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstatat64:ORIG_FXSTATAT64(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat64, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT64(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(&mut *statbuf);
        }
        Ok(ret)
    }
}

// Defined raw as these functions don't follow normal return code pattern

#[no_mangle]
pub unsafe extern "C" fn getuid() -> uid_t {
    0
}

#[no_mangle]
pub unsafe extern "C" fn geteuid() -> uid_t {
    0
}

#[no_mangle]
pub unsafe extern "C" fn getgid() -> gid_t {
    0
}

#[no_mangle]
pub unsafe extern "C" fn getegid() -> gid_t {
    0
}
