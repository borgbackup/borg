use std::fs;
use std::ffi::CStr;
use std::os::raw::*;
use std::path::{Path, PathBuf};

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use errno::{errno, set_errno};

use libc::{self, mode_t, uid_t, gid_t, dev_t};

use shared::*;

trait StatBase {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t);
    fn set_owner(&mut self, owner: uid_t);
    fn set_group(&mut self, group: gid_t);
    fn set_dev(&mut self, dev: dev_t);
}

impl StatBase for libc::stat {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        debug_assert_eq!(mode & !mask, 0);
        self.st_mode = mode | (self.st_mode & !mask);
    }

    fn set_owner(&mut self, owner: uid_t) {
        self.st_uid = owner;
    }

    fn set_group(&mut self, group: gid_t) {
        self.st_gid = group;
    }

    fn set_dev(&mut self, dev: dev_t) {
        self.st_dev = dev;
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl StatBase for libc::stat64 {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        debug_assert_eq!(mode & !mask, 0);
        self.st_mode = mode | (self.st_mode & !mask);
    }

    fn set_owner(&mut self, owner: uid_t) {
        self.st_uid = owner;
    }

    fn set_group(&mut self, group: gid_t) {
        self.st_gid = group;
    }

    fn set_dev(&mut self, dev: dev_t) {
        self.st_dev = dev;
    }
}

fn stat_base(path: &Path, statbuf: &mut StatBase) {
    let overrides = request::<ReplyGetPermissions>(Message::GetPermissions(path.as_os_str().as_bytes()));
    if let Some((mode, mask)) = overrides.mode_and_mask {
        statbuf.set_mode(mode, mask);
    }
    if let Some(owner) = overrides.owner {
        statbuf.set_owner(owner);
    }
    if let Some(group) = overrides.group {
        statbuf.set_group(group);
    }
    if let Some(dev) = overrides.dev {
        statbuf.set_dev(dev);
    }
}

fn chmod_base<F: Fn(mode_t) -> c_int>(path: &Path, mut mode: mode_t, orig_chmod: F) -> Result<c_int> {
    let file_meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => return Err(err.raw_os_error().unwrap()),
    };
    mode = mode & 0o777;
    // On OSX mode_t is u16, but fs::metadata gives us a u32 (so we cast it).
    let old_mode = file_meta.mode() as mode_t & 0o777;
    // Since we aren't root, don't downgrade permissions.
    let fs_mode = (old_mode as mode_t) | mode;
    let mut override_mode = fs_mode != mode;
    let old_errno = errno();
    if fs_mode != old_mode {
        if orig_chmod(fs_mode) == -1 {
            if errno().0 == libc::EPERM {
                override_mode = true;
                set_errno(old_errno);
            } else {
                return Ok(-1);
            }
        }
    } else if !path.exists() {
        return Err(libc::ENOENT);
    }
    if override_mode {
        send(Message::OverrideMode(path.as_os_str().as_bytes(), mode, 0o777, None));
    }
    Ok(0)
}

fn chown_base(path: &Path, owner: uid_t, group: gid_t) -> Result<c_int> {
    let owner = if (owner as i32) == -1 { None } else { Some(owner) };
    let group = if (group as i32) == -1 { None } else { Some(group) };
    send(Message::OverrideOwner(path.as_os_str().as_bytes(), owner, group));
    Ok(0)
}

fn mknod_base<F: Fn() -> Result<PathBuf>>(get_path: F, mode: &mut mode_t, dev: dev_t) -> Result<()> {
    if (*mode & libc::S_IFCHR) != 0 || (*mode & libc::S_IFBLK) != 0 {
        send(Message::OverrideMode(get_path()?.as_os_str().as_bytes(), *mode, mode_t::max_value(), Some(dev)));
        *mode = 0o600 | *mode & 0o777;
    }
    Ok(())
}

wrap! {
    unsafe fn chmod:ORIG_CHMOD(path: *const c_char, mode: mode_t) -> c_int {
        chmod_base(&cpath(CStr::from_ptr(path), true)?, mode, |mode| ORIG_CHMOD(path, mode))
    }

    unsafe fn fchmod:ORIG_FCHMOD(fd: c_int, mode: mode_t) -> c_int {
        chmod_base(&get_fd_path!(fd)?, mode, |mode| ORIG_FCHMOD(fd, mode))
    }

    unsafe fn fchmodat:ORIG_FCHMODAT(dfd: c_int, path: *const c_char, mode: mode_t, flags: c_int) -> c_int {
        chmod_base(&cpath_at(dfd, CStr::from_ptr(path), true)?, mode, |mode| ORIG_FCHMODAT(dfd, path, mode, flags))
    }

    unsafe fn chown:_(path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
        chown_base(&cpath(CStr::from_ptr(path), true)?, owner, group)
    }

    unsafe fn lchown:_(path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
        chown_base(&cpath(CStr::from_ptr(path), false)?, owner, group)
    }

    unsafe fn fchown:_(fd: c_int, owner: uid_t, group: gid_t) -> c_int {
        chown_base(get_fd_path!(fd)?, owner, group)
    }

    unsafe fn fchownat:_(dfd: c_int, path: *const c_char, owner: uid_t, group: gid_t) -> c_int {
        chown_base(&cpath_at(dfd, CStr::from_ptr(path), true)?, owner, group)
    }
}

#[cfg(not(target_os = "linux"))]
wrap! {
    unsafe fn stat:ORIG_STAT(path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_STAT(path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(&CStr::from_ptr(path), true) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn lstat:ORIG_LSTAT(path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LSTAT(path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(&CStr::from_ptr(path), false) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn fstat:ORIG_FSTAT(fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FSTAT(fd, statbuf);
        if ret == 0 {
            if let Ok(path) = get_fd_path!(fd) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn fstatat:ORIG_FSTATAT(dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FSTATAT(dfd, path, statbuf, flags);
        if ret == 0 {
            if let Ok(path) = cpath_at(dfd, &CStr::from_ptr(path), (flags & libc::AT_SYMLINK_NOFOLLOW) == 0) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn mknod:ORIG_MKNOD(path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        let mut mode = mode;
        mknod_base(|| cpath(CStr::from_ptr(path), false), &mut mode, dev)?;
        Ok(ORIG_MKNOD(path, mode, dev))
    }

    unsafe fn mknodat:ORIG_MKNODAT(dfd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        let mut mode = mode;
        mknod_base(|| cpath_at(dfd, CStr::from_ptr(path), false), &mut mode, dev)?;
        Ok(ORIG_MKNODAT(dfd, path, mode, dev))
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn __xstat:ORIG_SXTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_SXTAT(ver, path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(&CStr::from_ptr(path), true) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __lxstat:ORIG_LXSTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LXSTAT(ver, path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(&CStr::from_ptr(path), false) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __fxstat:ORIG_FXSTAT(ver: c_int, fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FXSTAT(ver, fd, statbuf);
        if ret == 0 {
            if let Ok(path) = get_fd_path!(fd) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __fxstatat:ORIG_FXSTATAT(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            if let Ok(path) = cpath_at(dfd, &CStr::from_ptr(path), (flags & libc::AT_SYMLINK_NOFOLLOW) == 0) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __xstat64:ORIG_XSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_XSTAT64(ver, path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), true) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __lxstat64:ORIG_LXSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_LXSTAT64(ver, path, statbuf);
        if ret == 0 {
            if let Ok(path) = cpath(CStr::from_ptr(path), false) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __fxstat64:ORIG_FXSTAT64(ver: c_int, fd: c_int, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_FXSTAT64(ver, fd, statbuf);
        if ret == 0 {
            if let Ok(path) = get_fd_path!(fd) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __fxstatat64:ORIG_FXSTATAT64(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat64, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT64(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            if let Ok(path) = cpath_at(dfd, &CStr::from_ptr(path), (flags & libc::AT_SYMLINK_NOFOLLOW) == 0) {
                stat_base(&path, &mut *statbuf);
            }
        }
        Ok(ret)
    }

    unsafe fn __xmknod:ORIG_MKNOD(ver: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        let mut mode = mode;
        mknod_base(|| cpath(CStr::from_ptr(path), false), &mut mode, dev)?;
        Ok(ORIG_MKNOD(ver, path, mode, dev))
    }

    unsafe fn __xmknodat:ORIG_MKNODAT(ver: c_int, dfd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        let mut mode = mode;
        mknod_base(|| cpath_at(dfd, CStr::from_ptr(path), false), &mut mode, dev)?;
        Ok(ORIG_MKNODAT(ver, dfd, path, mode, dev))
    }
}
