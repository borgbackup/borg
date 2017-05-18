use std::os::raw::*;

use errno::errno;

use libc::{self, mode_t, uid_t, gid_t, dev_t};

use shared::*;

trait StatBase {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t);
    fn set_owner(&mut self, owner: uid_t);
    fn set_group(&mut self, group: gid_t);
    fn set_rdev(&mut self, dev: dev_t);
}

impl StatBase for libc::stat {
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

    fn set_rdev(&mut self, dev: dev_t) {
        self.st_rdev = dev;
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl StatBase for libc::stat64 {
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

    fn set_rdev(&mut self, dev: dev_t) {
        self.st_rdev = dev;
    }
}

fn stat_base(path: CPath, statbuf: &mut StatBase) {
    let id = if let Ok(id) = path.get_id() {
        id
    } else {
        warn!("Failed to get stat path: {:?} errno {}", path, errno());
        return;
    };
    let overrides = request::<ReplyGetPermissions>(Message::GetPermissions(id));
    if let Some((mode, mask)) = overrides.mode_and_mask {
        statbuf.set_mode(mode, mask);
    }
    if let Some(owner) = overrides.owner {
        statbuf.set_owner(owner);
    }
    if let Some(group) = overrides.group {
        statbuf.set_group(group);
    }
    // TODO this breaks stuff
    //if let Some(dev) = overrides.dev {
    //    statbuf.set_rdev(dev);
    //}
}

fn chmod_base<'a, F: Fn(mode_t) -> c_int>(path: CPath, mut mode: mode_t, orig_chmod: F) -> Result<c_int> {
    mode &= 0o7777;
    let stat = path.get_stat()?;
    let old_mode = stat.st_mode & 0o7777;
    // Since we aren't root, don't downgrade permissions.
    let fs_mode = (old_mode as mode_t) | mode;
    let mut override_mode = fs_mode != mode;
    if fs_mode != old_mode {
        if orig_chmod(fs_mode) == -1 {
            if errno().0 == libc::EPERM {
                override_mode = true;
            } else {
                return Err(0);
            }
        }
    }
    if override_mode {
        send(Message::OverrideMode(stat.into(), mode, 0o7777, None));
    }
    Ok(0)
}

fn chown_base(path: CPath, owner: uid_t, group: gid_t) -> Result<c_int> {
    let owner = if (owner as i32) == -1 { None } else { Some(owner) };
    let group = if (group as i32) == -1 { None } else { Some(group) };
    send(Message::OverrideOwner(path.get_id()?, owner, group));
    Ok(0)
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
        send(Message::OverrideMode(get_path().get_id()?, mode, mode_t::max_value(), Some(dev)));
    }
    Ok(ret)
}

wrap! {
    unsafe fn chmod:ORIG_CHMOD(path: *const c_char, mode: mode_t) -> c_int {
        chmod_base(CPath::from_path(path, true), mode, |mode| ORIG_CHMOD(path, mode))
    }

    unsafe fn fchmod:ORIG_FCHMOD(fd: c_int, mode: mode_t) -> c_int {
        chmod_base(CPath::from_fd(fd), mode, |mode| ORIG_FCHMOD(fd, mode))
    }

    unsafe fn fchmodat:ORIG_FCHMODAT(dfd: c_int, path: *const c_char, mode: mode_t, flags: c_int) -> c_int {
        chmod_base(CPath::from_path_at(dfd, path, flags), mode, |mode| ORIG_FCHMODAT(dfd, path, mode, flags))
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
            stat_base(CPath::from_path(path, true), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn lstat:ORIG_LSTAT(path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LSTAT(path, statbuf);
        if ret == 0 {
            stat_base(CPath::from_path(path, false), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn fstat:ORIG_FSTAT(fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FSTAT(fd, statbuf);
        if ret == 0 {
            stat_base(CPath::from_fd(fd), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn fstatat:ORIG_FSTATAT(dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FSTATAT(dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(CPath::from_path_at(dfd, path, flags), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn mknod:ORIG_MKNOD(path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path(path, false), mode, dev, |mode| ORIG_MKNOD(path, mode, dev))
    }

    unsafe fn mknodat:ORIG_MKNODAT(dfd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path_at(dfd, path, 0), mode, dev, |mode| ORIG_MKNODAT(dfd, path, mode, dev))
    }
}

#[cfg(target_os = "linux")]
wrap! {
    unsafe fn __xstat:ORIG_SXTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_SXTAT(ver, path, statbuf);
        if ret == 0 {
            stat_base(CPath::from_path(path, true), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __lxstat:ORIG_LXSTAT(ver: c_int, path: *const c_char, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_LXSTAT(ver, path, statbuf);
        if ret == 0 {
            stat_base(CPath::from_path(path, false), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstat:ORIG_FXSTAT(ver: c_int, fd: c_int, statbuf: *mut libc::stat) -> c_int {
        let ret = ORIG_FXSTAT(ver, fd, statbuf);
        if ret == 0 {
            stat_base(CPath::from_fd(fd), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstatat:ORIG_FXSTATAT(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(CPath::from_path_at(dfd, path, flags), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __xstat64:ORIG_XSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_XSTAT64(ver, path, statbuf);
        if ret == 0 {
            stat_base(CPath::from_path(path, true), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __lxstat64:ORIG_LXSTAT64(ver: c_int, path: *const c_char, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_LXSTAT64(ver, path, statbuf);
        if ret == 0 {
            stat_base(CPath::from_path(path, false), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstat64:ORIG_FXSTAT64(ver: c_int, fd: c_int, statbuf: *mut libc::stat64) -> c_int {
        let ret = ORIG_FXSTAT64(ver, fd, statbuf);
        if ret == 0 {
            stat_base(CPath::from_fd(fd), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __fxstatat64:ORIG_FXSTATAT64(ver: c_int, dfd: c_int, path: *const c_char, statbuf: *mut libc::stat64, flags: c_int) -> c_int {
        let ret = ORIG_FXSTATAT64(ver, dfd, path, statbuf, flags);
        if ret == 0 {
            stat_base(CPath::from_path_at(dfd, path, flags), &mut *statbuf);
        }
        Ok(ret)
    }

    unsafe fn __xmknod:ORIG_XMKNOD(ver: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path(path, false), mode, dev, |mode| ORIG_XMKNOD(ver, path, mode, dev))
    }

    unsafe fn __xmknodat:ORIG_XMKNODAT(ver: c_int, dfd: c_int, path: *const c_char, mode: mode_t, dev: dev_t) -> c_int {
        mknod_base(|| CPath::from_path_at(dfd, path, 0), mode, dev, |mode| ORIG_XMKNODAT(ver, dfd, path, mode, dev))
    }
}
