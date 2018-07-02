use libc::{self, mode_t, uid_t, gid_t, dev_t, ino_t};

pub trait StatBase {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t);
    fn set_owner(&mut self, owner: uid_t);
    fn set_group(&mut self, group: gid_t);
    fn set_rdev(&mut self, dev: dev_t);
    fn get_dev(&self) -> dev_t;
    fn get_ino(&self) -> ino_t;
}

impl StatBase for libc::stat {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        assert_eq!(mode & !mask, 0);
        let new_mode = mode | (self.st_mode & !mask);
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

    fn get_dev(&self) -> dev_t {
        self.st_dev
    }

    fn get_ino(&self) -> ino_t {
        self.st_ino
    }
}

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
impl StatBase for libc::stat64 {
    fn set_mode(&mut self, mode: mode_t, mask: mode_t) {
        assert_eq!(mode & !mask, 0);
        let new_mode = mode | (self.st_mode & !mask);
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

    fn get_dev(&self) -> dev_t {
        self.st_dev
    }

    fn get_ino(&self) -> ino_t {
        self.st_ino
    }
}
