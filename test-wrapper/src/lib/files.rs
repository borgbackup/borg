use std::mem;
use std::os::raw::*;

use shared::*;
use internal_stat::{INTERNAL_FSTAT, NativeStat};

use libc::{self, O_RDONLY, O_NONBLOCK};

fn base_unlink<F: FnOnce() -> c_int, G: FnOnce() -> c_int>(fd_fn: F, orig_fn: G) -> Result<c_int> {
    REENTRANT.with(|c| c.set(false));
    let fd = fd_fn();
    REENTRANT.with(|c| c.set(true));
    if fd == -1 {
        debug!("Failed to open file before unlink");
        return Ok(orig_fn());
    }
    let ret = orig_fn();
    let statbuf = unsafe {
        let mut statbuf: NativeStat = mem::uninitialized();
        if INTERNAL_FSTAT(fd, &mut statbuf as *mut _) == -1 {
            return Err(0);
        }
        statbuf
    };
    if statbuf.st_nlink == 0 {
        let _ = message(Message::ReadyDeletion(FileId::from_stat(&statbuf)));
    }
    REENTRANT.with(|c| c.set(false));
    unsafe { libc::close(fd) };
    REENTRANT.with(|c| c.set(true));
    Ok(ret)
}

wrap! {
    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        base_unlink(|| libc::open(path as *const _, O_RDONLY | O_NONBLOCK), || ORIG_UNLINK(path))
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        base_unlink(|| libc::openat(dfd, path as *const _, O_RDONLY | O_NONBLOCK), || ORIG_UNLINKAT(dfd, path, flags))
    }

    unsafe fn rmdir:ORIG_RMDIR(path: *const c_char) -> c_int {
        base_unlink(|| libc::open(path as *const _, O_RDONLY | O_NONBLOCK), || ORIG_RMDIR(path))
    }
}
