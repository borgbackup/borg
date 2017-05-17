use std::os::raw::*;

use shared::*;

use libc;
use errno::errno;

wrap! {
    // TODO figure out why tracing here causes an EBADF error in Rust's Unix socket code
    !notrace unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        let ret = ORIG_CLOSE(fd);
        if ret == 0 {
            FD_ID_CACHE.lock().unwrap().remove(&fd);
        }
        Ok(ret)
    }

    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        let cpath = CPath::from_path(path, false);
        let id = cpath.get_id(); // needs to be done before ORIG_UNLINK
        let ret = ORIG_UNLINK(path);
        if ret == 0 {
            if let Ok(id) = id {
                send(Message::Remove(id));
            } else {
                warn!("Failed to get unlink path: {:?} errno {}", cpath, errno());
            }
        }
        Ok(ret)
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let cpath = CPath::from_path_at(dfd, path, flags);
        let id = cpath.get_id();
        let ret = ORIG_UNLINKAT(dfd, path, flags & !libc::AT_REMOVEDIR);
        if ret == 0 {
            if let Ok(id) = id {
                send(Message::Remove(id));
            } else {
                warn!("Failed to get unlink path: {:?} errno {}", cpath, errno());
            }
        }
        Ok(ret)
    }
}
