use std::os::raw::*;

use shared::*;

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
        let ret = ORIG_UNLINK(path);
        if ret == 0 {
            let path = CPath::from_path(path, false);
            if let Ok(id) = path.get_id() {
                send(Message::Remove(id));
            } else {
                warn!("Failed to get unlink path: {:?} errno {}", path, errno());
            }
        }
        Ok(ret)
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let ret = ORIG_UNLINKAT(dfd, path, flags);
        if ret == 0 {
            let path = CPath::from_path_at(dfd, path, flags);
            if let Ok(id) = path.get_id() {
                send(Message::Remove(id));
            } else {
                warn!("Failed to get unlink path: {:?} errno {}", path, errno());
            }
        }
        Ok(ret)
    }
}
