use std::os::raw::*;

use shared::*;

wrap! {
    // TODO figure out why tracing here causes an EBADF error in Rust's Unix socket code
    !notrace unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        let ret = ORIG_CLOSE(fd);
        if ret == 0 {
            FD_INOS.lock().unwrap().remove(&fd);
        }
        Ok(ret)
    }

    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        let ret = ORIG_UNLINK(path);
        if ret == 0 {
            if let Ok(ino) = CPath::from_path(path, false).get_ino() {
                send(Message::Remove(ino));
            }
        }
        Ok(ret)
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let ret = ORIG_UNLINKAT(dfd, path, flags);
        if ret == 0 {
            if let Ok(ino) = CPath::from_path_at(dfd, path, flags).get_ino() {
                send(Message::Remove(ino));
            }
        }
        Ok(ret)
    }
}
