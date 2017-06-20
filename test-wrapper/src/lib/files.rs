use std::os::raw::*;

use shared::*;

use libc;

wrap! {
    // TODO figure out why tracing here causes an EBADF error in Rust's Unix socket code
    !notrace unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        FD_ID_CACHE.lock().unwrap().remove(&fd);
        return Ok(ORIG_CLOSE(fd))
    }

    unsafe fn unlink:ORIG_UNLINK(path: *const c_char) -> c_int {
        let cpath = CPath::from_path(path, false);
        let id = cpath.get_id()?;
        let message_daemon = request::<bool>(Message::BeginRemove(id));
        let ret = ORIG_UNLINK(path);
        if message_daemon {
            if ret == 0 {
                let _ = message(Message::FinishRemove(id, true));
            } else {
                let _ = message(Message::FinishRemove(id, false));
            }
        }
        Ok(ret)
    }

    unsafe fn unlinkat:ORIG_UNLINKAT(dfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        let cpath = CPath::from_path_at(dfd, path, libc::AT_SYMLINK_NOFOLLOW);
        let id = cpath.get_id()?;
        let message_daemon = request::<bool>(Message::BeginRemove(id));
        let ret = ORIG_UNLINKAT(dfd, path, flags);
        if message_daemon {
            if ret == 0 {
                let _ = message(Message::FinishRemove(id, true));
            } else {
                let _ = message(Message::FinishRemove(id, false));
            }
        }
        Ok(ret)
    }

    unsafe fn rmdir:ORIG_RMDIR(path: *const c_char) -> c_int {
        let cpath = CPath::from_path(path, false);
        let id = cpath.get_id()?;
        let message_daemon = request::<bool>(Message::BeginRemove(id));
        let ret = ORIG_RMDIR(path);
        if message_daemon {
            if ret == 0 {
                let _ = message(Message::FinishRemove(id, true));
            } else {
                let _ = message(Message::FinishRemove(id, false));
            }
        }
        Ok(ret)
    }
}
