use std::mem;
use std::os::raw::*;

use libc;

use shared::*;
use internal_stat::{INTERNAL_FSTAT, NativeStat};

fn base_dup(oldfd: c_int, newfd: c_int) -> Result<()> {
    let id = {
        let mut fd_id_cache = FD_ID_CACHE.lock().unwrap();
        if let Some(&id) = fd_id_cache.get(&oldfd) {
            fd_id_cache.insert(newfd, id);
            id
        } else {
            let statbuf = unsafe {
                let mut statbuf: NativeStat = mem::uninitialized();
                if INTERNAL_FSTAT(newfd, &mut statbuf as *mut _) == -1 {
                    return Err(0);
                }
                statbuf
            };
            let id = FileId::from_stat(&statbuf);
            fd_id_cache.insert(oldfd, id);
            id
        }
    };
    inc_file_ref_count(id)
}

wrap! {
    !notrace unsafe fn close:ORIG_CLOSE(fd: c_int) -> c_int {
        {
            let daemon_stream_fds = DAEMON_STREAM_FDS.read().unwrap();
            if fd == daemon_stream_fds.0 || fd == daemon_stream_fds.1 {
                return Ok(ORIG_CLOSE(fd));
            }
        }
        let id = CPath::from_fd(fd).get_id_notrace();
        FD_ID_CACHE.lock().unwrap().remove(&fd);
        let ret = ORIG_CLOSE(fd);
        if ret != -1 {
            if let Ok(id) = id {
                let mut file_ref_counts = FILE_REF_COUNTS.lock().unwrap();
                if let Some(count) = file_ref_counts.get_mut(&id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        let _ = message(Message::DropReference(id));
                    }
                }
            }
        }
        Ok(ret)
    }

    !notrace unsafe fn dup:ORIG_DUP(oldfd: c_int) -> c_int {
        let ret = ORIG_DUP(oldfd);
        if ret >= 0 {
            let _ = base_dup(oldfd, ret);
        }
        Ok(ret)
    }

    !notrace unsafe fn dup2:ORIG_DUP2(oldfd: c_int, newfd: c_int) -> c_int {
        let ret = ORIG_DUP2(oldfd, newfd);
        if ret != -1 {
            let _ = base_dup(oldfd, newfd);
        }
        Ok(ret)
    }

    !notrace unsafe fn dup3:ORIG_DUP3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
        let ret = ORIG_DUP3(oldfd, newfd, flags);
        if ret != -1 {
            let _ = base_dup(oldfd, newfd);
        }
        Ok(ret)
    }

    !notrace unsafe fn fcntl:ORIG_FCNTL(fd: c_int, cmd: c_int, arg: c_int) -> c_int {
        let ret = ORIG_FCNTL(fd, cmd, arg);
        if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
            if ret >= 0 {
                let _ = base_dup(fd, ret);
            }
        }
        Ok(ret)
    }
}
