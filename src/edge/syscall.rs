use libc;
use super::common::{UnsafePointer, MAX_EDGECALL, CallStatus, EdgeCall};
use super::call::{EdgeCallHandler};
use super::syscall_nums::{
    SYS_OPENAT, SYS_UNLINKAT, SYS_WRITE, SYS_READ, SYS_FSYNC,
    SYS_CLOSE, SYS_LSEEK, SYS_FTRUNCATE, SYS_FSTATAT,
};

pub const EDGECALL_SYSCALL: usize = MAX_EDGECALL + 1;

pub struct EdgeSyscall {
    pub syscall_num: usize,
    pub data: *mut u8,
}

pub struct SargsSysOpenat {
    pub dirfd: i32,
    pub flags: i32,
    pub mode: i32,
    pub path: *const i8,
}

pub struct SargsSysUnlinkat {
    pub dirfd: i32,
    pub flags: i32,
    pub mode: i32,
    pub path: *const i8,
}

pub struct SargsSysWrite {
    pub fd: i32,
    pub len: usize,
    pub buf: *const libc::c_void,
}

pub struct SargsSysRead {
    pub fd: i32,
    pub len: usize,
    pub buf: *mut libc::c_void,
}

pub struct SargsSysFsync {
    pub fd: i32,
}

pub struct SargsSysClose {
    pub fd: i32,
}

pub struct SargsSysLseek {
    pub fd: i32,
    pub offset: i64,
    pub whence: i32,
}

pub struct SargsSysFtruncate {
    pub fd: i32,
    pub offset: i64,
}

pub struct SargesSysFstatat {
    pub dirfd: i32,
    pub flags: i32,
    pub stats: libc::stat,
    pub pathname: *const i8,
}

impl EdgeCallHandler {
    pub fn incoming_syscall(&self, edge_call: &mut EdgeCall) {
        let mut syscall_info: UnsafePointer = 0;
        let mut size: usize = 0;

        if self.args_ptr(&edge_call, &mut syscall_info, &mut size) != 0 {
            edge_call.return_data.call_status = CallStatus::SyscallFailed;
            return;
        }

        edge_call.return_data.call_status = CallStatus::Ok;

        let mut ret: i32;

        let syscall_info = unsafe{ &*(syscall_info as *const EdgeSyscall) };
        match syscall_info.syscall_num {
            SYS_OPENAT => {
                unsafe {
                    let openat_args = &*(syscall_info.data as *const SargsSysOpenat);
                    ret = libc::openat(openat_args.dirfd, openat_args.path, openat_args.flags, openat_args.mode);
                };
            },
            SYS_UNLINKAT => {
                unsafe {
                    let unlinkat_args = &*(syscall_info.data as *const SargsSysUnlinkat);
                    ret = libc::unlinkat(unlinkat_args.dirfd, unlinkat_args.path, unlinkat_args.flags);
                };
            },
            SYS_WRITE => {
                unsafe {
                    let write_args = &*(syscall_info.data as *const SargsSysWrite);
                    ret = libc::write(write_args.fd, write_args.buf, write_args.len) as i32;
                };
            },
            SYS_READ => {
                unsafe {
                    let read_args = &*(syscall_info.data as *const SargsSysRead);
                    ret = libc::read(read_args.fd, read_args.buf, read_args.len) as i32;
                };
            },
            SYS_FSYNC => {
                unsafe {
                    let fsync_args = &*(syscall_info.data as *const SargsSysFsync);
                    ret = libc::fsync(fsync_args.fd);
                };
            },
            SYS_CLOSE => {
                unsafe {
                    let close_args = &*(syscall_info.data as *const SargsSysClose);
                    ret = libc::close(close_args.fd);
                };
            },
            SYS_LSEEK => {
                unsafe {
                    let lseek_args = &*(syscall_info.data as *const SargsSysLseek);
                    ret = libc::lseek(lseek_args.fd, lseek_args.offset, lseek_args.whence) as i32;
                };
            },
            SYS_FTRUNCATE => {
                unsafe {
                    let ftruncate_args = &*(syscall_info.data as *const SargsSysFtruncate);
                    ret = libc::ftruncate(ftruncate_args.fd, ftruncate_args.offset);
                };
            },
            SYS_FSTATAT => {
                unsafe {
                    let fstatat_args = &mut *(syscall_info.data as *mut SargesSysFstatat);
                    ret = libc::fstatat(fstatat_args.dirfd, fstatat_args.pathname, &mut fstatat_args.stats, fstatat_args.flags);
                };
            },
            _ => return edge_call.return_data.call_status = CallStatus::SyscallFailed,
        };

        let mut ret_data_ptr = self.data_ptr();
        unsafe { *(ret_data_ptr as *mut i64) = ret.into() };
        if self.setup_ret(edge_call, &mut ret_data_ptr, size) != 0 {
            edge_call.return_data.call_status = CallStatus::SyscallFailed;
        }
    }
}
