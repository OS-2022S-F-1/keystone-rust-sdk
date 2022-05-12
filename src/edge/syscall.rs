use crate::common::{syscall, stat};
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
    pub dirfd: usize,
    pub flags: u32,
    pub mode: u32,
    pub path: *const u8,
}

pub struct SargsSysUnlinkat {
    pub dirfd: usize,
    pub flags: usize,
    pub mode: i32,
    pub path: *const u8,
}

pub struct SargsSysWrite {
    pub fd: usize,
    pub len: usize,
    pub buf: *const u8,
}

pub struct SargsSysRead {
    pub fd: usize,
    pub len: usize,
    pub buf: *mut u8,
}

pub struct SargsSysFsync {
    pub fd: usize,
}

pub struct SargsSysClose {
    pub fd: usize,
}

pub struct SargsSysLseek {
    pub fd: usize,
    pub offset: isize,
    pub whence: u8,
}

pub struct SargsSysFtruncate {
    pub fd: usize,
    pub offset: usize,
}

pub struct SargesSysFstatat {
    pub dirfd: usize,
    pub flags: usize,
    pub stats: *mut stat::Stat,
    pub pathname: *const u8,
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

        let ret: isize;

        let syscall_info = unsafe{ &*(syscall_info as *const EdgeSyscall) };
        match syscall_info.syscall_num {
            SYS_OPENAT => {
                unsafe {
                    let openat_args = &*(syscall_info.data as *const SargsSysOpenat);
                    ret = syscall::sys_openat(openat_args.dirfd, openat_args.path, openat_args.flags, openat_args.mode);
                };
            },
            SYS_UNLINKAT => {
                unsafe {
                    let unlinkat_args = &*(syscall_info.data as *const SargsSysUnlinkat);
                    ret = syscall::sys_unlinkat(unlinkat_args.dirfd, unlinkat_args.path, unlinkat_args.flags);
                };
            },
            SYS_WRITE => {
                unsafe {
                    let write_args = &*(syscall_info.data as *const SargsSysWrite);
                    ret = syscall::sys_write(write_args.fd, write_args.buf, write_args.len);
                };
            },
            SYS_READ => {
                unsafe {
                    let read_args = &*(syscall_info.data as *const SargsSysRead);
                    ret = syscall::sys_read(read_args.fd, read_args.buf, read_args.len);
                };
            },
            SYS_FSYNC => {
                unsafe {
                    let fsync_args = &*(syscall_info.data as *const SargsSysFsync);
                    ret = syscall::sys_fsync(fsync_args.fd);
                };
            },
            SYS_CLOSE => {
                unsafe {
                    let close_args = &*(syscall_info.data as *const SargsSysClose);
                    ret = syscall::sys_close(close_args.fd);
                };
            },
            SYS_LSEEK => {
                unsafe {
                    let lseek_args = &*(syscall_info.data as *const SargsSysLseek);
                    ret = syscall::sys_lseek(lseek_args.fd, lseek_args.offset, lseek_args.whence);
                };
            },
            SYS_FTRUNCATE => {
                unsafe {
                    let ftruncate_args = &*(syscall_info.data as *const SargsSysFtruncate);
                    ret = syscall::sys_ftruncate(ftruncate_args.fd, ftruncate_args.offset);
                };
            },
            SYS_FSTATAT => {
                unsafe {
                    let fstatat_args = &mut *(syscall_info.data as *mut SargesSysFstatat);
                    ret = syscall::sys_fstatat(fstatat_args.dirfd, fstatat_args.pathname, fstatat_args.stats, fstatat_args.flags);
                };
            },
            _ => return edge_call.return_data.call_status = CallStatus::SyscallFailed,
        };

        let mut ret_data_ptr = self.data_ptr();
        unsafe { *(ret_data_ptr as *mut isize) = ret };
        if self.setup_ret(edge_call, &mut ret_data_ptr, size) != 0 {
            edge_call.return_data.call_status = CallStatus::SyscallFailed;
        }
    }
}
