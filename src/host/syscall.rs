/// zCore has removed crate `linux-user`, so there is no syscall function to use
/// these functions are syscalls used in keystone

use super::ioctl::{_IOR, SYS_IOCTL};

pub const SYSCALL_MMAP: usize = 222;
pub const PROT_NONE: usize = 0x00;
pub const PROT_READ: usize = 0x01;
pub const PROT_WRITE: usize = 0x02;
pub const PROT_EXEC: usize = 0x04;
pub const MAP_SHARED: usize = 0x0001;
pub const MAP_PRIVATE: usize = 0x0002;

fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        core::arch::asm!(
        "ecall",
        inlateout("x10") args[0] => ret,
        in("x11") args[1],
        in("x12") args[2],
        in("x17") id
        );
    }
    ret
}

fn syscall6(id: usize, args: [usize; 6]) -> isize {
    let mut ret: isize;
    unsafe {
        core::arch::asm!("ecall",
        inlateout("x10") args[0] => ret,
        in("x11") args[1],
        in("x12") args[2],
        in("x13") args[3],
        in("x14") args[4],
        in("x15") args[5],
        in("x17") id
        );
    }
    ret
}

pub fn ioctl(fd: usize, request: usize, encl: *mut u8) -> isize {
    syscall(SYS_IOCTL, [fd, request, encl as usize])
}

pub fn mmap(start: usize, len: usize, prot: usize, flags: usize, fd: i32, offset: usize) -> isize {
    syscall6(SYSCALL_MMAP, [start, len, prot, flags, fd as usize, offset])
}
