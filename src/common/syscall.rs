use super::stat::Stat;

pub const SYS_IOCTL: usize = 29;
pub const SYSCALL_UNLINKAT: usize = 35;
pub const SYSCALL_FTRUNCATE: usize = 46;
pub const SYSCALL_OPENAT: usize = 56;
pub const SYSCALL_CLOSE: usize = 57;
pub const SYSCALL_LSEEK: usize = 62;
pub const SYSCALL_READ: usize = 63;
pub const SYSCALL_WRITE: usize = 64;
pub const SYSCALL_FSTATAT: usize = 79;
pub const SYSCALL_FSTAT: usize = 80;
pub const SYSCALL_FSYNC: usize = 82;
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

pub fn sys_unlinkat(dirfd: usize, path: *const u8, flags: usize) -> isize {
    syscall(SYSCALL_UNLINKAT, [dirfd, path as usize, flags])
}

pub fn sys_ftruncate(fd: usize, len: usize) -> isize {
    syscall(SYSCALL_FTRUNCATE, [fd, len, 0])
}

pub fn sys_openat(dirfd: usize, path: *const u8, flags: u32, mode: u32) -> isize {
    syscall6(
        SYSCALL_OPENAT,
        [
            dirfd,
            path as usize,
            flags as usize,
            mode as usize,
            0,
            0,
        ],
    )
}

pub fn sys_close(fd: usize) -> isize {
    syscall(SYSCALL_CLOSE, [fd, 0, 0])
}

pub fn sys_lseek(fd: usize, offset: isize, whence: u8) -> isize {
    syscall(SYSCALL_LSEEK, [fd, offset as usize, whence as usize])
}

pub fn sys_read(fd: usize, buffer: *mut u8, len: usize) -> isize {
    syscall(
        SYSCALL_READ,
        [fd, buffer as usize, len],
    )
}

pub fn sys_write(fd: usize, buffer: *const u8, len: usize) -> isize {
    syscall(SYSCALL_WRITE, [fd, buffer as usize, len])
}

pub fn sys_fstatat(dirfd: usize, path: *const u8, stat: *mut Stat, flags: usize) -> isize {
    syscall6(SYSCALL_FSTATAT, [dirfd, path as usize, stat as usize, flags, 0, 0])
}

pub fn sys_fstat(fd: usize, stat: *mut Stat) -> isize {
    syscall(SYSCALL_FSTAT, [fd, stat as usize, 0])
}

pub fn sys_fsync(fd: usize) -> isize {
    syscall(SYSCALL_FSYNC, [fd, 0, 0])
}

pub fn mmap(start: usize, len: usize, prot: usize, flags: usize, fd: i32, offset: usize) -> isize {
    syscall6(SYSCALL_MMAP, [start, len, prot, flags, fd as usize, offset])
}
