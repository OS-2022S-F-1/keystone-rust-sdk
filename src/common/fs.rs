use core::mem::zeroed;
use alloc::vec;
use alloc::vec::Vec;
use super::stat::Stat;
use super::syscall::{sys_openat, sys_fstat, sys_read, sys_close};

pub fn read(path: &str) -> Vec<u8> {
    let fd = sys_openat(
        /* CWD */ -100isize as usize,
        path.as_ptr(),
        /* O_RDONLY */ 0, 0
    ) as usize;
    let mut stat = unsafe { zeroed::<Stat>() };//sys_fstat(fd);
    sys_fstat(fd, &mut stat);
    let mut ret = vec![0u8; stat.size as usize];
    sys_read(fd, ret.as_mut_ptr(), stat.size as usize);
    sys_close(fd);
    ret
}
