use core::mem;
use super::sealing::SealingKey;

const SYSCALL_OCALL: usize = 1001;
const SYSCALL_SHAREDCOPY: usize = 1002;
const SYSCALL_ATTEST_ENCLAVE: usize = 1003;
const SYSCALL_GET_SEALING_KEY: usize = 1004;
const SYSCALL_EXIT: usize = 1011;

#[inline]
fn syscall(which: usize, arg0: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> usize {
    let mut ret;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("x10") arg0 => ret,
            in("x11") arg1,
            in("x12") arg2,
            in("x13") arg3,
            in("x14") arg4,
            in("x17") which,
        )
    }
    ret
}

pub fn ocall(call_id: usize, data: *const u8, data_len: usize, return_buffer: *mut u8, return_len: usize) -> usize {
    syscall(SYSCALL_OCALL, call_id, data as usize, data_len, return_buffer as usize, return_len)
}

pub fn copy_from_shared(dst: *mut u8, offset: usize, data_len: usize) -> usize {
    syscall(SYSCALL_SHAREDCOPY, dst as usize, offset, data_len, 0, 0)
}

pub fn attest_enclave(report: *mut u8, data: *const u8, size: usize) -> usize {
    syscall(SYSCALL_ATTEST_ENCLAVE, report as usize, data as usize, size, 0, 0)
}

pub fn get_sealing_key(sealing_key_struct: *mut SealingKey, key_ident: *const u8, key_ident_size: usize) -> usize {
    syscall(SYSCALL_GET_SEALING_KEY, sealing_key_struct as usize, mem::size_of::<SealingKey>(), key_ident as usize, key_ident_size, 0)
}
