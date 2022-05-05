pub const RT_NOEXEC: usize = 0;
pub const USER_NOEXEC: usize = 1;
pub const RT_FULL: usize = 2;
pub const USER_FULL: usize = 3;
pub const UTM_FULL: usize = 4;

pub const PAGE_BITS: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;

#[inline]
pub fn round_up(n: usize, b: usize) -> usize {
    (((n - 1) >> b) + 1) << b
}

#[inline]
pub fn round_down(n: usize, b: usize) -> usize {
    n & !((2 << (b - 1)) - 1)
}

#[inline]
pub fn page_up(n: usize) -> usize {
    round_up(n, PAGE_BITS)
}

#[inline]
pub fn page_down(n: usize) -> usize {
    round_down(n, PAGE_BITS)
}

#[inline]
pub fn is_aligned(x: usize, align: usize) -> bool {
    x & (align - 1) != 0
}

pub const KEYSTONE_DEV_PATH: &str = "/dev/keystone_enclave";
pub const KEYSTONE_ENCLAVE_DONE: usize = 0;
pub const KEYSTONE_ENCLAVE_INTERRUPTED: usize = 100002;
pub const KEYSTONE_ENCLAVE_EDGE_CALL_HOST: usize = 100011;
