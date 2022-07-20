use core::mem::size_of;
use super::ioctl::{_ior, _iow};

pub const KEYSTONE_IOC_MAGIC: usize = 0xa4;

pub const RT_NOEXEC: usize = 0;
pub const USER_NOEXEC: usize = 1;
pub const RT_FULL: usize = 2;
pub const USER_FULL: usize = 3;
pub const UTM_FULL: usize = 4;

pub struct RuntimeParams {
    pub runtime_entry: usize,
    pub user_entry: usize,
    pub untrusted_ptr: usize,
    pub untrusted_size: usize,
}

pub struct KeystoneIoctlCreateEnclave {
    pub eid: usize,
    pub min_pages: usize,
    pub runtime_vaddr: usize,
    pub runtime_size: usize,
    pub user_vaddr: usize,
    pub user_size: usize,
    pub utm_free_ptr: usize,
    pub params: RuntimeParams,
}

impl KeystoneIoctlCreateEnclave {
    pub fn new() -> Self {
        Self {
            eid: 0,
            min_pages: 0,
            runtime_vaddr: 0,
            runtime_size: 0,
            user_vaddr: 0,
            user_size: 0,
            utm_free_ptr: 0,
            params: RuntimeParams {
                runtime_entry: 0,
                user_entry: 0,
                untrusted_ptr: 0,
                untrusted_size: 0,
            },
        }
    }
}

pub struct KeystoneIoctlRunEnclave {
    pub eid: usize,
    pub error: usize,
    pub value: usize,
}

impl KeystoneIoctlRunEnclave {
    pub fn new() -> Self {
        Self {
            eid: 0,
            error: 0,
            value: 0,
        }
    }
}

pub const KEYSTONE_IOC_CREATE_ENCLAVE: usize = _ior(KEYSTONE_IOC_MAGIC, 0x00, size_of::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_DESTROY_ENCLAVE: usize = _iow(KEYSTONE_IOC_MAGIC, 0x01, size_of::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_RUN_ENCLAVE: usize = _ior(KEYSTONE_IOC_MAGIC, 0x04, size_of::<KeystoneIoctlRunEnclave>());
pub const KEYSTONE_IOC_RESUME_ENCLAVE: usize = _ior(KEYSTONE_IOC_MAGIC, 0x05, size_of::<KeystoneIoctlRunEnclave>());
pub const KEYSTONE_IOC_FINALIZE_ENCLAVE: usize = _ior(KEYSTONE_IOC_MAGIC, 0x06, size_of::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_UTM_INIT: usize = _ior(KEYSTONE_IOC_MAGIC, 0x07, size_of::<KeystoneIoctlCreateEnclave>());
