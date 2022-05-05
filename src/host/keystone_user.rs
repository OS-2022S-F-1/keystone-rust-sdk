use core::mem::sizeof;
use super::ioctl::_IOR;

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
    pub user_vaddr: usize,
    pub pt_ptr: usize,
    pub utm_free_ptr: usize,
    pub epm_paddr: usize,
    pub utm_paddr: usize,
    pub runtime_paddr: usize,
    pub user_paddr: usize,
    pub free_paddr: usize,
    pub epm_size: usize,
    pub utm_size: usize,
    pub params: RuntimeParams,
}

impl KeystoneIoctlCreateEnclave {
    pub fn new() -> Self {
        Self {
            eid: 0,
            min_pages: 0,
            runtime_vaddr: 0,
            user_vaddr: 0,
            pt_ptr: 0,
            utm_free_ptr: 0,
            epm_paddr: 0,
            utm_paddr: 0,
            runtime_paddr: 0,
            user_paddr: 0,
            free_paddr: 0,
            epm_size: 0,
            utm_size: 0,
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

pub const KEYSTONE_IOC_CREATE_ENCLAVE: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x00, sizeof::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_DESTROY_ENCLAVE: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x01, sizeof::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_RUN_ENCLAVE: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x04, sizeof::<KeystoneIoctlRunEnclave>());
pub const KEYSTONE_IOC_RESUME_ENCLAVE: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x05, sizeof::<KeystoneIoctlRunEnclave>());
pub const KEYSTONE_IOC_FINALIZE_ENCLAVE: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x06, sizeof::<KeystoneIoctlCreateEnclave>());
pub const KEYSTONE_IOC_UTM_INIT: usize = _IOR(KEYSTONE_IOC_MAGIC, 0x07, sizeof::<KeystoneIoctlCreateEnclave>());
