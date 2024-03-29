use alloc::vec;
use alloc::vec::Vec;
use crate::common::syscall::{ioctl, mmap, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FIXED};
use crate::println;
use super::common::{KEYSTONE_ENCLAVE_EDGE_CALL_HOST, KEYSTONE_ENCLAVE_INTERRUPTED, KEYSTONE_ENCLAVE_DONE};
use super::error::Error;
use super::params::Params;
use super::keystone_user::{
    RuntimeParams, KeystoneIoctlCreateEnclave, KeystoneIoctlRunEnclave,
    KEYSTONE_IOC_CREATE_ENCLAVE, KEYSTONE_IOC_DESTROY_ENCLAVE, KEYSTONE_IOC_RUN_ENCLAVE,
    KEYSTONE_IOC_RESUME_ENCLAVE, KEYSTONE_IOC_FINALIZE_ENCLAVE, KEYSTONE_IOC_UTM_INIT,
};

pub trait KeystoneDevice: Drop {
    fn new() -> Self where Self: Sized;
    fn get_phys_addr(&self) -> usize;
    fn init_device(&mut self, params: &Params) -> bool;
    fn create(&mut self, min_pages: u64, runtime_vaddr: usize, runtime_size: usize, user_vaddr: usize, user_size: usize) -> Error;
    fn init_utm(&mut self, size: usize) -> usize;
    fn finalize(&mut self, runtime_phys_addr: usize, eapp_phys_addr: usize, free_phys_addr: usize, params: RuntimeParams) -> Error;
    fn destroy(&mut self) -> Error;
    fn run(&mut self, ret: &mut usize) -> Error;
    fn resume(&mut self, ret: &mut usize) -> Error;
    fn map(&mut self, vaddr: usize, size: usize, prot: usize, offset: usize) -> isize;
}

pub struct PhysicalKeystoneDevice {
    eid: isize,
    phys_addr: usize,
    fd: isize,
}

impl Drop for PhysicalKeystoneDevice {
    fn drop(&mut self) {}
}

impl PhysicalKeystoneDevice {
    fn __run(&mut self, resume: bool, ret: &mut usize) -> Error {
        let mut encl = KeystoneIoctlRunEnclave::new();
        encl.eid = self.eid as usize;

        let error: Error;
        let request: usize;
        if resume {
            error = Error::IoctlErrorResume;
            request = KEYSTONE_IOC_RESUME_ENCLAVE;
        } else {
            error = Error::IoctlErrorRun;
            request = KEYSTONE_IOC_RUN_ENCLAVE;
        }

        if ioctl(
            self.fd as usize,
            request,
            &mut encl as *mut KeystoneIoctlRunEnclave as *mut u8
        ) != 0 {
            return error;
        }

        match encl.error {
            KEYSTONE_ENCLAVE_EDGE_CALL_HOST => Error::EdgeCallHost,
            KEYSTONE_ENCLAVE_INTERRUPTED => Error::EnclaveInterrupted,
            KEYSTONE_ENCLAVE_DONE => {
                *ret = encl.value;
                Error::Success
            },
            _ => {
                println!("Unknown SBI error ({}) returned by {}_enclave", encl.error, if resume { "resume" } else { "run" });
                error
            },
        }
    }
}

impl KeystoneDevice for PhysicalKeystoneDevice {
    fn new() -> Self {
        Self {
            eid: -1,
            phys_addr: 0,
            fd: 666,
        }
    }

    fn get_phys_addr(&self) -> usize {
        self.phys_addr
    }

    fn init_device(&mut self, _: &Params) -> bool {
        // fd is set to 666 in OS kernel
        true
    }

    fn create(&mut self, min_pages: u64, runtime_vaddr: usize, runtime_size: usize, user_vaddr: usize, user_size: usize) -> Error {
        let mut encl = KeystoneIoctlCreateEnclave::new();
        encl.min_pages = min_pages as usize;
        encl.runtime_vaddr = runtime_vaddr;
        encl.runtime_size = runtime_size;
        encl.user_vaddr = user_vaddr;
        encl.user_size = user_size;

        let res = ioctl(
            self.fd as usize,
            KEYSTONE_IOC_CREATE_ENCLAVE,
            &mut encl as *mut KeystoneIoctlCreateEnclave as *mut u8
        );
        if res != 0 {
            println!("ioctl error {}", res);
            self.eid = -1;
            Error::IoctlErrorCreate
        } else {
            self.eid = encl.eid as isize;
            Error::Success
        }
    }

    fn init_utm(&mut self, size: usize) -> usize {
        let mut encl = KeystoneIoctlCreateEnclave::new();
        encl.eid = self.eid as usize;
        encl.params.untrusted_size = size;

        let res = ioctl(
            self.fd as usize,
            KEYSTONE_IOC_UTM_INIT,
            &mut encl as *mut KeystoneIoctlCreateEnclave as *mut u8
        );
        if res != 0 {
            0
        } else {
            encl.utm_free_ptr
        }
    }

    fn finalize(&mut self, runtime_phys_addr: usize, eapp_phys_addr: usize, free_phys_addr: usize, params: RuntimeParams) -> Error {
        let mut encl = KeystoneIoctlCreateEnclave::new();
        encl.eid = self.eid as usize;
        encl.params = params;

        if ioctl(
            self.fd as usize,
            KEYSTONE_IOC_FINALIZE_ENCLAVE,
            &mut encl as *mut KeystoneIoctlCreateEnclave as *mut u8
        ) != 0 {
            println!("ioctl error");
            Error::IoctlErrorFinalize
        } else {
            Error::Success
        }
    }

    fn destroy(&mut self) -> Error {
        let mut encl = KeystoneIoctlCreateEnclave::new();
        encl.eid = self.eid as usize;

        if self.eid < 0 {
            return Error::Success;
        }

        if ioctl(
            self.fd as usize,
            KEYSTONE_IOC_DESTROY_ENCLAVE,
            &mut encl as *mut KeystoneIoctlCreateEnclave as *mut u8
        ) != 0 {
            println!("ioctl error");
            Error::IoctlErrorDestroy
        } else {
            Error::Success
        }
    }

    fn run(&mut self, ret: &mut usize) -> Error {
        self.__run(false, ret)
    }

    fn resume(&mut self, ret: &mut usize) -> Error {
        self.__run(true, ret)
    }

    fn map(&mut self, vaddr: usize, size: usize, prot: usize, offset: usize) -> isize {
        let flags = MAP_SHARED | if vaddr != 0 { MAP_FIXED } else { 0 };
        let ret = mmap(vaddr, (size & (1 << 48) - 1) | ((self.eid as usize) << 48), PROT_READ | PROT_WRITE | prot, flags, 666, offset);
        assert_ne!(ret, -1);
        ret
    }
}

pub struct MockKeystoneDevice {
    eid: i32,
    phys_addr: usize,
    fd: i32,
    shared_buffer: Option<Vec<u8>>,
}

impl Drop for MockKeystoneDevice {
    fn drop(&mut self) {
        if let Some(buffer) = self.shared_buffer.take() {
            drop(buffer);
        }
    }
}

impl KeystoneDevice for MockKeystoneDevice {
    fn new() -> Self {
        Self {
            eid: 0,
            phys_addr: 0,
            fd: 0,
            shared_buffer: None,
        }
    }

    fn get_phys_addr(&self) -> usize {
        self.phys_addr
    }

    fn init_device(&mut self, _: &Params) -> bool {
        true
    }

    fn create(&mut self, _: u64, _: usize, _: usize, _: usize, _: usize) -> Error {
        self.eid = -1;
        Error::Success
    }

    fn init_utm(&mut self, _: usize) -> usize {
        0
    }

    fn finalize(&mut self, _: usize, _: usize, _: usize, _: RuntimeParams) -> Error {
        Error::Success
    }

    fn destroy(&mut self) -> Error {
        Error::Success
    }

    fn run(&mut self, _: &mut usize) -> Error {
        Error::Success
    }

    fn resume(&mut self, _: &mut usize) -> Error {
        Error::Success
    }

    fn map(&mut self, _: usize, size: usize, _: usize, _: usize) -> isize {
        let mut buffer = vec![0u8; size];
        let ret = buffer.as_mut_ptr() as isize;
        self.shared_buffer = Some(buffer);
        ret
    }
}
